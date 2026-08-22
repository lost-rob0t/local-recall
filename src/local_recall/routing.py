from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

from local_recall.domain import (
    EgressAuthorization,
    EgressDataClass,
    ModelCapability,
    PrivacyClass,
    ProviderCapabilities,
    ProviderLocation,
    RoutingDecision,
    RoutingRequest,
)
from local_recall.redaction.detector import DeterministicSecretDetector


class RoutingMode(StrEnum):
    PRIVACY_STRICT = "privacy-strict"
    LOCAL_ONLY = "local-only"
    LOCAL_FIRST = "local-first"
    REMOTE_EXPLICIT = "remote-explicit"


class NoRouteError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        if not reason_code:
            raise ValueError("routing reason code must not be empty")
        self.reason_code = reason_code
        super().__init__(reason_code)


class EgressDeniedError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        if not reason_code:
            raise ValueError("egress reason code must not be empty")
        self.reason_code = reason_code
        super().__init__(reason_code)

    def __repr__(self) -> str:
        return f"EgressDeniedError(reason_code={self.reason_code!r})"


@dataclass(frozen=True, slots=True)
class EgressPayload:
    text: str = field(default="", repr=False)
    metadata: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    image: bytes = field(default=b"", repr=False)

    def __post_init__(self) -> None:
        if not self.text and not self.metadata and not self.image:
            raise ValueError("egress payload must not be empty")
        names = [name for name, _ in self.metadata]
        if any(not name for name in names):
            raise ValueError("metadata names must not be empty")
        if len(names) != len(set(names)):
            raise ValueError("metadata names must be unique")

    @property
    def data_classes(self) -> frozenset[EgressDataClass]:
        classes: set[EgressDataClass] = set()
        if self.text:
            classes.add(EgressDataClass.REDACTED_TEXT)
        if self.metadata:
            classes.add(EgressDataClass.APPROVED_METADATA)
        if self.image:
            classes.add(EgressDataClass.REDACTED_IMAGE)
        return frozenset(classes)


@dataclass(frozen=True, slots=True)
class ApprovedEgressPayload:
    authorization_id: str
    provider_id: str
    data_classes: frozenset[EgressDataClass]
    payload_bytes: int
    payload_sha256: str
    text: str = field(default="", repr=False)
    metadata: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    image: bytes = field(default=b"", repr=False)


class EgressGate:
    def __init__(self, detector: DeterministicSecretDetector | None = None) -> None:
        self._detector = detector or DeterministicSecretDetector()

    def approve(
        self,
        payload: EgressPayload,
        authorization: EgressAuthorization,
    ) -> ApprovedEgressPayload:
        data_classes = payload.data_classes
        if not data_classes.issubset(authorization.data_classes):
            raise EgressDeniedError("egress-data-class-denied")

        self._scan_text(payload.text)
        for name, value in payload.metadata:
            if self._detector.sensitive_metadata_name(name) is not None:
                raise EgressDeniedError("sensitive-metadata")
            self._scan_text(value)

        payload_bytes, payload_sha256 = self._measure(payload)
        if payload_bytes > authorization.max_payload_bytes:
            raise EgressDeniedError("payload-too-large")

        return ApprovedEgressPayload(
            authorization_id=authorization.authorization_id,
            provider_id=authorization.provider_id,
            data_classes=data_classes,
            payload_bytes=payload_bytes,
            payload_sha256=payload_sha256,
            text=payload.text,
            metadata=payload.metadata,
            image=payload.image,
        )

    def _scan_text(self, text: str) -> None:
        if text and self._detector.scan(text).matches:
            raise EgressDeniedError("secret-detected")

    @staticmethod
    def _measure(payload: EgressPayload) -> tuple[int, str]:
        digest = hashlib.sha256()
        size = 0

        def add(kind: bytes, content: bytes) -> None:
            nonlocal size
            size += len(content)
            digest.update(kind)
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)

        if payload.text:
            add(b"text", payload.text.encode("utf-8"))
        for name, value in sorted(payload.metadata):
            add(b"metadata-name", name.encode("utf-8"))
            add(b"metadata-value", value.encode("utf-8"))
        if payload.image:
            add(b"image", payload.image)
        return size, digest.hexdigest()


_REMOTE_PRIVACY_CLASSES = frozenset(
    {
        PrivacyClass.PUBLIC,
        PrivacyClass.OPERATIONAL_METADATA,
        PrivacyClass.REDACTED_CONTENT,
    }
)


class RoutingPolicy:
    def __init__(self, mode: RoutingMode) -> None:
        self._mode = mode

    @property
    def policy_id(self) -> str:
        return f"routing:{self._mode.value}"

    async def route(
        self,
        request: RoutingRequest,
        providers: tuple[ProviderCapabilities, ...],
    ) -> RoutingDecision:
        if self._mode is RoutingMode.REMOTE_EXPLICIT:
            return self._route_remote(request, providers)
        return self._route_local(request, providers)

    def _route_local(
        self,
        request: RoutingRequest,
        providers: tuple[ProviderCapabilities, ...],
    ) -> RoutingDecision:
        for provider in providers:
            if not self._provider_matches(
                provider,
                request,
                location=ProviderLocation.LOCAL,
            ):
                continue
            reason = {
                RoutingMode.PRIVACY_STRICT: "privacy-strict-local",
                RoutingMode.LOCAL_ONLY: "local-only",
                RoutingMode.LOCAL_FIRST: "local-first",
            }[self._mode]
            return RoutingDecision(
                provider_id=provider.provider_id,
                location=ProviderLocation.LOCAL,
                capability=request.capability,
                egress_authorization_id=None,
                reason_code=reason,
            )

        if self._mode is RoutingMode.PRIVACY_STRICT:
            raise NoRouteError("privacy-strict-local-only")
        raise NoRouteError("local-unavailable")

    def _route_remote(
        self,
        request: RoutingRequest,
        providers: tuple[ProviderCapabilities, ...],
    ) -> RoutingDecision:
        authorization = request.authorization
        if not request.allow_remote or authorization is None:
            raise NoRouteError("egress-authorization-required")
        if (
            request.egress_authorization_id is not None
            and request.egress_authorization_id != authorization.authorization_id
        ):
            raise NoRouteError("egress-authorization-mismatch")
        if request.privacy_class not in _REMOTE_PRIVACY_CLASSES:
            raise NoRouteError("privacy-class-denied")
        if not request.data_classes:
            raise NoRouteError("egress-data-class-required")
        if not request.data_classes.issubset(authorization.data_classes):
            raise NoRouteError("egress-data-class-denied")

        for provider in providers:
            if provider.provider_id != authorization.provider_id:
                continue
            if not self._provider_matches(
                provider,
                request,
                location=ProviderLocation.REMOTE,
            ):
                continue
            return RoutingDecision(
                provider_id=provider.provider_id,
                location=ProviderLocation.REMOTE,
                capability=request.capability,
                egress_authorization_id=authorization.authorization_id,
                reason_code="remote-explicit-authorized",
            )

        raise NoRouteError("remote-unavailable")

    @staticmethod
    def _provider_matches(
        provider: ProviderCapabilities,
        request: RoutingRequest,
        *,
        location: ProviderLocation,
    ) -> bool:
        return (
            provider.location is location
            and provider.available
            and request.capability in provider.capabilities
            and provider.accepts(request.privacy_class)
        )
