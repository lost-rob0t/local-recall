from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from local_recall.domain import (
    ModelCapability,
    PrivacyClass,
    ProviderCapabilities,
    ProviderLocation,
    RoutingDecision,
)


class RoutingMode(StrEnum):
    PRIVACY_STRICT = "privacy-strict"
    LOCAL_ONLY = "local-only"
    LOCAL_FIRST = "local-first"
    REMOTE_EXPLICIT = "remote-explicit"


class EgressDataClass(StrEnum):
    REDACTED_TEXT = "redacted-text"
    APPROVED_METADATA = "approved-metadata"
    REDACTED_IMAGE = "redacted-image"


class NoRouteError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        if not reason_code:
            raise ValueError("routing reason code must not be empty")
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class EgressAuthorization:
    authorization_id: str
    provider_id: str
    data_classes: frozenset[EgressDataClass]
    max_payload_bytes: int

    def __post_init__(self) -> None:
        if not self.authorization_id:
            raise ValueError("egress authorization id must not be empty")
        if not self.provider_id:
            raise ValueError("egress provider id must not be empty")
        if not self.data_classes:
            raise ValueError("egress authorization requires data classes")
        if self.max_payload_bytes <= 0:
            raise ValueError("egress payload limit must be positive")


@dataclass(frozen=True, slots=True)
class RoutingRequest:
    capability: ModelCapability
    privacy_class: PrivacyClass
    data_classes: frozenset[EgressDataClass]
    authorization: EgressAuthorization | None = None

    def __post_init__(self) -> None:
        if not self.data_classes:
            raise ValueError("routing request requires data classes")


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
        if authorization is None:
            raise NoRouteError("egress-authorization-required")
        if request.privacy_class not in _REMOTE_PRIVACY_CLASSES:
            raise NoRouteError("privacy-class-denied")
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
