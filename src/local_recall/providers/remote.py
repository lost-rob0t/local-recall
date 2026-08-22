from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from urllib.parse import urlsplit

from local_recall.routing import ApprovedEgressPayload, EgressDataClass


class RemoteProviderKind(StrEnum):
    OPENAI_COMPATIBLE = "openai-compatible"
    OPENROUTER = "openrouter"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"


class RemoteRequestError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        if not reason_code:
            raise ValueError("remote request reason code must not be empty")
        self.reason_code = reason_code
        super().__init__(reason_code)

    def __repr__(self) -> str:
        return f"RemoteRequestError(reason_code={self.reason_code!r})"


@dataclass(frozen=True, slots=True, repr=False)
class ResolvedCredential:
    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("resolved credential must not be empty")
        if any(character in self.value for character in ("\x00", "\r", "\n")):
            raise ValueError("resolved credential contains invalid characters")


@dataclass(frozen=True, slots=True)
class RemoteProviderSpec:
    provider_id: str
    kind: RemoteProviderKind
    endpoint: str = field(repr=False)
    model_id: str

    def __post_init__(self) -> None:
        if not self.provider_id:
            raise ValueError("remote provider id must not be empty")
        if not self.model_id:
            raise ValueError("remote model id must not be empty")
        try:
            parsed = urlsplit(self.endpoint)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("remote endpoint must be a valid HTTPS URL") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or not parsed.path.startswith("/")
            or parsed.path == "/"
            or parsed.query
            or parsed.fragment
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ValueError("remote endpoint must be a valid HTTPS URL")


@dataclass(frozen=True, slots=True)
class RemoteHttpRequest:
    method: str
    origin: str
    path: str
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)


class RemoteRequestBuilder:
    def build(
        self,
        spec: RemoteProviderSpec,
        approved: ApprovedEgressPayload,
        credential: ResolvedCredential,
    ) -> RemoteHttpRequest:
        if approved.provider_id != spec.provider_id:
            raise RemoteRequestError("provider-authorization-mismatch")
        if self._present_data_classes(approved) != approved.data_classes:
            raise RemoteRequestError("approved-payload-class-mismatch")
        if spec.kind is RemoteProviderKind.OPENROUTER:
            return self._build_openrouter(spec, approved, credential)
        raise RemoteRequestError("unsupported-remote-provider")

    @staticmethod
    def _present_data_classes(
        approved: ApprovedEgressPayload,
    ) -> frozenset[EgressDataClass]:
        classes: set[EgressDataClass] = set()
        if approved.text:
            classes.add(EgressDataClass.REDACTED_TEXT)
        if approved.metadata:
            classes.add(EgressDataClass.APPROVED_METADATA)
        if approved.image:
            classes.add(EgressDataClass.REDACTED_IMAGE)
        return frozenset(classes)

    @staticmethod
    def _build_openrouter(
        spec: RemoteProviderSpec,
        approved: ApprovedEgressPayload,
        credential: ResolvedCredential,
    ) -> RemoteHttpRequest:
        if approved.metadata or approved.image:
            raise RemoteRequestError("unsupported-egress-modality")
        if not approved.text:
            raise RemoteRequestError("remote-text-required")

        parsed = urlsplit(spec.endpoint)
        if not parsed.hostname:
            raise RemoteRequestError("invalid-remote-endpoint")
        origin = f"https://{parsed.hostname}"
        if parsed.port is not None:
            origin = f"{origin}:{parsed.port}"

        body = json.dumps(
            {
                "messages": [{"role": "user", "content": approved.text}],
                "model": spec.model_id,
                "provider": {"allow_fallbacks": False},
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        headers = MappingProxyType(
            {
                "authorization": f"Bearer {credential.value}",
                "content-type": "application/json",
            }
        )
        return RemoteHttpRequest(
            method="POST",
            origin=origin,
            path=parsed.path,
            headers=headers,
            body=body,
        )
