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
        if any(character in self.model_id for character in ("\x00", "\r", "\n")):
            raise ValueError("remote model id contains invalid characters")
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
        self._require_text_only(approved)

        if spec.kind is RemoteProviderKind.OPENROUTER:
            return self._build_openrouter(spec, approved, credential)
        if spec.kind is RemoteProviderKind.OPENAI_COMPATIBLE:
            return self._build_openai_compatible(spec, approved, credential)
        if spec.kind is RemoteProviderKind.ANTHROPIC:
            return self._build_anthropic(spec, approved, credential)
        if spec.kind is RemoteProviderKind.GOOGLE:
            return self._build_google(spec, approved, credential)
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
    def _require_text_only(approved: ApprovedEgressPayload) -> None:
        if approved.metadata or approved.image:
            raise RemoteRequestError("unsupported-egress-modality")
        if not approved.text:
            raise RemoteRequestError("remote-text-required")

    @staticmethod
    def _endpoint_parts(spec: RemoteProviderSpec) -> tuple[str, str]:
        parsed = urlsplit(spec.endpoint)
        if not parsed.hostname:
            raise RemoteRequestError("invalid-remote-endpoint")
        origin = f"https://{parsed.hostname}"
        if parsed.port is not None:
            origin = f"{origin}:{parsed.port}"
        return origin, parsed.path

    @staticmethod
    def _json_body(payload: object) -> bytes:
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def _build_openrouter(
        cls,
        spec: RemoteProviderSpec,
        approved: ApprovedEgressPayload,
        credential: ResolvedCredential,
    ) -> RemoteHttpRequest:
        origin, path = cls._endpoint_parts(spec)
        return RemoteHttpRequest(
            method="POST",
            origin=origin,
            path=path,
            headers=MappingProxyType(
                {
                    "authorization": f"Bearer {credential.value}",
                    "content-type": "application/json",
                }
            ),
            body=cls._json_body(
                {
                    "messages": [{"role": "user", "content": approved.text}],
                    "model": spec.model_id,
                    "provider": {"allow_fallbacks": False},
                }
            ),
        )

    @classmethod
    def _build_openai_compatible(
        cls,
        spec: RemoteProviderSpec,
        approved: ApprovedEgressPayload,
        credential: ResolvedCredential,
    ) -> RemoteHttpRequest:
        origin, path = cls._endpoint_parts(spec)
        return RemoteHttpRequest(
            method="POST",
            origin=origin,
            path=path,
            headers=MappingProxyType(
                {
                    "authorization": f"Bearer {credential.value}",
                    "content-type": "application/json",
                }
            ),
            body=cls._json_body(
                {
                    "messages": [{"role": "user", "content": approved.text}],
                    "model": spec.model_id,
                }
            ),
        )

    @classmethod
    def _build_anthropic(
        cls,
        spec: RemoteProviderSpec,
        approved: ApprovedEgressPayload,
        credential: ResolvedCredential,
    ) -> RemoteHttpRequest:
        origin, path = cls._endpoint_parts(spec)
        return RemoteHttpRequest(
            method="POST",
            origin=origin,
            path=path,
            headers=MappingProxyType(
                {
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                    "x-api-key": credential.value,
                }
            ),
            body=cls._json_body(
                {
                    "max_tokens": 1024,
                    "messages": [{"role": "user", "content": approved.text}],
                    "model": spec.model_id,
                }
            ),
        )

    @classmethod
    def _build_google(
        cls,
        spec: RemoteProviderSpec,
        approved: ApprovedEgressPayload,
        credential: ResolvedCredential,
    ) -> RemoteHttpRequest:
        origin, path = cls._endpoint_parts(spec)
        expected_suffix = f"/models/{spec.model_id}:generateContent"
        if not path.endswith(expected_suffix):
            raise RemoteRequestError("provider-endpoint-model-mismatch")
        return RemoteHttpRequest(
            method="POST",
            origin=origin,
            path=path,
            headers=MappingProxyType(
                {
                    "content-type": "application/json",
                    "x-goog-api-key": credential.value,
                }
            ),
            body=cls._json_body(
                {"contents": [{"parts": [{"text": approved.text}]}]}
            ),
        )
