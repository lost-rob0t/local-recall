from __future__ import annotations

import json
from importlib import import_module

import pytest

routing = import_module("local_recall.routing")
remote = import_module("local_recall.providers.remote")

ApprovedEgressPayload = routing.ApprovedEgressPayload
EgressDataClass = routing.EgressDataClass
RemoteProviderKind = remote.RemoteProviderKind
RemoteProviderSpec = remote.RemoteProviderSpec
RemoteRequestBuilder = remote.RemoteRequestBuilder
RemoteRequestError = remote.RemoteRequestError
ResolvedCredential = remote.ResolvedCredential


def _approved(provider_id: str = "openrouter-main") -> object:
    return ApprovedEgressPayload(
        authorization_id="auth-remote-1",
        provider_id=provider_id,
        data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
        payload_bytes=18,
        payload_sha256="0" * 64,
        text="safe redacted text",
    )


def test_openrouter_request_disables_upstream_provider_fallback() -> None:
    builder = RemoteRequestBuilder()
    spec = RemoteProviderSpec(
        provider_id="openrouter-main",
        kind=RemoteProviderKind.OPENROUTER,
        endpoint="https://openrouter.ai/api/v1/chat/completions",
        model_id="anthropic/claude-sonnet-4.6",
    )
    credential = ResolvedCredential(
        value="sk-or-v1-synthetic-value",  # pragma: allowlist secret
    )

    request = builder.build(spec, _approved(), credential)
    body = json.loads(request.body.decode("utf-8"))

    assert request.method == "POST"
    assert request.origin == "https://openrouter.ai"
    assert request.path == "/api/v1/chat/completions"
    assert body["model"] == "anthropic/claude-sonnet-4.6"
    assert body["provider"] == {"allow_fallbacks": False}
    assert "models" not in body
    assert request.headers["authorization"].startswith("Bearer ")
    assert credential.value not in repr(request)
    assert credential.value not in repr(credential)


def test_approved_payload_provider_must_match_remote_spec() -> None:
    builder = RemoteRequestBuilder()
    spec = RemoteProviderSpec(
        provider_id="openrouter-main",
        kind=RemoteProviderKind.OPENROUTER,
        endpoint="https://openrouter.ai/api/v1/chat/completions",
        model_id="anthropic/claude-sonnet-4.6",
    )

    with pytest.raises(RemoteRequestError, match="provider-authorization-mismatch"):
        builder.build(
            spec,
            _approved(provider_id="different-provider"),
            ResolvedCredential(
                value="sk-or-v1-synthetic-value",  # pragma: allowlist secret
            ),
        )


def test_remote_endpoint_must_be_https_origin_without_userinfo() -> None:
    with pytest.raises(ValueError, match="remote endpoint"):
        RemoteProviderSpec(
            provider_id="openrouter-main",
            kind=RemoteProviderKind.OPENROUTER,
            endpoint="http://openrouter.ai/api/v1/chat/completions",
            model_id="anthropic/claude-sonnet-4.6",
        )

    with pytest.raises(ValueError, match="remote endpoint"):
        RemoteProviderSpec(
            provider_id="openrouter-main",
            kind=RemoteProviderKind.OPENROUTER,
            endpoint="https://user@example.com/api/v1/chat/completions",
            model_id="anthropic/claude-sonnet-4.6",
        )


def test_openrouter_adapter_does_not_accept_image_without_image_approval() -> None:
    builder = RemoteRequestBuilder()
    spec = RemoteProviderSpec(
        provider_id="openrouter-main",
        kind=RemoteProviderKind.OPENROUTER,
        endpoint="https://openrouter.ai/api/v1/chat/completions",
        model_id="anthropic/claude-sonnet-4.6",
    )
    approved = ApprovedEgressPayload(
        authorization_id="auth-remote-1",
        provider_id="openrouter-main",
        data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
        payload_bytes=18,
        payload_sha256="0" * 64,
        text="safe redacted text",
        image=b"synthetic-redacted-image",
    )

    with pytest.raises(RemoteRequestError, match="approved-payload-class-mismatch"):
        builder.build(
            spec,
            approved,
            ResolvedCredential(
                value="sk-or-v1-synthetic-value",  # pragma: allowlist secret
            ),
        )
