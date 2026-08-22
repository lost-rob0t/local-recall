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


def _credential() -> object:
    return ResolvedCredential(
        value="sk-remote-synthetic-value",  # pragma: allowlist secret
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


def test_openai_compatible_request_uses_bearer_auth_and_one_model() -> None:
    builder = RemoteRequestBuilder()
    spec = RemoteProviderSpec(
        provider_id="openai-main",
        kind=RemoteProviderKind.OPENAI_COMPATIBLE,
        endpoint="https://api.openai.com/v1/chat/completions",
        model_id="gpt-5.2",
    )

    request = builder.build(spec, _approved("openai-main"), _credential())
    body = json.loads(request.body.decode("utf-8"))

    assert request.path == "/v1/chat/completions"
    assert request.headers["authorization"].startswith("Bearer ")
    assert body == {
        "messages": [{"content": "safe redacted text", "role": "user"}],
        "model": "gpt-5.2",
    }


def test_anthropic_request_uses_api_key_and_fixed_protocol_version() -> None:
    builder = RemoteRequestBuilder()
    spec = RemoteProviderSpec(
        provider_id="anthropic-main",
        kind=RemoteProviderKind.ANTHROPIC,
        endpoint="https://api.anthropic.com/v1/messages",
        model_id="claude-sonnet-4-6",
    )

    request = builder.build(spec, _approved("anthropic-main"), _credential())
    body = json.loads(request.body.decode("utf-8"))

    assert request.path == "/v1/messages"
    assert request.headers["x-api-key"]
    assert request.headers["anthropic-version"] == "2023-06-01"
    assert "authorization" not in request.headers
    assert "fallbacks" not in body
    assert body == {
        "max_tokens": 1024,
        "messages": [{"content": "safe redacted text", "role": "user"}],
        "model": "claude-sonnet-4-6",
    }


def test_google_request_uses_header_key_and_model_bound_endpoint() -> None:
    builder = RemoteRequestBuilder()
    spec = RemoteProviderSpec(
        provider_id="google-main",
        kind=RemoteProviderKind.GOOGLE,
        endpoint=(
            "https://generativelanguage.googleapis.com/v1beta/models/"
            "gemini-3.7-flash:generateContent"
        ),
        model_id="gemini-3.7-flash",
    )

    request = builder.build(spec, _approved("google-main"), _credential())
    body = json.loads(request.body.decode("utf-8"))

    assert request.path == "/v1beta/models/gemini-3.7-flash:generateContent"
    assert request.headers["x-goog-api-key"]
    assert "authorization" not in request.headers
    assert body == {"contents": [{"parts": [{"text": "safe redacted text"}]}]}


def test_google_endpoint_model_must_match_selected_model() -> None:
    builder = RemoteRequestBuilder()
    spec = RemoteProviderSpec(
        provider_id="google-main",
        kind=RemoteProviderKind.GOOGLE,
        endpoint=(
            "https://generativelanguage.googleapis.com/v1beta/models/"
            "different-model:generateContent"
        ),
        model_id="gemini-3.7-flash",
    )

    with pytest.raises(RemoteRequestError, match="provider-endpoint-model-mismatch"):
        builder.build(spec, _approved("google-main"), _credential())


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
