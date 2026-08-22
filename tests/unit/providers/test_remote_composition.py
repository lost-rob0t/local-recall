from __future__ import annotations

import asyncio
from collections.abc import Mapping
from importlib import import_module

import pytest

from local_recall.config import CredentialReference, RemoteProviderSettings
from local_recall.providers.remote import RemoteHttpRequest, ResolvedCredential
from local_recall.routing import ApprovedEgressPayload, EgressDataClass

composition = import_module("local_recall.providers.remote_composition")
compose_remote_provider_client = composition.compose_remote_provider_client


class FakeCredentialProvider:
    def __init__(self) -> None:
        self.references: list[CredentialReference] = []

    def resolve(self, reference: CredentialReference) -> ResolvedCredential:
        self.references.append(reference)
        return ResolvedCredential(value="fixture-key")


class FakeExecutor:
    def __init__(self) -> None:
        self.requests: list[RemoteHttpRequest] = []

    async def execute(self, request: RemoteHttpRequest) -> Mapping[str, object]:
        self.requests.append(request)
        return {"ok": True}


def configured_provider(*, enabled: bool = True) -> RemoteProviderSettings:
    return RemoteProviderSettings(
        provider_id="openrouter-main",
        enabled=enabled,
        kind="openrouter",
        endpoint="https://openrouter.ai/api/v1/chat/completions",
        model_id="anthropic/claude-sonnet-4.6",
        credential_reference=CredentialReference(
            provider_id="os-keyring",
            reference="openrouter-main",
        ),
    )


def approved_payload() -> ApprovedEgressPayload:
    return ApprovedEgressPayload(
        authorization_id="auth-1",
        provider_id="openrouter-main",
        data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
        payload_bytes=5,
        payload_sha256="0" * 64,
        text="hello",
    )


def test_composition_builds_executable_client_without_resolving_secret() -> None:
    credentials = FakeCredentialProvider()
    executor = FakeExecutor()

    client = compose_remote_provider_client(
        configured_provider(),
        credential_provider=credentials,
        executor=executor,
    )

    assert client.provider_id == "openrouter-main"
    assert credentials.references == []

    response = asyncio.run(client.execute(approved_payload()))

    assert response == {"ok": True}
    assert len(credentials.references) == 1
    assert len(executor.requests) == 1
    request = executor.requests[0]
    assert request.origin == "https://openrouter.ai"
    assert request.path == "/api/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer fixture-key"
    assert b'"allow_fallbacks":false' in request.body


def test_composition_rejects_disabled_provider() -> None:
    credentials = FakeCredentialProvider()

    with pytest.raises(ValueError, match="disabled"):
        compose_remote_provider_client(
            configured_provider(enabled=False),
            credential_provider=credentials,
            executor=FakeExecutor(),
        )

    assert credentials.references == []
