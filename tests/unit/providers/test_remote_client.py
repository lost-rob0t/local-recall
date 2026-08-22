from __future__ import annotations

import asyncio
from collections.abc import Mapping

import pytest

from local_recall.config import CredentialReference
from local_recall.providers.remote import (
    RemoteHttpRequest,
    RemoteProviderKind,
    RemoteProviderSpec,
    RemoteRequestError,
    ResolvedCredential,
)
from local_recall.providers.remote_client import RemoteProviderClient
from local_recall.routing import ApprovedEgressPayload, EgressDataClass


class FakeCredentialProvider:
    def __init__(self, value: str = "fixture-key") -> None:
        self.value = value
        self.references: list[CredentialReference] = []

    def resolve(self, reference: CredentialReference) -> ResolvedCredential:
        self.references.append(reference)
        return ResolvedCredential(value=self.value)


class FakeExecutor:
    def __init__(self) -> None:
        self.requests: list[RemoteHttpRequest] = []

    async def execute(self, request: RemoteHttpRequest) -> Mapping[str, object]:
        self.requests.append(request)
        return {"ok": True}


def approved_payload(provider_id: str = "remote-one") -> ApprovedEgressPayload:
    return ApprovedEgressPayload(
        authorization_id="auth-1",
        provider_id=provider_id,
        data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
        payload_bytes=5,
        payload_sha256="0" * 64,
        text="hello",
    )


def provider_spec() -> RemoteProviderSpec:
    return RemoteProviderSpec(
        provider_id="remote-one",
        kind=RemoteProviderKind.OPENAI_COMPATIBLE,
        endpoint="https://api.example.test/v1/chat/completions",
        model_id="model-1",
    )


def credential_reference() -> CredentialReference:
    return CredentialReference(
        provider_id="os-keyring",
        reference="remote-one",
    )


def test_remote_client_resolves_credential_only_when_executing() -> None:
    credentials = FakeCredentialProvider()
    executor = FakeExecutor()
    client = RemoteProviderClient(
        spec=provider_spec(),
        credential_reference=credential_reference(),
        credential_provider=credentials,
        executor=executor,
    )

    assert credentials.references == []

    response = asyncio.run(client.execute(approved_payload()))

    assert response == {"ok": True}
    assert credentials.references == [credential_reference()]
    assert len(executor.requests) == 1
    assert executor.requests[0].origin == "https://api.example.test"
    assert "fixture-key" not in repr(client)
    assert "fixture-key" not in repr(executor.requests[0])


def test_remote_client_rejects_provider_mismatch_before_resolving_secret() -> None:
    credentials = FakeCredentialProvider()
    executor = FakeExecutor()
    client = RemoteProviderClient(
        spec=provider_spec(),
        credential_reference=credential_reference(),
        credential_provider=credentials,
        executor=executor,
    )

    with pytest.raises(RemoteRequestError, match="provider-authorization-mismatch"):
        asyncio.run(client.execute(approved_payload(provider_id="other-provider")))

    assert credentials.references == []
    assert executor.requests == []


def test_remote_client_does_not_reuse_resolved_credentials_between_calls() -> None:
    credentials = FakeCredentialProvider()
    executor = FakeExecutor()
    client = RemoteProviderClient(
        spec=provider_spec(),
        credential_reference=credential_reference(),
        credential_provider=credentials,
        executor=executor,
    )

    asyncio.run(client.execute(approved_payload()))
    credentials.value = "rotated-fixture-key"
    asyncio.run(client.execute(approved_payload()))

    assert len(credentials.references) == 2
    assert len(executor.requests) == 2
    assert executor.requests[0].headers["authorization"] == "Bearer fixture-key"
    assert executor.requests[1].headers["authorization"] == "Bearer rotated-fixture-key"
