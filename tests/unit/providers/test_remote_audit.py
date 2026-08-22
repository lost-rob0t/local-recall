from __future__ import annotations

import asyncio
from collections.abc import Mapping
from importlib import import_module
from uuid import uuid4

from local_recall.audit import AuditAction, AuditEvent, AuditOutcome, AuditReasonCode
from local_recall.audit.recorder import AuditRecorder
from local_recall.config import CredentialReference
from local_recall.providers.remote import (
    RemoteHttpRequest,
    RemoteProviderKind,
    RemoteProviderSpec,
    ResolvedCredential,
)
from local_recall.routing import ApprovedEgressPayload, EgressDataClass

_adapters_module = import_module("local_recall.audit.adapters")
_remote_client_module = import_module("local_recall.providers.remote_client")
RemoteProviderAuditAdapter = vars(_adapters_module)["RemoteProviderAuditAdapter"]
RemoteProviderClient = vars(_remote_client_module)["RemoteProviderClient"]


class MemorySink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)


class FakeCredentialProvider:
    def resolve(self, reference: CredentialReference) -> ResolvedCredential:
        return ResolvedCredential("synthetic-credential")


class FakeExecutor:
    async def execute(self, request: RemoteHttpRequest) -> Mapping[str, object]:
        return {"ok": True}


class FakeBuilder:
    def build(
        self,
        spec: RemoteProviderSpec,
        approved: ApprovedEgressPayload,
        credential: ResolvedCredential,
    ) -> RemoteHttpRequest:
        return RemoteHttpRequest(
            method="POST",
            origin="https://api.example.test",
            path="/v1/messages",
            headers={"authorization": f"Bearer {credential.value}"},
            body=b'{"private":"payload"}',
        )


def _approved() -> ApprovedEgressPayload:
    return ApprovedEgressPayload(
        authorization_id="auth-1",
        provider_id="remote-main",
        data_classes=frozenset({EgressDataClass.REDACTED_TEXT}),
        payload_bytes=21,
        payload_sha256="a" * 64,
        text="private redacted text",
    )


def test_remote_audit_adapter_emits_control_only_provider_event() -> None:
    sink = MemorySink()
    recorder = AuditRecorder(sink)
    adapter = RemoteProviderAuditAdapter(recorder)
    correlation_id = uuid4()

    event = adapter.authorized(
        provider_id="remote-main",
        correlation_id=correlation_id,
    )

    assert event.action is AuditAction.PROVIDER_SELECTION
    assert event.outcome is AuditOutcome.ACCEPTED
    assert event.reason is AuditReasonCode.PROVIDER_REMOTE_AUTHORIZED
    assert event.provider_id == "remote-main"
    assert event.correlation_id == correlation_id
    assert dict(event.attributes) == {"remote": True, "authorized": True}
    rendered = repr(event)
    assert "private" not in rendered
    assert "credential" not in rendered


def test_remote_client_records_authorized_egress_without_payload_or_credential() -> None:
    sink = MemorySink()
    audit = RemoteProviderAuditAdapter(AuditRecorder(sink))
    correlation_id = uuid4()
    client = RemoteProviderClient(
        spec=RemoteProviderSpec(
            provider_id="remote-main",
            kind=RemoteProviderKind.OPENAI_COMPATIBLE,
            endpoint="https://api.example.test/v1/chat/completions",
            model_id="configured-model",
        ),
        credential_reference=CredentialReference(
            provider_id="os-keyring",
            reference="remote-main",
        ),
        credential_provider=FakeCredentialProvider(),
        executor=FakeExecutor(),
        builder=FakeBuilder(),
        audit=audit,
    )

    async def scenario() -> None:
        response = await client.execute(_approved(), correlation_id=correlation_id)
        assert response == {"ok": True}

    asyncio.run(scenario())

    assert len(sink.events) == 1
    event = sink.events[0]
    assert event.correlation_id == correlation_id
    serialized = repr(event)
    assert "private redacted text" not in serialized
    assert "synthetic-credential" not in serialized
    assert "private" not in serialized


def test_remote_client_rejection_is_audited_without_attempting_transport() -> None:
    sink = MemorySink()
    audit = RemoteProviderAuditAdapter(AuditRecorder(sink))
    client = RemoteProviderClient(
        spec=RemoteProviderSpec(
            provider_id="other-provider",
            kind=RemoteProviderKind.OPENAI_COMPATIBLE,
            endpoint="https://api.example.test/v1/chat/completions",
            model_id="configured-model",
        ),
        credential_reference=CredentialReference(
            provider_id="os-keyring",
            reference="other-provider",
        ),
        credential_provider=FakeCredentialProvider(),
        executor=FakeExecutor(),
        builder=FakeBuilder(),
        audit=audit,
    )
    correlation_id = uuid4()

    async def scenario() -> None:
        try:
            await client.execute(_approved(), correlation_id=correlation_id)
        except Exception:
            return
        raise AssertionError("provider mismatch must fail")

    asyncio.run(scenario())

    assert len(sink.events) == 1
    event = sink.events[0]
    assert event.outcome is AuditOutcome.REJECTED
    assert event.reason is AuditReasonCode.PROVIDER_REJECTED
    assert event.correlation_id == correlation_id
    assert dict(event.attributes) == {"remote": True, "authorized": False}
