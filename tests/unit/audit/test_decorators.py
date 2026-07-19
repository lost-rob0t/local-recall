from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

from local_recall.audit import (
    AuditedCapturePolicy,
    AuditedKeyProvider,
    AuditedModelRoutingPolicy,
    AuditedStorageBackend,
    AuditEvent,
    AuditReasonCode,
    AuditRecorder,
)
from local_recall.domain.capture import (
    CaptureDecision,
    CaptureIntent,
    CapturePolicyInput,
)
from local_recall.domain.crypto import (
    EncryptedRecordEnvelope,
    KeyHandle,
    KeyRequest,
    SecretKeyMaterial,
    StoredRecordRef,
)
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextMetadata
from local_recall.domain.privacy import PrivacyClass, ProviderLocation
from local_recall.domain.providers import (
    ModelCapability,
    ProviderCapabilities,
    RoutingDecision,
    RoutingRequest,
)
from local_recall.ports.keys import (
    KeyDestructionRequest,
    KeyDestructionResult,
    KeyHealthReport,
    KeyHealthStatus,
    KeyRotationRequest,
    KeyUnwrapRequest,
    KeyWrapRequest,
)
from local_recall.ports.storage import DeleteRequest, DeleteResult


class MemorySink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class AllowPolicy:
    revision = "fixture-policy"

    async def evaluate(self, request: CapturePolicyInput) -> CaptureDecision:
        del request
        return CaptureDecision.allow(
            policy_revision=self.revision,
            allowed_metadata_fields=frozenset(),
        )


class LocalRoutingPolicy:
    policy_id = "fixture-routing"

    async def route(
        self,
        request: RoutingRequest,
        providers: tuple[ProviderCapabilities, ...],
    ) -> RoutingDecision:
        del request
        return RoutingDecision(
            provider_id=providers[0].provider_id,
            location=ProviderLocation.LOCAL,
            capability=ModelCapability.GENERATION,
            egress_authorization_id=None,
            reason_code="fixture-local",
        )


class MemoryStorage:
    backend_id = "memory"

    async def put(self, envelope: EncryptedRecordEnvelope) -> StoredRecordRef:
        return StoredRecordRef(envelope.record_id, "fixture", envelope.schema_version)

    async def get(self, record_id: UUID) -> EncryptedRecordEnvelope | None:
        del record_id
        return None

    async def delete(self, request: DeleteRequest) -> DeleteResult:
        return DeleteResult(request.record_id, True, False)


class MemoryKeyProvider:
    provider_id = "fixture-key-provider"

    async def health(self, request: KeyRequest) -> KeyHealthReport:
        del request
        return KeyHealthReport(self.provider_id, KeyHealthStatus.READY)

    async def active_key(self, request: KeyRequest) -> KeyHandle:
        del request
        return KeyHandle("fixture-key", self.provider_id, 1)

    async def wrap_data_key(self, request: KeyWrapRequest) -> bytes:
        del request
        return b"wrapped"

    async def unwrap_data_key(self, request: KeyUnwrapRequest) -> SecretKeyMaterial:
        del request
        return SecretKeyMaterial.from_bytes(b"k" * 32)

    async def rotate(self, request: KeyRotationRequest) -> KeyHandle:
        return KeyHandle(
            request.current.key_id,
            request.current.provider_id,
            request.current.version + 1,
        )

    async def destroy(self, request: KeyDestructionRequest) -> KeyDestructionResult:
        return KeyDestructionResult(request.key, True)


def test_capture_policy_decision_is_audited_without_metadata_content() -> None:
    sink = MemorySink()
    policy = AuditedCapturePolicy(AllowPolicy(), AuditRecorder(sink))
    request = CapturePolicyInput(
        intent=CaptureIntent(
            job_id=uuid4(),
            generation=CaptureGeneration(2),
            requested_at=datetime.now(UTC),
            deadline_monotonic_ns=1,
            configuration_revision="private-revision",
        ),
        metadata=ContextMetadata(datetime.now(UTC), ()),
    )

    decision = asyncio.run(policy.evaluate(request))

    assert decision.authorization is not None
    assert sink.events[-1].reason is AuditReasonCode.POLICY_ALLOW
    assert sink.events[-1].record_id is None


def test_local_provider_selection_is_audited() -> None:
    sink = MemorySink()
    policy = AuditedModelRoutingPolicy(LocalRoutingPolicy(), AuditRecorder(sink))
    providers = (
        ProviderCapabilities(
            provider_id="ollama",
            location=ProviderLocation.LOCAL,
            capabilities=frozenset({ModelCapability.GENERATION}),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
            max_input_bytes=1024,
            supports_vision=False,
        ),
    )

    decision = asyncio.run(
        policy.route(
            RoutingRequest(
                ModelCapability.GENERATION,
                PrivacyClass.REDACTED_CONTENT,
                False,
            ),
            providers,
        )
    )

    assert decision.provider_id == "ollama"
    assert sink.events[-1].reason is AuditReasonCode.PROVIDER_LOCAL


def test_storage_deletion_and_key_operations_are_audited() -> None:
    sink = MemorySink()
    recorder = AuditRecorder(sink)
    record_id = uuid4()
    storage = AuditedStorageBackend(MemoryStorage(), recorder)
    provider = AuditedKeyProvider(MemoryKeyProvider(), recorder)
    key = KeyHandle("fixture-key", "fixture-key-provider", 1)

    deletion = asyncio.run(storage.delete(DeleteRequest(record_id, "user-request")))
    rotated = asyncio.run(provider.rotate(KeyRotationRequest(key, "scheduled")))
    destroyed = asyncio.run(provider.destroy(KeyDestructionRequest(rotated, "retired")))

    assert deletion.deleted
    assert destroyed.destroyed
    assert [event.reason for event in sink.events] == [
        AuditReasonCode.DELETION_COMPLETED,
        AuditReasonCode.KEY_ROTATED,
        AuditReasonCode.KEY_DESTROYED,
    ]
