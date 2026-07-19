from __future__ import annotations

from uuid import UUID

from local_recall.domain.capture import (
    CaptureDecision,
    CaptureDecisionKind,
    CapturePolicyInput,
)
from local_recall.domain.crypto import (
    EncryptedRecordEnvelope,
    KeyHandle,
    KeyRequest,
    SecretKeyMaterial,
    StoredRecordRef,
)
from local_recall.domain.privacy import ProviderLocation
from local_recall.domain.providers import (
    ProviderCapabilities,
    RoutingDecision,
    RoutingRequest,
)
from local_recall.ports.keys import (
    KeyDestructionRequest,
    KeyDestructionResult,
    KeyHealthReport,
    KeyProvider,
    KeyRotationRequest,
    KeyUnwrapRequest,
    KeyWrapRequest,
)
from local_recall.ports.policy import CapturePolicy
from local_recall.ports.routing import ModelRoutingPolicy
from local_recall.ports.storage import DeleteRequest, DeleteResult, StorageBackend

from .models import AuditReasonCode
from .recorder import AuditRecorder


class AuditedCapturePolicy:
    def __init__(self, inner: CapturePolicy, recorder: AuditRecorder) -> None:
        self._inner = inner
        self._recorder = recorder

    @property
    def revision(self) -> str:
        return self._inner.revision

    async def evaluate(self, request: CapturePolicyInput) -> CaptureDecision:
        try:
            decision = await self._inner.evaluate(request)
        except Exception:
            self._recorder.policy_decision(
                record_id=None,
                generation=request.intent.generation.value,
                allowed=False,
                reason=AuditReasonCode.POLICY_FAILURE,
            )
            raise
        allowed = decision.kind is CaptureDecisionKind.ALLOW
        self._recorder.policy_decision(
            record_id=None,
            generation=request.intent.generation.value,
            allowed=allowed,
            reason=(
                AuditReasonCode.POLICY_ALLOW if allowed else AuditReasonCode.POLICY_DENY
            ),
            correlation_id=decision.decision_id,
        )
        return decision


class AuditedModelRoutingPolicy:
    def __init__(self, inner: ModelRoutingPolicy, recorder: AuditRecorder) -> None:
        self._inner = inner
        self._recorder = recorder

    @property
    def policy_id(self) -> str:
        return self._inner.policy_id

    async def route(
        self,
        request: RoutingRequest,
        providers: tuple[ProviderCapabilities, ...],
    ) -> RoutingDecision:
        try:
            decision = await self._inner.route(request, providers)
        except Exception:
            self._recorder.provider_selection(
                provider_id=None,
                remote=request.allow_remote,
                authorized=False,
                reason=AuditReasonCode.PROVIDER_REJECTED,
            )
            raise
        remote = decision.location is ProviderLocation.REMOTE
        self._recorder.provider_selection(
            provider_id=decision.provider_id,
            remote=remote,
            authorized=not remote or decision.egress_authorization_id is not None,
            reason=(
                AuditReasonCode.PROVIDER_REMOTE_AUTHORIZED
                if remote
                else AuditReasonCode.PROVIDER_LOCAL
            ),
        )
        return decision


class AuditedStorageBackend:
    def __init__(self, inner: StorageBackend, recorder: AuditRecorder) -> None:
        self._inner = inner
        self._recorder = recorder

    @property
    def backend_id(self) -> str:
        return self._inner.backend_id

    async def put(self, envelope: EncryptedRecordEnvelope) -> StoredRecordRef:
        return await self._inner.put(envelope)

    async def get(self, record_id: UUID) -> EncryptedRecordEnvelope | None:
        return await self._inner.get(record_id)

    async def delete(self, request: DeleteRequest) -> DeleteResult:
        try:
            result = await self._inner.delete(request)
        except Exception:
            self._recorder.record_deletion(
                record_id=request.record_id,
                deleted=False,
                failed=True,
                reason=AuditReasonCode.PERSISTENCE_FAILED,
            )
            raise
        self._recorder.record_deletion(
            record_id=result.record_id,
            deleted=result.deleted,
            reason=(
                AuditReasonCode.DELETION_COMPLETED
                if result.deleted
                else AuditReasonCode.INVALID_RECORD
            ),
            cryptographic_material_destroyed=result.cryptographic_material_destroyed,
        )
        return result


class AuditedKeyProvider:
    def __init__(self, inner: KeyProvider, recorder: AuditRecorder) -> None:
        self._inner = inner
        self._recorder = recorder

    @property
    def provider_id(self) -> str:
        return self._inner.provider_id

    async def health(self, request: KeyRequest) -> KeyHealthReport:
        return await self._inner.health(request)

    async def active_key(self, request: KeyRequest) -> KeyHandle:
        return await self._inner.active_key(request)

    async def wrap_data_key(self, request: KeyWrapRequest) -> bytes:
        return await self._inner.wrap_data_key(request)

    async def unwrap_data_key(self, request: KeyUnwrapRequest) -> SecretKeyMaterial:
        return await self._inner.unwrap_data_key(request)

    async def rotate(self, request: KeyRotationRequest) -> KeyHandle:
        try:
            result = await self._inner.rotate(request)
        except Exception:
            self._recorder.key_operation(
                reason=AuditReasonCode.KEY_ROTATED,
                key_id=request.current.key_id,
                key_version=request.current.version,
                succeeded=False,
                provider_id=request.current.provider_id,
            )
            raise
        self._recorder.key_operation(
            reason=AuditReasonCode.KEY_ROTATED,
            key_id=result.key_id,
            key_version=result.version,
            succeeded=True,
            provider_id=result.provider_id,
        )
        return result

    async def destroy(self, request: KeyDestructionRequest) -> KeyDestructionResult:
        try:
            result = await self._inner.destroy(request)
        except Exception:
            self._recorder.key_operation(
                reason=AuditReasonCode.KEY_DESTROYED,
                key_id=request.key.key_id,
                key_version=request.key.version,
                succeeded=False,
                provider_id=request.key.provider_id,
            )
            raise
        self._recorder.key_operation(
            reason=AuditReasonCode.KEY_DESTROYED,
            key_id=result.key.key_id,
            key_version=result.key.version,
            succeeded=result.destroyed,
            provider_id=result.key.provider_id,
        )
        return result
