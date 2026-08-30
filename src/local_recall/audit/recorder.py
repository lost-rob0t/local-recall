from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from uuid import UUID, uuid4

from local_recall.domain.lifecycle import CaptureState

from .errors import AuditFailure, AuditFailureCode
from .models import (
    AuditAction,
    AuditCategory,
    AuditEvent,
    AuditOutcome,
    AuditReasonCode,
)
from .ports import AuditSink


class AuditRecorder:
    def __init__(
        self,
        sink: AuditSink,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._sink = sink
        self._clock = clock or (lambda: datetime.now(UTC))

    def lifecycle_transition(
        self,
        *,
        reason: AuditReasonCode,
        generation: int,
        correlation_id: UUID,
        previous_state: CaptureState,
        current_state: CaptureState,
        configuration_revision: str | None,
        faulted: bool,
    ) -> AuditEvent:
        return self._emit(
            category=AuditCategory.LIFECYCLE,
            action=AuditAction.LIFECYCLE_TRANSITION,
            outcome=AuditOutcome.FAILED if faulted else AuditOutcome.SUCCEEDED,
            reason=reason,
            generation=generation,
            correlation_id=correlation_id,
            previous_state=previous_state,
            current_state=current_state,
            configuration_revision=configuration_revision,
        )

    def capture_decision(
        self,
        *,
        record_id: UUID | None,
        generation: int,
        accepted: bool,
        reason: AuditReasonCode,
        correlation_id: UUID | None = None,
        attributes: Mapping[str, int | bool] | None = None,
    ) -> AuditEvent:
        return self._emit(
            category=AuditCategory.CAPTURE,
            action=AuditAction.CAPTURE_DECISION,
            outcome=AuditOutcome.ACCEPTED if accepted else AuditOutcome.SKIPPED,
            reason=reason,
            record_id=record_id,
            generation=generation,
            correlation_id=correlation_id,
            attributes=attributes,
        )

    def policy_decision(
        self,
        *,
        record_id: UUID | None,
        generation: int,
        allowed: bool,
        reason: AuditReasonCode,
        correlation_id: UUID | None = None,
    ) -> AuditEvent:
        return self._emit(
            category=AuditCategory.POLICY,
            action=AuditAction.POLICY_DECISION,
            outcome=AuditOutcome.ACCEPTED if allowed else AuditOutcome.REJECTED,
            reason=reason,
            record_id=record_id,
            generation=generation,
            correlation_id=correlation_id,
        )

    def provider_selection(
        self,
        *,
        provider_id: str | None,
        remote: bool,
        authorized: bool,
        reason: AuditReasonCode,
        correlation_id: UUID | None = None,
    ) -> AuditEvent:
        return self._emit(
            category=AuditCategory.PROVIDER,
            action=AuditAction.PROVIDER_SELECTION,
            outcome=AuditOutcome.ACCEPTED if authorized else AuditOutcome.REJECTED,
            reason=reason,
            provider_id=provider_id,
            correlation_id=correlation_id,
            attributes={"remote": remote, "authorized": authorized},
        )

    def ipc_request(
        self,
        *,
        authorized: bool,
        capability: str | None,
        urgent: bool,
        correlation_id: UUID | None = None,
    ) -> AuditEvent:
        if capability is not None and capability not in {"control", "query", "diagnostic"}:
            raise ValueError("unsupported IPC capability")
        if authorized and capability is None:
            raise ValueError("authorized IPC request requires capability")
        return self._emit(
            category=AuditCategory.IPC,
            action=AuditAction.IPC_REQUEST,
            outcome=AuditOutcome.ACCEPTED if authorized else AuditOutcome.REJECTED,
            reason=(AuditReasonCode.IPC_AUTHORIZED if authorized else AuditReasonCode.IPC_REJECTED),
            correlation_id=correlation_id,
            attributes={
                "authorized": authorized,
                "control": capability == "control",
                "diagnostic": capability == "diagnostic",
                "query": capability == "query",
                "urgent": urgent,
            },
        )

    def record_rejected(
        self,
        *,
        record_id: UUID,
        generation: int,
        reason: AuditReasonCode,
        correlation_id: UUID | None = None,
    ) -> AuditEvent:
        return self._emit(
            category=AuditCategory.RECORD,
            action=AuditAction.RECORD_REJECTED,
            outcome=AuditOutcome.REJECTED,
            reason=reason,
            record_id=record_id,
            generation=generation,
            correlation_id=correlation_id,
        )

    def record_deletion(
        self,
        *,
        record_id: UUID,
        deleted: bool,
        reason: AuditReasonCode,
        cryptographic_material_destroyed: bool = False,
        failed: bool = False,
        correlation_id: UUID | None = None,
    ) -> AuditEvent:
        if failed:
            outcome = AuditOutcome.FAILED
        elif deleted:
            outcome = AuditOutcome.SUCCEEDED
        else:
            outcome = AuditOutcome.SKIPPED
        return self._emit(
            category=AuditCategory.RECORD,
            action=AuditAction.RECORD_DELETED,
            outcome=outcome,
            reason=reason,
            record_id=record_id,
            correlation_id=correlation_id,
            attributes={
                "deleted": deleted,
                "cryptographic_material_destroyed": cryptographic_material_destroyed,
            },
        )

    def record_deleted(
        self,
        *,
        record_id: UUID,
        reason: AuditReasonCode = AuditReasonCode.DELETION_COMPLETED,
        cryptographic_material_destroyed: bool = False,
        correlation_id: UUID | None = None,
    ) -> AuditEvent:
        return self.record_deletion(
            record_id=record_id,
            deleted=True,
            reason=reason,
            cryptographic_material_destroyed=cryptographic_material_destroyed,
            correlation_id=correlation_id,
        )

    def deletion_request(
        self,
        *,
        scope_kind: str,
        count: int,
        succeeded: bool,
        correlation_id: UUID | None = None,
    ) -> AuditEvent:
        flags = _DELETION_SCOPE_FLAGS.get(scope_kind)
        if flags is None:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        attributes: dict[str, int | bool] = {
            "records": flags == "records",
            "cluster": flags == "cluster",
            "application": flags == "application",
            "time_range": flags == "time_range",
            "success": succeeded,
            "count": count,
        }
        return self._emit(
            category=AuditCategory.RECORD,
            action=AuditAction.DELETION_REQUEST,
            outcome=AuditOutcome.SUCCEEDED if succeeded else AuditOutcome.FAILED,
            reason=(
                AuditReasonCode.DELETION_COMPLETED if succeeded else AuditReasonCode.USER_REQUEST
            ),
            correlation_id=correlation_id,
            attributes=attributes,
        )

    def export_decision(
        self,
        *,
        allowed: bool,
        reason: AuditReasonCode,
        correlation_id: UUID | None = None,
        count: int = 0,
    ) -> AuditEvent:
        return self._emit(
            category=AuditCategory.EXPORT,
            action=AuditAction.EXPORT_DECISION,
            outcome=AuditOutcome.ACCEPTED if allowed else AuditOutcome.REJECTED,
            reason=reason,
            correlation_id=correlation_id,
            attributes={"count": count},
        )

    def key_operation(
        self,
        *,
        reason: AuditReasonCode,
        key_id: str,
        key_version: int,
        succeeded: bool,
        provider_id: str,
        correlation_id: UUID | None = None,
    ) -> AuditEvent:
        return self._emit(
            category=AuditCategory.KEY,
            action=AuditAction.KEY_OPERATION,
            outcome=AuditOutcome.SUCCEEDED if succeeded else AuditOutcome.FAILED,
            reason=reason,
            provider_id=provider_id,
            key_version=key_version,
            key_id=key_id,
            correlation_id=correlation_id,
        )

    def system_hardening(
        self,
        *,
        succeeded: bool,
        reason: AuditReasonCode,
        correlation_id: UUID | None = None,
    ) -> AuditEvent:
        return self._emit(
            category=AuditCategory.SYSTEM,
            action=AuditAction.SYSTEM_HARDENING,
            outcome=AuditOutcome.SUCCEEDED if succeeded else AuditOutcome.FAILED,
            reason=reason,
            correlation_id=correlation_id,
        )

    def _emit(
        self,
        *,
        category: AuditCategory,
        action: AuditAction,
        outcome: AuditOutcome,
        reason: AuditReasonCode,
        correlation_id: UUID | None = None,
        record_id: UUID | None = None,
        generation: int | None = None,
        provider_id: str | None = None,
        key_version: int | None = None,
        previous_state: CaptureState | None = None,
        current_state: CaptureState | None = None,
        configuration_revision: str | None = None,
        key_id: str | None = None,
        attributes: Mapping[str, int | bool] | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            category=category,
            action=action,
            outcome=outcome,
            reason=reason,
            correlation_id=correlation_id or uuid4(),
            occurred_at=self._clock(),
            record_id=record_id,
            generation=generation,
            provider_id=provider_id,
            key_version=key_version,
            previous_state=previous_state,
            current_state=current_state,
            configuration_revision_digest=_digest(configuration_revision),
            key_id_digest=_digest(key_id),
            attributes=attributes or {},
        )
        self._sink.emit(event)
        return event


_DELETION_SCOPE_FLAGS = {
    "record-ids": "records",
    "activity-cluster": "cluster",
    "application": "application",
    "time-range": "time_range",
}


def _digest(value: str | None) -> str | None:
    if value is None:
        return None
    return hashlib.blake2b(value.encode("utf-8"), digest_size=16).hexdigest()
