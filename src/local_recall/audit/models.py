from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID, uuid4

from local_recall.domain.lifecycle import CaptureState

from .errors import AuditFailure, AuditFailureCode


class AuditCategory(StrEnum):
    LIFECYCLE = "lifecycle"
    CAPTURE = "capture"
    POLICY = "policy"
    PROVIDER = "provider"
    RECORD = "record"
    EXPORT = "export"
    KEY = "key"
    SYSTEM = "system"
    IPC = "ipc"


class AuditAction(StrEnum):
    LIFECYCLE_TRANSITION = "lifecycle_transition"
    CAPTURE_DECISION = "capture_decision"
    POLICY_DECISION = "policy_decision"
    PROVIDER_SELECTION = "provider_selection"
    RECORD_REJECTED = "record_rejected"
    RECORD_DELETED = "record_deleted"
    DELETION_REQUEST = "deletion_request"
    EXPORT_DECISION = "export_decision"
    RESTORE_DECISION = "restore_decision"
    KEY_OPERATION = "key_operation"
    SYSTEM_HARDENING = "system_hardening"
    RETENTION_SWEEP = "retention_sweep"
    PURGE_ALL = "purge_all"
    GARBAGE_COLLECTION = "garbage_collection"
    STORAGE_PERMISSION_CHECK = "storage_permission_check"
    LOG_ROTATION = "log_rotation"
    IPC_REQUEST = "ipc_request"


class AuditOutcome(StrEnum):
    ACCEPTED = "accepted"
    SKIPPED = "skipped"
    REJECTED = "rejected"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class AuditReasonCode(StrEnum):
    USER_REQUEST = "user_request"
    STARTUP_OPT_IN = "startup_opt_in"
    STARTUP_SAFE_DEFAULT = "startup_safe_default"
    SHUTDOWN = "shutdown"
    POLICY_ALLOW = "policy_allow"
    POLICY_DENY = "policy_deny"
    POLICY_FAILURE = "policy_failure"
    CAPTURE_DISABLED = "capture_disabled"
    CAPTURE_PAUSED = "capture_paused"
    PRIVACY_MODE = "privacy_mode"
    SESSION_LOCKED = "session_locked"
    SESSION_UNLOCKED = "session_unlocked"
    IDLE = "idle"
    ACTIVE = "active"
    STALE_GENERATION = "stale_generation"
    OVERLOAD = "overload"
    REDACTION_FAILED = "redaction_failed"
    ENCRYPTION_UNAVAILABLE = "encryption_unavailable"
    PERSISTENCE_FAILED = "persistence_failed"
    INVALID_RECORD = "invalid_record"
    CORRUPTION_QUARANTINED = "corruption_quarantined"
    DELETION_COMPLETED = "deletion_completed"
    EXPORT_ALLOWED = "export_allowed"
    EXPORT_DENIED = "export_denied"
    PROVIDER_LOCAL = "provider_local"
    PROVIDER_REMOTE_AUTHORIZED = "provider_remote_authorized"
    PROVIDER_REJECTED = "provider_rejected"
    KEY_CREATED = "key_created"
    KEY_ROTATED = "key_rotated"
    KEY_REVOKED = "key_revoked"
    KEY_DESTROYED = "key_destroyed"
    PERMISSIONS_VALID = "permissions_valid"
    PERMISSIONS_INVALID = "permissions_invalid"
    CORE_DUMPS_DISABLED = "core_dumps_disabled"
    RETENTION_SWEEP = "retention_sweep"
    PURGE_ALL = "purge_all"
    GARBAGE_COLLECTION = "garbage_collection"
    HARDENING_FAILED = "hardening_failed"
    CRITICAL_FAULT = "critical_fault"
    IPC_AUTHORIZED = "ipc_authorized"
    IPC_REJECTED = "ipc_rejected"


_ACTION_CATEGORIES: dict[AuditAction, AuditCategory] = {
    AuditAction.LIFECYCLE_TRANSITION: AuditCategory.LIFECYCLE,
    AuditAction.CAPTURE_DECISION: AuditCategory.CAPTURE,
    AuditAction.POLICY_DECISION: AuditCategory.POLICY,
    AuditAction.PROVIDER_SELECTION: AuditCategory.PROVIDER,
    AuditAction.RECORD_REJECTED: AuditCategory.RECORD,
    AuditAction.RECORD_DELETED: AuditCategory.RECORD,
    AuditAction.DELETION_REQUEST: AuditCategory.RECORD,
    AuditAction.EXPORT_DECISION: AuditCategory.EXPORT,
    AuditAction.RESTORE_DECISION: AuditCategory.EXPORT,
    AuditAction.KEY_OPERATION: AuditCategory.KEY,
    AuditAction.SYSTEM_HARDENING: AuditCategory.SYSTEM,
    AuditAction.RETENTION_SWEEP: AuditCategory.SYSTEM,
    AuditAction.PURGE_ALL: AuditCategory.SYSTEM,
    AuditAction.GARBAGE_COLLECTION: AuditCategory.SYSTEM,
    AuditAction.STORAGE_PERMISSION_CHECK: AuditCategory.SYSTEM,
    AuditAction.LOG_ROTATION: AuditCategory.SYSTEM,
    AuditAction.IPC_REQUEST: AuditCategory.IPC,
}

_ALLOWED_ATTRIBUTE_KEYS = frozenset(
    {
        "remote",
        "authorized",
        "privacy_mode",
        "deleted",
        "cryptographic_material_destroyed",
        "count",
        "bytes",
        "attempt",
        "queue_depth",
        "quarantined",
        "control",
        "query",
        "diagnostic",
        "urgent",
        "delete",
        "records",
        "cluster",
        "application",
        "time_range",
        "success",
        "dry_run",
        "key_destroyed",
    }
)


def _empty_attributes() -> dict[str, int | bool]:
    return {}


@dataclass(frozen=True, slots=True, repr=False)
class AuditEvent:
    category: AuditCategory
    action: AuditAction
    outcome: AuditOutcome
    reason: AuditReasonCode
    correlation_id: UUID
    occurred_at: datetime
    event_id: UUID = field(default_factory=uuid4)
    record_id: UUID | None = None
    generation: int | None = None
    provider_id: str | None = None
    key_version: int | None = None
    previous_state: CaptureState | None = None
    current_state: CaptureState | None = None
    configuration_revision_digest: str | None = None
    key_id_digest: str | None = None
    attributes: Mapping[str, int | bool] = field(default_factory=_empty_attributes)

    def __post_init__(self) -> None:
        if type(self.category) is not AuditCategory:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if type(self.action) is not AuditAction:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if type(self.outcome) is not AuditOutcome:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if type(self.reason) is not AuditReasonCode:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if _ACTION_CATEGORIES[self.action] is not self.category:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if self.event_id.version != 4 or self.correlation_id.version != 4:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if self.record_id is not None and self.record_id.version != 4:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if self.generation is not None and self.generation <= 0:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if self.key_version is not None and self.key_version <= 0:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if self.previous_state is not None and type(self.previous_state) is not CaptureState:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if self.current_state is not None and type(self.current_state) is not CaptureState:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if (self.previous_state is None) != (self.current_state is None):
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if self.provider_id is not None and not _safe_identifier(self.provider_id):
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if self.configuration_revision_digest is not None and not _digest(
            self.configuration_revision_digest
        ):
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if self.key_id_digest is not None and not _digest(self.key_id_digest):
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        normalized: dict[str, int | bool] = {}
        for key, value in self.attributes.items():
            if key not in _ALLOWED_ATTRIBUTE_KEYS:
                raise AuditFailure(AuditFailureCode.INVALID_EVENT)
            if type(value) not in {int, bool}:
                raise AuditFailure(AuditFailureCode.INVALID_EVENT)
            if type(value) is int and value < 0:
                raise AuditFailure(AuditFailureCode.INVALID_EVENT)
            normalized[key] = value
        _validate_action_fields(self, normalized)
        object.__setattr__(self, "attributes", MappingProxyType(normalized))

    def __repr__(self) -> str:
        return (
            f"AuditEvent(event_id={self.event_id!r}, category={self.category.value!r}, "
            f"action={self.action.value!r}, outcome={self.outcome.value!r}, "
            f"reason={self.reason.value!r}, correlation_id={self.correlation_id!r}, "
            f"record_id={self.record_id!r}, generation={self.generation!r}, "
            f"previous_state={self.previous_state!r}, current_state={self.current_state!r})"
        )


def _validate_action_fields(event: AuditEvent, attributes: dict[str, int | bool]) -> None:
    if event.action is AuditAction.LIFECYCLE_TRANSITION:
        if event.previous_state is None or event.current_state is None or event.generation is None:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
    elif event.previous_state is not None or event.current_state is not None:
        raise AuditFailure(AuditFailureCode.INVALID_EVENT)

    if (
        event.action
        in {
            AuditAction.CAPTURE_DECISION,
            AuditAction.POLICY_DECISION,
            AuditAction.RECORD_REJECTED,
        }
        and event.generation is None
    ):
        raise AuditFailure(AuditFailureCode.INVALID_EVENT)

    if (
        event.action in {AuditAction.RECORD_REJECTED, AuditAction.RECORD_DELETED}
        and event.record_id is None
    ):
        raise AuditFailure(AuditFailureCode.INVALID_EVENT)

    if event.action is AuditAction.RETENTION_SWEEP:
        required = {"count", "bytes", "success", "dry_run"}
        if set(attributes) != required:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        for key in ("success", "dry_run"):
            if type(attributes[key]) is not bool:
                raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        for key in ("count", "bytes"):
            if type(attributes[key]) is not int or attributes[key] < 0:
                raise AuditFailure(AuditFailureCode.INVALID_EVENT)

    if event.action is AuditAction.RESTORE_DECISION:
        required = {"count", "success"}
        if set(attributes) != required:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if type(attributes["success"]) is not bool:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if type(attributes["count"]) is not int or attributes["count"] < 0:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)

    if event.action is AuditAction.GARBAGE_COLLECTION:
        required = {"count", "success"}
        if set(attributes) != required:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if type(attributes["success"]) is not bool:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if type(attributes["count"]) is not int or attributes["count"] < 0:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)

    if event.action is AuditAction.PURGE_ALL:
        required = {"count", "success", "key_destroyed"}
        if set(attributes) != required:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if type(attributes["success"]) is not bool or type(attributes["key_destroyed"]) is not bool:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if type(attributes["count"]) is not int or attributes["count"] < 0:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)

    if event.action is AuditAction.DELETION_REQUEST:
        required = {
            "records",
            "cluster",
            "application",
            "time_range",
            "success",
            "count",
        }
        if set(attributes) != required:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        for key in ("records", "cluster", "application", "time_range", "success"):
            if type(attributes[key]) is not bool:
                raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if type(attributes["count"]) is not int or attributes["count"] < 0:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        scope_classes = sum(
            1
            for key in ("records", "cluster", "application", "time_range")
            if attributes[key] is True
        )
        if scope_classes != 1:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)

    if event.action is AuditAction.PROVIDER_SELECTION:
        if set(attributes) != {"remote", "authorized"}:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        remote = attributes["remote"]
        authorized = attributes["authorized"]
        if type(remote) is not bool or type(authorized) is not bool:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)

    if event.action is AuditAction.IPC_REQUEST:
        required = {"authorized", "control", "diagnostic", "query", "delete", "urgent"}
        if set(attributes) != required:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        if any(type(attributes[key]) is not bool for key in required):
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        capability_count = sum(
            1 for key in ("control", "diagnostic", "query", "delete") if attributes[key] is True
        )
        authorized = attributes["authorized"]
        if (authorized and capability_count != 1) or (not authorized and capability_count > 1):
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)

    if event.action is AuditAction.KEY_OPERATION and (
        event.provider_id is None or event.key_version is None or event.key_id_digest is None
    ):
        raise AuditFailure(AuditFailureCode.INVALID_EVENT)


def _safe_identifier(value: str) -> bool:
    if not 1 <= len(value) <= 64:
        return False
    first = value[0]
    if not (first.isascii() and first.isalnum()):
        return False
    return all(
        character.isascii() and (character.isalnum() or character in "_.:-") for character in value
    )


def _digest(value: str) -> bool:
    return len(value) == 32 and all(character in "0123456789abcdef" for character in value)
