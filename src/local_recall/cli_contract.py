"""Typed, content-minimizing contract for Local Recall CLI requests."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum

PROTOCOL_VERSION = "local-recall-cli-v1"
MAX_DEADLINE = timedelta(seconds=30)
MAX_REASON_CODE_LENGTH = 64
MAX_QUERY_TEXT_LENGTH = 65_536
MAX_QUERY_RESULT_TEXT_LENGTH = 1_048_576
MAX_CITATIONS = 256
MAX_RECORD_ID_LENGTH = 128
MAX_DIAGNOSTIC_ENTRIES = 256
MAX_DIAGNOSTIC_FIELD_LENGTH = 128
MAX_STATUS_IDENTIFIER_LENGTH = 128
_MAX_SCOPE_RECORD_IDS = 1_000
_CLUSTER_ID_LENGTH = 32
_MAX_APPLICATION_FILTER_LENGTH = 256
_PREVIEW_TARGETS = frozenset({"text", "image"})


class CliPriority(StrEnum):
    """Server scheduling class requested by a CLI command."""

    URGENT_CONTROL = "urgent-control"
    CONTROL = "control"
    QUERY = "query"


class CliCommand(StrEnum):
    """Closed set of daemon commands exposed through the CLI boundary."""

    START = "start"
    PAUSE = "pause"
    RESUME = "resume"
    STOP = "stop"
    STATUS = "status"
    PRIVACY_ON = "privacy-on"
    PRIVACY_OFF = "privacy-off"
    ASK = "ask"
    TIMELINE = "timeline"
    SEARCH = "search"
    PREVIEW_RECORD = "preview-record"
    DELETE_RECORDS = "delete-records"
    PROVIDERS = "providers"
    HEALTH = "health"
    STORAGE_STATS = "storage-stats"

    @property
    def priority(self) -> CliPriority:
        if self in {CliCommand.STOP, CliCommand.PRIVACY_ON, CliCommand.PRIVACY_OFF}:
            return CliPriority.URGENT_CONTROL
        if self in {
            CliCommand.START,
            CliCommand.PAUSE,
            CliCommand.RESUME,
            CliCommand.STATUS,
        }:
            return CliPriority.CONTROL
        return CliPriority.QUERY


_TIME_FILTER_COMMANDS = frozenset(
    {CliCommand.ASK, CliCommand.TIMELINE, CliCommand.SEARCH, CliCommand.DELETE_RECORDS}
)
_DELETION_COMMANDS = frozenset({CliCommand.DELETE_RECORDS, CliCommand.PREVIEW_RECORD})


class CliOutcome(StrEnum):
    """Closed response outcomes safe for exit-code and rendering decisions."""

    SUCCESS = "success"
    UNAVAILABLE = "unavailable"
    UNAUTHORIZED = "unauthorized"
    LOCKED = "locked"
    INVALID = "invalid"
    OVERLOADED = "overloaded"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    FAULTED = "faulted"
    INTERNAL_FAILURE = "internal-failure"


class CliLifecycleState(StrEnum):
    """Sanitized authoritative daemon lifecycle states."""

    OFF = "off"
    PAUSED = "paused"
    RECORDING = "recording"
    LOCKED = "locked"
    OVERLOADED = "overloaded"
    FAULTED = "faulted"


class CliDiagnosticCategory(StrEnum):
    """Closed operational diagnostic categories."""

    PROVIDERS = "providers"
    HEALTH = "health"
    STORAGE = "storage"


def _require_aware(value: datetime, *, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")


def _validate_reason_code(reason_code: str) -> None:
    if not reason_code or len(reason_code) > MAX_REASON_CODE_LENGTH:
        raise ValueError("reason_code has invalid length")
    if any(
        not (character.isascii() and (character.isalnum() or character in "-_"))
        for character in reason_code
    ):
        raise ValueError("reason_code contains invalid characters")


def _validate_diagnostic_field(value: str, *, field: str) -> None:
    if not value or len(value) > MAX_DIAGNOSTIC_FIELD_LENGTH:
        raise ValueError(f"{field} has invalid length")
    if any(character in "\r\n\x00" for character in value):
        raise ValueError(f"{field} contains invalid characters")


def _validate_status_identifier(value: str, *, field: str) -> None:
    if not value or len(value) > MAX_STATUS_IDENTIFIER_LENGTH:
        raise ValueError(f"{field} has invalid length")
    if any(
        not (character.isascii() and (character.isalnum() or character in "-_."))
        for character in value
    ):
        raise ValueError(f"{field} contains invalid characters")


def _validate_command_query(command: CliCommand, query: str | None) -> None:
    text_query_commands = {CliCommand.ASK, CliCommand.SEARCH}
    if command in text_query_commands:
        if query is None or not query.strip() or len(query) > MAX_QUERY_TEXT_LENGTH:
            raise ValueError("query has invalid length or content")
        return
    if query is not None:
        raise ValueError("query is not valid for this command")


def _validate_record_id_scope(
    command: CliCommand,
    record_ids: tuple[str, ...] | list[str],
) -> tuple[str, ...]:
    if not record_ids:
        if command is CliCommand.PREVIEW_RECORD:
            raise ValueError("preview scope requires exactly one record ID")
        return ()
    if command not in _DELETION_COMMANDS:
        raise ValueError("deletion scope fields are only valid for deletion commands")
    if command is CliCommand.PREVIEW_RECORD and len(record_ids) != 1:
        raise ValueError("preview scope requires exactly one record ID")
    if len(record_ids) > _MAX_SCOPE_RECORD_IDS:
        raise ValueError("deletion scope exceeds the record limit")
    for record_id in record_ids:
        if not record_id:
            raise ValueError("deletion scope record IDs must be non-empty strings")
        try:
            uuid.UUID(hex=record_id)
        except ValueError as exc:
            raise ValueError("deletion scope record IDs must be canonical UUIDs") from exc
    return tuple(record_ids)


def _validate_cluster_scope(command: CliCommand, cluster_id: str | None) -> str | None:
    if cluster_id is None:
        return None
    if command is not CliCommand.DELETE_RECORDS:
        raise ValueError("deletion scope fields are only valid for deletion commands")
    if len(cluster_id) != _CLUSTER_ID_LENGTH or any(
        character not in "0123456789abcdef" for character in cluster_id
    ):
        raise ValueError("deletion scope cluster identifier is invalid")
    return cluster_id


def _validate_application_scope(command: CliCommand, application: str | None) -> str | None:
    if application is None:
        return None
    if command not in {CliCommand.DELETE_RECORDS, CliCommand.TIMELINE}:
        raise ValueError("application filter is only valid for timeline and deletion commands")
    if not application or len(application) > _MAX_APPLICATION_FILTER_LENGTH:
        raise ValueError("deletion scope application value has invalid length")
    if any(character in "\r\n\x00" or ord(character) < 0x20 for character in application):
        raise ValueError("deletion scope application value contains invalid characters")
    return application


def _validate_target(command: CliCommand, target: str | None) -> str | None:
    if target is None:
        if command is CliCommand.PREVIEW_RECORD:
            raise ValueError("preview scope requires a closed preview target")
        return None
    if command is not CliCommand.PREVIEW_RECORD:
        raise ValueError("deletion scope fields are only valid for deletion commands")
    if target not in _PREVIEW_TARGETS:
        raise ValueError("preview target is invalid")
    return target


def _validate_single_deletion_scope(
    *,
    has_records: bool,
    has_cluster: bool,
    has_application: bool,
    has_range: bool,
) -> None:
    selected = sum(
        (
            has_records,
            has_cluster,
            has_range and not has_application,
            has_application,
        )
    )
    if selected != 1:
        raise ValueError("deletion scope must select exactly one scope class")


@dataclass(frozen=True, slots=True, repr=False)
class CliCitation:
    """Opaque record citation intentionally safe for requested query output."""

    record_id: str
    captured_at: datetime

    def __post_init__(self) -> None:
        if not self.record_id or len(self.record_id) > MAX_RECORD_ID_LENGTH:
            raise ValueError("record_id has invalid length")
        _require_aware(self.captured_at, field="captured_at")

    def to_dict(self) -> dict[str, str]:
        return {
            "record_id": self.record_id,
            "captured_at": self.captured_at.isoformat(),
        }

    def __repr__(self) -> str:
        return "CliCitation(record_id=<opaque>, captured_at=<timestamp>)"


@dataclass(frozen=True, slots=True, repr=False)
class CliQueryPayload:
    """Bounded user-requested query content plus canonical source citations."""

    text: str
    citations: tuple[CliCitation, ...] = ()

    def __post_init__(self) -> None:
        if not self.text or len(self.text) > MAX_QUERY_RESULT_TEXT_LENGTH:
            raise ValueError("query result text has invalid length")
        if len(self.citations) > MAX_CITATIONS:
            raise ValueError("too many citations")
        record_ids = tuple(citation.record_id for citation in self.citations)
        if len(record_ids) != len(set(record_ids)):
            raise ValueError("citations must have unique record IDs")

    def to_json(self) -> str:
        return json.dumps(
            {
                "text": self.text,
                "citations": [citation.to_dict() for citation in self.citations],
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def __repr__(self) -> str:
        return f"CliQueryPayload(text=<content>, citation_count={len(self.citations)})"


@dataclass(frozen=True, slots=True, repr=False)
class CliDiagnosticEntry:
    """One bounded, sanitized operational status field."""

    name: str
    state: str
    value: str | None = None

    def __post_init__(self) -> None:
        _validate_diagnostic_field(self.name, field="name")
        _validate_diagnostic_field(self.state, field="state")
        if self.value is not None:
            _validate_diagnostic_field(self.value, field="value")

    def to_dict(self) -> dict[str, str | None]:
        return {"name": self.name, "state": self.state, "value": self.value}

    def __repr__(self) -> str:
        return "CliDiagnosticEntry(name=<opaque>, state=<opaque>, value=<opaque>)"


@dataclass(frozen=True, slots=True, repr=False)
class CliDiagnosticPayload:
    """Closed bounded operational diagnostic response."""

    category: CliDiagnosticCategory
    entries: tuple[CliDiagnosticEntry, ...] = ()

    def __post_init__(self) -> None:
        if len(self.entries) > MAX_DIAGNOSTIC_ENTRIES:
            raise ValueError("too many diagnostic entries")
        names = tuple(entry.name for entry in self.entries)
        if len(names) != len(set(names)):
            raise ValueError("diagnostic entry names must be unique")

    def to_json(self) -> str:
        return json.dumps(
            {
                "category": self.category.value,
                "entries": [entry.to_dict() for entry in self.entries],
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def __repr__(self) -> str:
        return (
            "CliDiagnosticPayload("
            f"category={self.category.value!r}, entry_count={len(self.entries)})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CliStatusPayload:
    """Content-free authoritative status details intended for status indicators."""

    privacy_mode: bool
    capture_backend: str | None = None
    metadata_source: str | None = None
    last_capture_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.capture_backend is not None:
            _validate_status_identifier(self.capture_backend, field="capture_backend")
        if self.metadata_source is not None:
            _validate_status_identifier(self.metadata_source, field="metadata_source")
        if self.last_capture_at is not None:
            _require_aware(self.last_capture_at, field="last_capture_at")

    def to_dict(self) -> dict[str, bool | str | None]:
        return {
            "privacy_mode": self.privacy_mode,
            "capture_backend": self.capture_backend,
            "metadata_source": self.metadata_source,
            "last_capture_at": (
                self.last_capture_at.isoformat() if self.last_capture_at is not None else None
            ),
        }

    def __repr__(self) -> str:
        return (
            "CliStatusPayload("
            f"privacy_mode={self.privacy_mode}, capture_backend=<opaque>, "
            "metadata_source=<opaque>, last_capture_at=<timestamp>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CliDeletionPayload:
    """Content-free destructive-operation result for authorized deletion."""

    deleted_count: int
    scope_kind: str
    recovered: bool = False

    def __post_init__(self) -> None:
        if self.deleted_count < 0:
            raise ValueError("deleted_count must be non-negative")
        if self.scope_kind not in {
            "record-ids",
            "activity-cluster",
            "application",
            "time-range",
        }:
            raise ValueError("scope_kind is not a closed deletion scope class")

    def to_json(self) -> str:
        return json.dumps(
            {
                "deleted_count": self.deleted_count,
                "recovered": self.recovered,
                "scope_kind": self.scope_kind,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def __repr__(self) -> str:
        return (
            "CliDeletionPayload("
            f"deleted_count={self.deleted_count}, scope_kind={self.scope_kind!r}, "
            f"recovered={self.recovered})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CliRequest:
    """One bounded request from the CLI to the daemon."""

    protocol_version: str
    request_id: str
    command: CliCommand
    priority: CliPriority
    deadline: datetime
    query: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    record_ids: tuple[str, ...] = ()
    cluster_id: str | None = None
    application: str | None = field(default=None, repr=False)
    target: str | None = None

    @classmethod
    def create(
        cls,
        *,
        command: CliCommand,
        now: datetime,
        deadline: datetime,
        query: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        record_ids: tuple[str, ...] | list[str] = (),
        cluster_id: str | None = None,
        application: str | None = None,
        target: str | None = None,
    ) -> CliRequest:
        _require_aware(now, field="now")
        _require_aware(deadline, field="deadline")
        if deadline <= now or deadline - now > MAX_DEADLINE:
            raise ValueError("deadline must be in the future and within the request budget")
        _validate_command_query(command, query)
        if (start is None) is not (end is None):
            raise ValueError("time filter requires both start and end")
        if start is not None and end is not None:
            if command not in _TIME_FILTER_COMMANDS:
                raise ValueError("time filter is only valid for query commands")
            _require_aware(start, field="start")
            _require_aware(end, field="end")
            if start >= end:
                raise ValueError("time filter start must precede end")
        scoped_record_ids = _validate_record_id_scope(command, record_ids)
        validated_cluster_id = _validate_cluster_scope(command, cluster_id)
        validated_application = _validate_application_scope(command, application)
        validated_target = _validate_target(command, target)
        if command is CliCommand.DELETE_RECORDS:
            if validated_application is not None and start is None:
                raise ValueError("application deletion scope requires explicit time bounds")
            _validate_single_deletion_scope(
                has_records=bool(scoped_record_ids),
                has_cluster=validated_cluster_id is not None,
                has_application=validated_application is not None,
                has_range=start is not None,
            )
        return cls(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid.uuid4().hex,
            command=command,
            priority=command.priority,
            deadline=deadline,
            query=query,
            start=start,
            end=end,
            record_ids=scoped_record_ids,
            cluster_id=validated_cluster_id,
            application=validated_application,
            target=validated_target,
        )

    def routing_json(self) -> str:
        """Serialize content-free request routing metadata."""
        return json.dumps(
            {
                "protocol_version": self.protocol_version,
                "request_id": self.request_id,
                "command": self.command.value,
                "priority": self.priority.value,
                "deadline": self.deadline.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def __repr__(self) -> str:
        return (
            "CliRequest("
            f"command={self.command.value!r}, priority={self.priority.value!r}, "
            f"request_id={self.request_id!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CliResponse:
    """Sanitized envelope plus explicit user-requested output."""

    protocol_version: str
    request_id: str
    outcome: CliOutcome
    reason_code: str | None = None
    lifecycle_state: CliLifecycleState | None = None
    query_payload: CliQueryPayload | None = None
    diagnostic_payload: CliDiagnosticPayload | None = None
    status_payload: CliStatusPayload | None = None
    deletion_payload: CliDeletionPayload | None = None

    @classmethod
    def success(
        cls,
        *,
        request_id: str,
        lifecycle_state: CliLifecycleState | str | None = None,
        query_payload: CliQueryPayload | None = None,
        diagnostic_payload: CliDiagnosticPayload | None = None,
        status_payload: CliStatusPayload | None = None,
        deletion_payload: CliDeletionPayload | None = None,
    ) -> CliResponse:
        state = CliLifecycleState(lifecycle_state) if lifecycle_state is not None else None
        content_payload_count = sum(
            value is not None
            for value in (query_payload, diagnostic_payload, status_payload, deletion_payload)
        )
        if content_payload_count > 1:
            raise ValueError("success response cannot mix payload types")
        if state is not None and (
            query_payload is not None
            or diagnostic_payload is not None
            or deletion_payload is not None
        ):
            raise ValueError("lifecycle state cannot accompany query or diagnostic payload")
        if status_payload is not None and state is None:
            raise ValueError("status payload requires lifecycle state")
        return cls(
            protocol_version=PROTOCOL_VERSION,
            request_id=request_id,
            outcome=CliOutcome.SUCCESS,
            lifecycle_state=state,
            query_payload=query_payload,
            diagnostic_payload=diagnostic_payload,
            status_payload=status_payload,
            deletion_payload=deletion_payload,
        )

    @classmethod
    def failure(
        cls,
        *,
        request_id: str,
        outcome: CliOutcome,
        reason_code: str,
    ) -> CliResponse:
        if outcome is CliOutcome.SUCCESS:
            raise ValueError("failure response cannot use success outcome")
        _validate_reason_code(reason_code)
        return cls(
            protocol_version=PROTOCOL_VERSION,
            request_id=request_id,
            outcome=outcome,
            reason_code=reason_code,
        )

    def to_json(self) -> str:
        return json.dumps(
            {
                "protocol_version": self.protocol_version,
                "request_id": self.request_id,
                "outcome": self.outcome.value,
                "reason_code": self.reason_code,
                "lifecycle_state": (
                    self.lifecycle_state.value if self.lifecycle_state is not None else None
                ),
                "query_payload": (
                    json.loads(self.query_payload.to_json())
                    if self.query_payload is not None
                    else None
                ),
                "diagnostic_payload": (
                    json.loads(self.diagnostic_payload.to_json())
                    if self.diagnostic_payload is not None
                    else None
                ),
                "status_payload": (
                    self.status_payload.to_dict() if self.status_payload is not None else None
                ),
                "deletion_payload": (
                    json.loads(self.deletion_payload.to_json())
                    if self.deletion_payload is not None
                    else None
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def __repr__(self) -> str:
        state = self.lifecycle_state.value if self.lifecycle_state is not None else None
        query = (
            f"{len(self.query_payload.citations)} citations"
            if self.query_payload is not None
            else None
        )
        diagnostic = (
            f"{len(self.diagnostic_payload.entries)} entries"
            if self.diagnostic_payload is not None
            else None
        )
        status = "present" if self.status_payload is not None else None
        return (
            "CliResponse("
            f"outcome={self.outcome.value!r}, request_id={self.request_id!r}, "
            f"reason_code={self.reason_code!r}, lifecycle_state={state!r}, "
            f"query_payload={query!r}, diagnostic_payload={diagnostic!r}, "
            f"status_payload={status!r})"
        )
