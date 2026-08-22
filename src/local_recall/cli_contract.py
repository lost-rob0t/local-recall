"""Typed, content-minimizing contract for Local Recall CLI requests."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

PROTOCOL_VERSION = "local-recall-cli-v1"
MAX_DEADLINE = timedelta(seconds=30)
MAX_REASON_CODE_LENGTH = 64
MAX_QUERY_RESULT_TEXT_LENGTH = 1_048_576
MAX_CITATIONS = 256
MAX_RECORD_ID_LENGTH = 128
MAX_DIAGNOSTIC_ENTRIES = 256
MAX_DIAGNOSTIC_FIELD_LENGTH = 128


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
    ) -> CliRequest:
        _require_aware(now, field="now")
        _require_aware(deadline, field="deadline")
        if deadline <= now or deadline - now > MAX_DEADLINE:
            raise ValueError("deadline must be in the future and within the request budget")
        if (start is None) is not (end is None):
            raise ValueError("time filter requires both start and end")
        if start is not None and end is not None:
            if command not in {CliCommand.ASK, CliCommand.TIMELINE, CliCommand.SEARCH}:
                raise ValueError("time filter is only valid for query commands")
            _require_aware(start, field="start")
            _require_aware(end, field="end")
            if start >= end:
                raise ValueError("time filter start must precede end")
        return cls(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid.uuid4().hex,
            command=command,
            priority=command.priority,
            deadline=deadline,
            query=query,
            start=start,
            end=end,
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

    @classmethod
    def success(
        cls,
        *,
        request_id: str,
        lifecycle_state: CliLifecycleState | str | None = None,
        query_payload: CliQueryPayload | None = None,
        diagnostic_payload: CliDiagnosticPayload | None = None,
    ) -> CliResponse:
        state = CliLifecycleState(lifecycle_state) if lifecycle_state is not None else None
        payload_count = sum(
            value is not None for value in (state, query_payload, diagnostic_payload)
        )
        if payload_count > 1:
            raise ValueError("success response cannot mix payload types")
        return cls(
            protocol_version=PROTOCOL_VERSION,
            request_id=request_id,
            outcome=CliOutcome.SUCCESS,
            lifecycle_state=state,
            query_payload=query_payload,
            diagnostic_payload=diagnostic_payload,
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
        return (
            "CliResponse("
            f"outcome={self.outcome.value!r}, request_id={self.request_id!r}, "
            f"reason_code={self.reason_code!r}, lifecycle_state={state!r}, "
            f"query_payload={query!r}, diagnostic_payload={diagnostic!r})"
        )
