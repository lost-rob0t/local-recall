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


@dataclass(frozen=True, slots=True, repr=False)
class CliRequest:
    """One bounded request from the CLI to the daemon."""

    protocol_version: str
    request_id: str
    command: CliCommand
    priority: CliPriority
    deadline: datetime
    query: str | None = None

    @classmethod
    def create(
        cls,
        *,
        command: CliCommand,
        now: datetime,
        deadline: datetime,
        query: str | None = None,
    ) -> CliRequest:
        _require_aware(now, field="now")
        _require_aware(deadline, field="deadline")
        if deadline <= now or deadline - now > MAX_DEADLINE:
            raise ValueError("deadline must be in the future and within the request budget")
        return cls(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid.uuid4().hex,
            command=command,
            priority=command.priority,
            deadline=deadline,
            query=query,
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
    """Sanitized response envelope used for CLI control flow."""

    protocol_version: str
    request_id: str
    outcome: CliOutcome
    reason_code: str | None = None
    lifecycle_state: CliLifecycleState | None = None

    @classmethod
    def success(
        cls,
        *,
        request_id: str,
        lifecycle_state: CliLifecycleState | str | None = None,
    ) -> CliResponse:
        state = CliLifecycleState(lifecycle_state) if lifecycle_state is not None else None
        return cls(
            protocol_version=PROTOCOL_VERSION,
            request_id=request_id,
            outcome=CliOutcome.SUCCESS,
            lifecycle_state=state,
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
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def __repr__(self) -> str:
        state = self.lifecycle_state.value if self.lifecycle_state is not None else None
        return (
            "CliResponse("
            f"outcome={self.outcome.value!r}, request_id={self.request_id!r}, "
            f"reason_code={self.reason_code!r}, lifecycle_state={state!r})"
        )
