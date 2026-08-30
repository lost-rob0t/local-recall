"""Versioned, authenticated, bounded Local Recall IPC request framing."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import cast

from local_recall.cli_contract import (
    PROTOCOL_VERSION,
    CliCommand,
    CliPriority,
    CliRequest,
)
from local_recall.ipc import SessionToken

MAX_ROUTING_BYTES = 4_096
MAX_REQUEST_PAYLOAD_BYTES = 131_072
_REQUEST_FRAME_COUNT = 3
_ROUTING_KEYS = frozenset({"protocol_version", "request_id", "command", "priority", "deadline"})
_PAYLOAD_KEYS = frozenset(
    {"query", "start", "end", "record_ids", "cluster_id", "application", "target"}
)


class IpcProtocolError(RuntimeError):
    """Fixed, content-free IPC protocol rejection."""


class IpcCapability(StrEnum):
    """Closed daemon API capabilities used for command authorization."""

    CONTROL = "control"
    QUERY = "query"
    DIAGNOSTIC = "diagnostic"
    EXPORT = "export"
    DELETE = "delete"


_CONTROL_COMMANDS = frozenset(
    {
        CliCommand.START,
        CliCommand.PAUSE,
        CliCommand.RESUME,
        CliCommand.STOP,
        CliCommand.STATUS,
        CliCommand.PRIVACY_ON,
        CliCommand.PRIVACY_OFF,
    }
)
_QUERY_COMMANDS = frozenset(
    {CliCommand.ASK, CliCommand.TIMELINE, CliCommand.SEARCH, CliCommand.PREVIEW_RECORD}
)
_DIAGNOSTIC_COMMANDS = frozenset(
    {CliCommand.PROVIDERS, CliCommand.HEALTH, CliCommand.STORAGE_STATS}
)


@dataclass(frozen=True, slots=True, repr=False)
class IpcRequestCodec:
    """Encode and validate one authenticated CLI request protocol."""

    token: SessionToken
    capabilities: frozenset[IpcCapability]

    def encode(self, request: CliRequest) -> tuple[bytes, bytes, bytes]:
        routing = request.routing_json().encode("utf-8")
        payload = json.dumps(
            {
                "application": request.application,
                "cluster_id": request.cluster_id,
                "end": request.end.isoformat() if request.end is not None else None,
                "query": request.query,
                "record_ids": list(request.record_ids),
                "start": request.start.isoformat() if request.start is not None else None,
                "target": request.target,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(routing) > MAX_ROUTING_BYTES:
            raise IpcProtocolError("routing-too-large")
        if len(payload) > MAX_REQUEST_PAYLOAD_BYTES:
            raise IpcProtocolError("payload-too-large")
        return routing, self.token.frame(), payload

    def decode(self, frames: tuple[bytes, ...], *, now: datetime) -> CliRequest:
        if len(frames) != _REQUEST_FRAME_COUNT:
            raise IpcProtocolError("frame-count")
        routing_frame, authentication_frame, payload_frame = frames
        if len(routing_frame) > MAX_ROUTING_BYTES:
            raise IpcProtocolError("routing-too-large")
        if len(payload_frame) > MAX_REQUEST_PAYLOAD_BYTES:
            raise IpcProtocolError("payload-too-large")

        # Authentication deliberately precedes every content-bearing parse.
        if not self.token.matches(authentication_frame):
            raise IpcProtocolError("unauthorized")

        routing = _decode_object(routing_frame, error="invalid-routing")
        if frozenset(routing) != _ROUTING_KEYS:
            raise IpcProtocolError("invalid-routing")

        protocol_version = _string_field(routing, "protocol_version")
        if protocol_version != PROTOCOL_VERSION:
            raise IpcProtocolError("protocol-version")
        request_id = _request_id(_string_field(routing, "request_id"))
        command = _command(_string_field(routing, "command"))
        priority = _priority(_string_field(routing, "priority"))
        if priority is not command.priority:
            raise IpcProtocolError("priority-mismatch")
        if _required_capability(command) not in self.capabilities:
            raise IpcProtocolError("capability-denied")
        deadline = _timestamp(_string_field(routing, "deadline"), field="deadline")

        payload = _decode_object(payload_frame, error="invalid-payload")
        if frozenset(payload) != _PAYLOAD_KEYS:
            raise IpcProtocolError("invalid-payload")
        query = _optional_string(payload, "query")
        start = _optional_timestamp(payload, "start")
        end = _optional_timestamp(payload, "end")
        record_ids = _optional_record_ids(payload, "record_ids")
        cluster_id = _optional_string(payload, "cluster_id")
        application = _optional_string(payload, "application")
        target = _optional_string(payload, "target")

        try:
            validated = CliRequest.create(
                command=command,
                now=now,
                deadline=deadline,
                query=query,
                start=start,
                end=end,
                record_ids=record_ids,
                cluster_id=cluster_id,
                application=application,
                target=target,
            )
        except TypeError, ValueError:
            raise IpcProtocolError("invalid-request") from None

        return CliRequest(
            protocol_version=validated.protocol_version,
            request_id=request_id,
            command=validated.command,
            priority=validated.priority,
            deadline=validated.deadline,
            query=validated.query,
            start=validated.start,
            end=validated.end,
            record_ids=validated.record_ids,
            cluster_id=validated.cluster_id,
            application=validated.application,
            target=validated.target,
        )

    def __repr__(self) -> str:
        capabilities = ",".join(sorted(capability.value for capability in self.capabilities))
        return f"IpcRequestCodec(token=<secret>, capabilities={capabilities!r})"


def _decode_object(frame: bytes, *, error: str) -> dict[str, object]:
    try:
        text = frame.decode("utf-8", errors="strict")
        loaded = cast(object, json.loads(text))
    except UnicodeDecodeError, json.JSONDecodeError:
        raise IpcProtocolError(error) from None
    if not isinstance(loaded, dict):
        raise IpcProtocolError(error)
    mapping = cast(dict[object, object], loaded)
    result: dict[str, object] = {}
    for key, value in mapping.items():
        if not isinstance(key, str):
            raise IpcProtocolError(error)
        result[key] = value
    return result


def _string_field(values: dict[str, object], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str):
        raise IpcProtocolError("invalid-routing")
    return value


def _optional_string(values: dict[str, object], key: str) -> str | None:
    value = values.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise IpcProtocolError("invalid-payload")
    return value


def _request_id(value: str) -> str:
    if len(value) != 32 or any(character not in "0123456789abcdef" for character in value):
        raise IpcProtocolError("invalid-request-id")
    return value


def _command(value: str) -> CliCommand:
    try:
        return CliCommand(value)
    except ValueError:
        raise IpcProtocolError("invalid-command") from None


def _priority(value: str) -> CliPriority:
    try:
        return CliPriority(value)
    except ValueError:
        raise IpcProtocolError("invalid-priority") from None


def _timestamp(value: str, *, field: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError:
        raise IpcProtocolError(f"invalid-{field}") from None
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise IpcProtocolError(f"invalid-{field}")
    return timestamp


def _optional_timestamp(values: dict[str, object], key: str) -> datetime | None:
    value = values.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise IpcProtocolError("invalid-payload")
    return _timestamp(value, field=key)


_DELETION_COMMANDS = frozenset({CliCommand.DELETE_RECORDS})


def _required_capability(command: CliCommand) -> IpcCapability:
    if command in _CONTROL_COMMANDS:
        return IpcCapability.CONTROL
    if command in _QUERY_COMMANDS:
        return IpcCapability.QUERY
    if command in _DIAGNOSTIC_COMMANDS:
        return IpcCapability.DIAGNOSTIC
    if command in _DELETION_COMMANDS:
        return IpcCapability.DELETE
    raise IpcProtocolError("invalid-command")


def _optional_record_ids(values: dict[str, object], key: str) -> tuple[str, ...]:
    value = values.get(key)
    if value is None:
        return ()
    if not isinstance(value, list):
        raise IpcProtocolError("invalid-payload")
    raw_items = cast(list[object], value)
    if any(not isinstance(item, str) for item in raw_items):
        raise IpcProtocolError("invalid-payload")
    return tuple(cast(list[str], raw_items))
