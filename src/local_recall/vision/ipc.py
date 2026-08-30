"""Owner-only IPC transport for visual-context explanation requests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from local_recall.ipc import SessionToken
from local_recall.ipc_protocol import (
    MAX_ROUTING_BYTES,
    IpcCapability,
    IpcProtocolError,
)
from local_recall.ipc_protocol import (
    PROTOCOL_VERSION as IPC_PROTOCOL_VERSION,
)
from local_recall.vision.context import (
    PROTOCOL_VERSION,
    ExplainVisualContextRequest,
    ExplainVisualContextResponse,
    RemoteAuthorizationMode,
    VisualContextSelector,
    VisualContextService,
)

_MAX_PAYLOAD_BYTES = 32 * 1024
_ROUTING_KEYS = frozenset(
    {
        "protocol_version",
        "visual_context_version",
        "request_id",
        "remote_authorization",
    }
)
_PAYLOAD_KEYS = frozenset(
    {
        "selector",
        "start",
        "end",
        "maximum_records",
        "deadline",
    }
)


@dataclass(frozen=True, slots=True, repr=False)
class VisualContextRequestCodec:
    """Authenticate and bound one visual-context request over the owner IPC."""

    token: SessionToken
    capabilities: frozenset[IpcCapability]

    def encode(self, request: ExplainVisualContextRequest) -> tuple[bytes, bytes, bytes]:
        routing = json.dumps(
            {
                "protocol_version": IPC_PROTOCOL_VERSION,
                "visual_context_version": request.protocol_version,
                "request_id": request.request_id,
                "remote_authorization": request.remote_authorization.value,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        payload = json.dumps(
            {
                "selector": request.selector.value,
                "start": request.start.isoformat() if request.start else None,
                "end": request.end.isoformat() if request.end else None,
                "maximum_records": request.maximum_records,
                "deadline": request.deadline.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(routing) > MAX_ROUTING_BYTES:
            raise IpcProtocolError("routing-too-large")
        if len(payload) > _MAX_PAYLOAD_BYTES:
            raise IpcProtocolError("payload-too-large")
        return routing, self.token.frame(), payload

    def decode(self, frames: tuple[bytes, ...], *, now: datetime) -> ExplainVisualContextRequest:
        if len(frames) != 3:
            raise IpcProtocolError("frame-count")
        routing_frame, authentication_frame, payload_frame = frames
        if len(routing_frame) > MAX_ROUTING_BYTES or len(payload_frame) > _MAX_PAYLOAD_BYTES:
            raise IpcProtocolError("payload-too-large")
        if not self.token.matches(authentication_frame):
            raise IpcProtocolError("unauthorized")
        routing = _decode_object(routing_frame, _ROUTING_KEYS)
        payload = _decode_object(payload_frame, _PAYLOAD_KEYS)
        if routing["protocol_version"] != IPC_PROTOCOL_VERSION:
            raise IpcProtocolError("protocol-version")
        if routing["visual_context_version"] != PROTOCOL_VERSION:
            raise IpcProtocolError("unsupported-visual-context-version")
        request_id = _required_id(cast(str, routing["request_id"]))
        try:
            request = ExplainVisualContextRequest(
                protocol_version=PROTOCOL_VERSION,
                request_id=request_id,
                selector=VisualContextSelector(cast(str, payload["selector"])),
                start=_optional_time(payload["start"]),
                end=_optional_time(payload["end"]),
                maximum_records=cast(int, payload["maximum_records"]),
                deadline=_required_time(cast(str, payload["deadline"])),
                remote_authorization=RemoteAuthorizationMode(
                    cast(str, routing["remote_authorization"])
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise IpcProtocolError("invalid-payload") from exc
        if now >= request.deadline:
            raise IpcProtocolError("deadline-expired")
        return request


class VisualContextIpcHandler:
    """Bind the typed service to the owner-only request frames."""

    def __init__(
        self,
        *,
        service: VisualContextService,
        codec: VisualContextRequestCodec,
    ) -> None:
        self._service = service
        self._codec = codec

    async def handle_async(
        self, frames: tuple[bytes, ...], *, now: datetime
    ) -> ExplainVisualContextResponse:
        request = self._codec.decode(frames, now=now)
        response = await self._service.explain(request)
        return response

    def handle(self, frames: tuple[bytes, ...], *, now: datetime) -> ExplainVisualContextResponse:
        import asyncio

        return asyncio.run(self.handle_async(frames, now=now))


def _decode_object(raw: bytes, expected: frozenset[str]) -> dict[str, object]:
    try:
        loaded: object = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IpcProtocolError("invalid-payload") from exc
    if not isinstance(loaded, dict) or frozenset(cast("dict[object, object]", loaded)) != expected:
        raise IpcProtocolError("invalid-payload")
    return cast("dict[str, object]", loaded)


def _required_id(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise IpcProtocolError("invalid-payload")
    return value


def _required_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise IpcProtocolError("invalid-payload") from exc
    return parsed


def _optional_time(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise IpcProtocolError("invalid-payload")
    return _required_time(value)
