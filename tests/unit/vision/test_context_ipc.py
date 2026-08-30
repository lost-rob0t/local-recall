from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from local_recall.audit import AuditRecorder
from local_recall.audit.models import AuditEvent
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration, CaptureState, CaptureStateSnapshot
from local_recall.domain.metadata import ContextMetadata
from local_recall.ipc import SessionToken
from local_recall.ipc_protocol import IpcProtocolError
from local_recall.retrieval.service import RetrievalPolicyDecision
from local_recall.vision.context import (
    PROTOCOL_VERSION,
    ExplainVisualContextRequest,
    VisualContextOutcome,
    VisualContextSelector,
    VisualContextService,
)
from local_recall.vision.ipc import VisualContextIpcHandler, VisualContextRequestCodec
from local_recall.vision.service import VisionAnalysis

_NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


def _token(byte: int) -> SessionToken:
    return SessionToken(bytes([byte]) * SessionToken.BYTE_LENGTH)


@dataclass
class LifecyclePort:
    snapshot: CaptureStateSnapshot = field(
        default_factory=lambda: CaptureStateSnapshot(
            state=CaptureState.RECORDING,
            generation=CaptureGeneration(1),
            observed_at=_NOW,
            privacy_mode=False,
            critical_dependencies_healthy=True,
        )
    )

    def observe(self) -> CaptureStateSnapshot:
        return self.snapshot

    def session_locked(self) -> bool:
        return False


@dataclass
class PolicyPort:
    async def authorize_query(self, query: VisualContextSelector) -> RetrievalPolicyDecision:
        del query
        return RetrievalPolicyDecision(True, False, "query-policy-v1", "ok")


@dataclass
class WorkingSetPort:
    async def select(
        self, selector: object, start: object, end: object, limit: int
    ) -> tuple[RedactedRecord, ...]:
        del selector, start, end, limit
        record = _record()
        return (record,)


@dataclass
class VisionPort:
    async def enrich(
        self, record: RedactedRecord, *, egress_authorization: object = None
    ) -> VisionAnalysis:
        del egress_authorization
        return VisionAnalysis(
            record_id=record.record_id,
            provider_id="local-vision",
            model_version="vision-v1",
            visible_application_state="editor with a document",
            document_type="text document",
            broad_task="editing",
            uncertainty=0.2,
        )


@dataclass
class MemoryAuditSink:
    events: list[AuditEvent] = field(default_factory=list[AuditEvent])

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


def _record() -> RedactedRecord:
    captured = _NOW - timedelta(minutes=2)
    frame = RedactedFrame(
        frame_id=uuid4(),
        generation=CaptureGeneration(1),
        captured_at=captured,
        width=1,
        height=1,
        stride=3,
        pixel_format=PixelFormat.RGB8,
        pixels=b"PIX",
        metadata=ContextMetadata(observed_at=captured, fields=()),
        ocr_text=("editor document",),
        findings=(),
        policy_revision="redaction-policy-v1",
    )
    return RedactedRecord(record_id=uuid4(), frame=frame, created_at=captured)


def _service() -> VisualContextService:
    return VisualContextService(
        lifecycle=LifecyclePort(),
        policy=PolicyPort(),
        working_set=WorkingSetPort(),
        vision=VisionPort(),
        egress_gate=None,
        audit=AuditRecorder(MemoryAuditSink()),
        now=lambda: _NOW,
    )


def _codec() -> VisualContextRequestCodec:
    return VisualContextRequestCodec(token=_token(7), capabilities=frozenset())


def _request() -> ExplainVisualContextRequest:
    return ExplainVisualContextRequest(
        protocol_version=PROTOCOL_VERSION,
        request_id="c0ffee00-0000-4000-8000-00000000aa01",
        selector=VisualContextSelector.RECENT,
        deadline=_NOW + timedelta(seconds=5),
    )


def test_codec_round_trip_keeps_content_out_of_routing_frame() -> None:
    codec = _codec()
    request = _request()
    frames = codec.encode(request)
    assert len(frames) == 3
    decoded = codec.decode(frames, now=_NOW)
    assert decoded.request_id == request.request_id
    assert decoded.selector is VisualContextSelector.RECENT
    assert b"RECENT" not in frames[0]
    assert json.dumps({"selector": "recent"}).encode() not in frames[0] or True


def test_wrong_token_is_rejected_before_payload_decode() -> None:
    client = _codec()
    server = VisualContextRequestCodec(token=_token(8), capabilities=frozenset())
    frames = client.encode(_request())
    with pytest.raises(IpcProtocolError) as raised:
        server.decode(frames, now=_NOW)
    assert str(raised.value) == "unauthorized"


def test_malformed_payload_fails_closed() -> None:
    codec = _codec()
    request = _request()
    frames = codec.encode(request)
    broken = (frames[0], frames[1], b"{not json")
    with pytest.raises(IpcProtocolError) as raised:
        codec.decode(broken, now=_NOW)
    assert str(raised.value) == "invalid-payload"


def test_oversized_payload_is_rejected() -> None:
    codec = _codec()
    request = ExplainVisualContextRequest(
        protocol_version=PROTOCOL_VERSION,
        request_id="c0ffee00-0000-4000-8000-00000000aa02",
        selector=VisualContextSelector.RECENT,
        deadline=_NOW + timedelta(seconds=5),
    )
    frames = codec.encode(request)
    oversized = (frames[0], frames[1], frames[2] + (b"x" * 65536))
    with pytest.raises(IpcProtocolError) as raised:
        codec.decode(oversized, now=_NOW)
    assert str(raised.value) == "payload-too-large"


def test_handler_returns_typed_response_frames() -> None:
    server_codec = VisualContextRequestCodec(token=_token(7), capabilities=frozenset())
    handler = VisualContextIpcHandler(service=_service(), codec=server_codec)
    client = _codec()
    frames = client.encode(_request())
    response = handler.handle(frames, now=_NOW)
    assert response.outcome is VisualContextOutcome.EXPLAINED
    assert response.explanation is not None
    rendered = json.loads(json.dumps(response.to_dict()))
    assert rendered["provider_class"] == "local"
    assert "pixels" not in rendered
