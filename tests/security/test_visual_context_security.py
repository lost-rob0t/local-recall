from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from local_recall.audit import AuditRecorder
from local_recall.audit.models import AuditEvent
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration, CaptureState, CaptureStateSnapshot
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.retrieval.service import RetrievalPolicyDecision
from local_recall.routing import EgressGate
from local_recall.vision.context import (
    PROTOCOL_VERSION,
    ExplainVisualContextRequest,
    VisualContextOutcome,
    VisualContextSelector,
    VisualContextService,
)
from local_recall.vision.service import VisionAnalysis

_NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
_SEEDED_TITLE = "SecretWindowTitle-9f2"
_SEEDED_CANARY = "sk-live-zara-leak-check"
_SEEDED_COMMAND = "curl -x evil.example.internal"
_SEEDED_USER = "alice.dev"
_SEEDED_PROMPT = "provider-prompt-marker-1f3"
_LEAK_MARKERS = (
    _SEEDED_TITLE,
    _SEEDED_CANARY,
    _SEEDED_COMMAND,
    _SEEDED_USER,
    _SEEDED_PROMPT,
)


@dataclass
class LifecyclePort:
    started: int = 0
    resumed: int = 0

    def observe(self) -> CaptureStateSnapshot:
        return CaptureStateSnapshot(
            state=CaptureState.RECORDING,
            generation=CaptureGeneration(1),
            observed_at=_NOW,
            privacy_mode=False,
            critical_dependencies_healthy=True,
        )

    def session_locked(self) -> bool:
        return False

    def start_capture(self) -> None:
        self.started += 1

    def resume_capture(self) -> None:
        self.resumed += 1


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
        record = _record_with_seeded_content()
        return (record,)


@dataclass
class VisionPort:
    prompts: list[str] = field(default_factory=list[str])

    async def enrich(
        self, record: RedactedRecord, *, egress_authorization: object = None
    ) -> VisionAnalysis:
        self.prompts.append(_SEEDED_PROMPT)
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


def _record_with_seeded_content() -> RedactedRecord:
    captured = _NOW - timedelta(minutes=2)
    provenance = (
        MetadataProvenance(
            source_id="synthetic-desktop",
            observed_at=captured,
            confidence=SourceConfidence(1.0),
            adapter_revision="zara-v1",
        ),
    )
    frame = RedactedFrame(
        frame_id=uuid4(),
        generation=CaptureGeneration(1),
        captured_at=captured,
        width=1,
        height=1,
        stride=3,
        pixel_format=PixelFormat.RGB8,
        pixels=b"PIX",
        metadata=ContextMetadata(
            observed_at=captured,
            fields=(
                ContextField("window.title", _SEEDED_TITLE, provenance),
                ContextField("command.line", _SEEDED_COMMAND, provenance),
                ContextField("user.name", _SEEDED_USER, provenance),
            ),
        ),
        ocr_text=(f"{_SEEDED_TITLE} {_SEEDED_CANARY} {_SEEDED_COMMAND}",),
        findings=(),
        policy_revision="redaction-policy-v1",
    )
    return RedactedRecord(record_id=uuid4(), frame=frame, created_at=captured)


def _service() -> tuple[VisualContextService, MemoryAuditSink, LifecyclePort]:
    lifecycle = LifecyclePort()
    sink = MemoryAuditSink()
    service = VisualContextService(
        lifecycle=lifecycle,
        policy=PolicyPort(),
        working_set=WorkingSetPort(),
        vision=VisionPort(),
        egress_gate=EgressGate(),
        audit=AuditRecorder(sink),
        now=lambda: _NOW,
    )
    return service, sink, lifecycle


def _request() -> ExplainVisualContextRequest:
    return ExplainVisualContextRequest(
        protocol_version=PROTOCOL_VERSION,
        request_id="c0ffee00-0000-4000-8000-00000000aa01",
        selector=VisualContextSelector.RECENT,
        deadline=_NOW + timedelta(seconds=5),
    )


def test_explanation_and_audit_never_leak_seeded_content() -> None:
    service, sink, _lifecycle = _service()
    response = asyncio.run(service.explain(_request()))

    rendered = json.dumps(response.to_dict())
    for marker in _LEAK_MARKERS:
        assert marker not in rendered
        for event in sink.events:
            assert marker not in repr(event)

    assert response.outcome is VisualContextOutcome.EXPLAINED


def test_explain_query_cannot_start_or_resume_capture() -> None:
    service, _sink, lifecycle = _service()
    before_started = lifecycle.started
    before_resumed = lifecycle.resumed

    asyncio.run(service.explain(_request()))
    denied = asyncio.run(service.explain(_request()))

    assert denied.outcome is VisualContextOutcome.DENIED or denied.outcome is (
        VisualContextOutcome.EXPLAINED
    )
    assert lifecycle.started == before_started
    assert lifecycle.resumed == before_resumed


def test_debug_mode_cannot_expose_visual_content() -> None:
    service, sink, _lifecycle = _service()
    response = asyncio.run(service.explain(_request(), debug=True))
    rendered = json.dumps(response.to_dict())
    for marker in _LEAK_MARKERS:
        assert marker not in rendered
    for event in sink.events:
        for marker in _LEAK_MARKERS:
            assert marker not in repr(event)
