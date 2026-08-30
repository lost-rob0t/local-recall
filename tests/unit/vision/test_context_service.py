from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from local_recall.audit import AuditRecorder
from local_recall.audit.models import AuditEvent
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration, CaptureState, CaptureStateSnapshot
from local_recall.domain.metadata import ContextMetadata
from local_recall.routing import EgressGate
from local_recall.vision.context import (
    PROTOCOL_VERSION,
    ExplainVisualContextRequest,
    RemoteAuthorizationMode,
    VisualContextOutcome,
    VisualContextSelector,
    VisualContextService,
)
from local_recall.vision.service import VisionAnalysis

_NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
_REQUEST_ID = "c0ffee00-0000-4000-8000-00000000aa01"


def _request(**overrides: object) -> ExplainVisualContextRequest:
    base: dict[str, object] = {
        "protocol_version": PROTOCOL_VERSION,
        "selector": VisualContextSelector.RECENT,
        "deadline": _NOW + timedelta(seconds=5),
    }
    base.update(overrides)
    return ExplainVisualContextRequest(request_id=_REQUEST_ID, **base)  # type: ignore[arg-type]


def _snapshot(state: CaptureState = CaptureState.RECORDING) -> CaptureStateSnapshot:
    return CaptureStateSnapshot(
        state=state,
        generation=CaptureGeneration(1),
        observed_at=_NOW,
        privacy_mode=False,
        critical_dependencies_healthy=True,
    )


@dataclass
class LifecyclePort:
    snapshot: CaptureStateSnapshot = field(default_factory=lambda: _snapshot())
    locked: bool = False

    def observe(self) -> CaptureStateSnapshot:
        return self.snapshot

    def session_locked(self) -> bool:
        return self.locked


@dataclass
class PolicyPort:
    allowed: bool = True
    remote_eligible: bool = False
    policy_revision: str = "query-policy-v1"

    async def authorize_query(self, query: object) -> object:
        from local_recall.retrieval.service import RetrievalPolicyDecision

        return RetrievalPolicyDecision(
            self.allowed, self.remote_eligible, self.policy_revision, "ok"
        )


@dataclass
class WorkingSetPort:
    records: tuple[RedactedRecord, ...] = ()

    async def select(self, selector: object, start: object, end: object, limit: int) -> tuple:
        del selector, start, end
        return self.records[:limit]


@dataclass
class VisionPort:
    uncertainty: float = 0.2
    calls: int = 0
    fail: bool = False

    async def enrich(
        self, record: RedactedRecord, *, egress_authorization: object = None
    ) -> VisionAnalysis:
        self.calls += 1
        if self.fail:
            raise RuntimeError("synthetic-vision-failure")
        return VisionAnalysis(
            record_id=record.record_id,
            provider_id="local-vision",
            model_version="vision-v1",
            visible_application_state="emacs with a document open",
            document_type="text document",
            broad_task="editing",
            uncertainty=self.uncertainty,
        )


@dataclass
class MemoryAuditSink:
    events: list[AuditEvent] = field(default_factory=list[AuditEvent])

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


def _record(index: int = 1) -> RedactedRecord:
    captured = _NOW - timedelta(minutes=5 * index)
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


def _service(
    *,
    records: tuple[RedactedRecord, ...] = (_record(),),
    lifecycle: LifecyclePort | None = None,
    policy: PolicyPort | None = None,
    vision: VisionPort | None = None,
    egress_gate: EgressGate | None = None,
    audit_sink: MemoryAuditSink | None = None,
) -> tuple[VisualContextService, MemoryAuditSink]:
    sink = audit_sink or MemoryAuditSink()
    service = VisualContextService(
        lifecycle=lifecycle or LifecyclePort(),
        policy=policy or PolicyPort(),
        working_set=WorkingSetPort(records=records),
        vision=vision or VisionPort(),
        egress_gate=egress_gate,
        audit=AuditRecorder(sink),
        now=lambda: _NOW,
    )
    return service, sink


def test_explained_response_from_local_provider() -> None:
    service, sink = _service()
    response = asyncio.run(service.explain(_request()))
    assert response.outcome is VisualContextOutcome.EXPLAINED
    assert response.explanation
    assert response.record_count == 1
    assert response.provider_class == "local"
    assert response.reason_code is None
    assert len(sink.events) >= 2


def test_privacy_mode_denies() -> None:
    lifecycle = LifecyclePort(snapshot=_snapshot(CaptureState.PRIVACY))
    service, _sink = _service(lifecycle=lifecycle)
    response = asyncio.run(service.explain(_request()))
    assert response.outcome is VisualContextOutcome.DENIED
    assert response.reason_code == "privacy-mode"
    assert response.explanation is None


def test_session_lock_denies() -> None:
    lifecycle = LifecyclePort(locked=True)
    service, _sink = _service(lifecycle=lifecycle)
    response = asyncio.run(service.explain(_request()))
    assert response.outcome is VisualContextOutcome.DENIED
    assert response.reason_code == "session-locked"


def test_capture_off_denies() -> None:
    lifecycle = LifecyclePort(snapshot=_snapshot(CaptureState.OFF))
    service, _sink = _service(lifecycle=lifecycle)
    response = asyncio.run(service.explain(_request()))
    assert response.outcome is VisualContextOutcome.DENIED
    assert response.reason_code == "capture-not-active"


def test_query_policy_denial() -> None:
    policy = PolicyPort(allowed=False)
    service, _sink = _service(policy=policy)
    response = asyncio.run(service.explain(_request()))
    assert response.outcome is VisualContextOutcome.DENIED
    assert response.reason_code == "query-policy-denied"


def test_missing_context_denies() -> None:
    service, _sink = _service(records=())
    response = asyncio.run(service.explain(_request()))
    assert response.outcome is VisualContextOutcome.DENIED
    assert response.reason_code == "missing-context"
    assert response.record_count == 0


def test_expired_deadline_denies() -> None:
    service, _sink = _service()
    response = asyncio.run(service.explain(_request(deadline=_NOW - timedelta(seconds=1))))
    assert response.outcome is VisualContextOutcome.DENIED
    assert response.reason_code == "deadline-expired"


def test_cancelled_request_denies() -> None:
    service, _sink = _service()
    service.cancel(_REQUEST_ID)
    response = asyncio.run(service.explain(_request()))
    assert response.outcome is VisualContextOutcome.DENIED
    assert response.reason_code == "cancelled"


def test_remote_without_explicit_authorization_is_denied() -> None:
    records = (_record(),)
    service, _sink = _service(records=records)
    response = asyncio.run(
        service.explain(_request(remote_authorization=RemoteAuthorizationMode.EXPLICIT))
    )
    assert response.outcome is VisualContextOutcome.DENIED
    assert response.reason_code == "remote-not-authorized"
    assert response.provider_class is None


def test_local_provider_failure_is_unavailable() -> None:
    vision = VisionPort(fail=True)
    service, _sink = _service(vision=vision)
    response = asyncio.run(service.explain(_request()))
    assert response.outcome is VisualContextOutcome.UNAVAILABLE
    assert response.reason_code == "vision-failed"


def test_no_records_beyond_maximum_are_selected() -> None:
    records = tuple(_record(index) for index in range(1, 6))
    service, _sink = _service(records=records)
    response = asyncio.run(service.explain(_request(maximum_records=2)))
    assert response.record_count == 2
    assert response.selected_start is not None
    assert response.selected_end is not None
