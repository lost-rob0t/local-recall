from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID

import pytest

from local_recall.capture.adaptive import AdaptiveCaptureController, FrameDisposition
from local_recall.capture.flow import AdaptiveCaptureFlow, AdaptiveCaptureOutcome
from local_recall.domain.capture import ApprovedCaptureRequest, CaptureAuthorization, CaptureIntent
from local_recall.domain.frames import PixelFormat, RawFrame
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)

_NOW = datetime(2026, 8, 22, tzinfo=UTC)


def _generation(value: int = 1) -> CaptureGeneration:
    return CaptureGeneration(value)


def _metadata(*, application: str = "editor", workspace: str = "1") -> ContextMetadata:
    provenance = (
        MetadataProvenance(
            source_id="qtile",
            observed_at=_NOW,
            confidence=SourceConfidence(1.0),
            adapter_revision="test-v1",
        ),
    )
    return ContextMetadata(
        observed_at=_NOW,
        fields=(
            ContextField("application", application, provenance),
            ContextField("workspace", workspace, provenance),
            ContextField("window.id", "42", provenance),
        ),
    )


def _request(*, generation: int = 1, policy_revision: str = "policy-a") -> ApprovedCaptureRequest:
    return ApprovedCaptureRequest(
        intent=CaptureIntent(
            job_id=UUID(int=1),
            generation=_generation(generation),
            requested_at=_NOW,
            deadline_monotonic_ns=10_000_000_000,
            configuration_revision="config-a",
        ),
        metadata=_metadata(),
        authorization=CaptureAuthorization(
            decision_id=UUID(int=2),
            policy_revision=policy_revision,
            allowed_metadata_fields=frozenset({"application", "workspace", "window.id"}),
        ),
    )


def _frame(*, generation: int = 1, value: int = 20) -> RawFrame:
    pixels = bytes((value, value, value)) * 81
    return RawFrame(
        frame_id=UUID(int=value + 10),
        generation=_generation(generation),
        captured_at=_NOW,
        width=9,
        height=9,
        stride=27,
        pixel_format=PixelFormat.RGB8,
        pixels=pixels,
        metadata=_metadata(),
    )


class _Backend:
    def __init__(self, frames: list[RawFrame]) -> None:
        self.frames = frames
        self.calls = 0

    async def capture(self, request: ApprovedCaptureRequest) -> RawFrame:
        del request
        self.calls += 1
        return self.frames.pop(0)


def _flow(backend: _Backend) -> AdaptiveCaptureFlow:
    return AdaptiveCaptureFlow(
        backend=backend,
        controller=AdaptiveCaptureController(
            cadence_seconds=1.0,
            change_threshold=0.0,
            debounce_seconds=0.0,
        ),
    )


def test_duplicate_frame_is_coalesced_before_downstream_admission() -> None:
    backend = _Backend([_frame(), _frame()])
    flow = _flow(backend)
    request = _request()

    first = asyncio.run(flow.capture_if_due(request=request, now_monotonic_ns=1_000_000_000))
    second = asyncio.run(flow.capture_if_due(request=request, now_monotonic_ns=2_000_000_000))

    assert first.outcome is AdaptiveCaptureOutcome.ADMIT
    assert first.frame is not None
    assert first.frame_decision.disposition is FrameDisposition.ACCEPT
    assert second.outcome is AdaptiveCaptureOutcome.COALESCE
    assert second.frame is None
    assert second.frame_decision.disposition is FrameDisposition.COALESCE
    assert backend.calls == 2


def test_privacy_revision_change_never_reuses_duplicate_state() -> None:
    backend = _Backend([_frame(), _frame()])
    flow = _flow(backend)

    first = asyncio.run(
        flow.capture_if_due(
            request=_request(policy_revision="policy-a"),
            now_monotonic_ns=1_000_000_000,
        )
    )
    second = asyncio.run(
        flow.capture_if_due(
            request=_request(policy_revision="policy-b"),
            now_monotonic_ns=2_000_000_000,
        )
    )

    assert first.outcome is AdaptiveCaptureOutcome.ADMIT
    assert second.outcome is AdaptiveCaptureOutcome.ADMIT
    assert second.frame is not None


def test_stale_backend_frame_is_rejected_before_dedup_state_changes() -> None:
    backend = _Backend([_frame(generation=1)])
    flow = _flow(backend)

    with pytest.raises(ValueError, match="generation"):
        asyncio.run(
            flow.capture_if_due(
                request=_request(generation=2),
                now_monotonic_ns=1_000_000_000,
            )
        )


def test_not_due_does_not_invoke_capture_backend() -> None:
    backend = _Backend([_frame(), _frame()])
    flow = AdaptiveCaptureFlow(
        backend=backend,
        controller=AdaptiveCaptureController(
            cadence_seconds=60.0,
            change_threshold=0.0,
            debounce_seconds=1.0,
        ),
    )
    request = _request()

    first = asyncio.run(flow.capture_if_due(request=request, now_monotonic_ns=1_000_000_000))
    second = asyncio.run(flow.capture_if_due(request=request, now_monotonic_ns=2_000_000_000))

    assert first.outcome is AdaptiveCaptureOutcome.ADMIT
    assert second.outcome is AdaptiveCaptureOutcome.SKIP
    assert second.frame is None
    assert backend.calls == 1
