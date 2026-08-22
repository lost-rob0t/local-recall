from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

import pytest

import local_recall.capture.xorg as xorg_capture
import local_recall.domain.capture as capture_domain
import local_recall.domain.frames as frame_domain
import local_recall.domain.lifecycle as lifecycle_domain
import local_recall.domain.metadata as metadata_domain

NOW = datetime(2026, 8, 22, 6, 0, tzinfo=UTC)


@dataclass
class FakeReader:
    snapshot: xorg_capture.XorgSnapshot | None = None
    error: xorg_capture.XorgCaptureError | None = None
    calls: int = 0

    async def capture_root(self, *, deadline_monotonic_ns: int) -> xorg_capture.XorgSnapshot:
        assert deadline_monotonic_ns > 0
        self.calls += 1
        if self.error is not None:
            raise self.error
        assert self.snapshot is not None
        return self.snapshot


def _request(
    *, metadata: metadata_domain.ContextMetadata | None = None, deadline: int = 9_000_000_000
) -> capture_domain.ApprovedCaptureRequest:
    intent = capture_domain.CaptureIntent(
        job_id=uuid4(),
        generation=lifecycle_domain.CaptureGeneration(7),
        requested_at=NOW,
        deadline_monotonic_ns=deadline,
        configuration_revision="config-v1",
    )
    decision = capture_domain.CaptureDecision.allow(
        policy_revision="policy-v4",
        allowed_metadata_fields=frozenset(
            {"window.x", "window.y", "window.width", "window.height"}
        ),
    )
    return capture_domain.ApprovedCaptureRequest.from_decision(
        intent=intent,
        metadata=metadata or metadata_domain.ContextMetadata(observed_at=NOW, fields=()),
        decision=decision,
    )


def _snapshot() -> xorg_capture.XorgSnapshot:
    return xorg_capture.XorgSnapshot(
        captured_at=NOW,
        root_x=-2,
        root_y=0,
        width=4,
        height=2,
        stride=12,
        pixel_format=frame_domain.PixelFormat.RGB8,
        pixels=bytes(range(24)),
        monitors=(
            xorg_capture.XorgSnapshot.Monitor(
                monitor_id="left",
                x=-2,
                y=0,
                width=2,
                height=2,
                scale_x=1.0,
                scale_y=1.0,
            ),
            xorg_capture.XorgSnapshot.Monitor(
                monitor_id="right",
                x=0,
                y=0,
                width=2,
                height=2,
                scale_x=1.5,
                scale_y=1.5,
            ),
        ),
        backend_revision="xlib-root-v1",
    )


def _window_metadata(*, source_id: str = "xorg-generic") -> metadata_domain.ContextMetadata:
    provenance = (
        metadata_domain.MetadataProvenance(
            source_id=source_id,
            observed_at=NOW,
            confidence=metadata_domain.SourceConfidence(0.99),
            adapter_revision="fixture-v1",
        ),
    )
    return metadata_domain.ContextMetadata(
        observed_at=NOW,
        fields=(
            metadata_domain.ContextField(name="window.x", value=0, provenance=provenance),
            metadata_domain.ContextField(name="window.y", value=0, provenance=provenance),
            metadata_domain.ContextField(name="window.width", value=2, provenance=provenance),
            metadata_domain.ContextField(name="window.height", value=2, provenance=provenance),
        ),
    )


def test_full_desktop_capture_preserves_generation_and_monitor_provenance() -> None:
    reader = FakeReader(snapshot=_snapshot())
    backend = xorg_capture.XorgCaptureBackend(reader=reader, monotonic_ns=lambda: 1_000_000_000)

    frame = asyncio.run(backend.capture(_request()))

    assert reader.calls == 1
    assert frame.generation == lifecycle_domain.CaptureGeneration(7)
    assert frame.width == 4
    assert frame.height == 2
    assert frame.pixels == bytes(range(24))
    assert frame.capture_provenance is not None
    assert frame.capture_provenance.backend_id == "xorg"
    assert frame.capture_provenance.backend_revision == "xlib-root-v1"
    assert [(m.x, m.width, m.scale_x) for m in frame.capture_provenance.monitors] == [
        (-2, 2, 1.0),
        (0, 2, 1.5),
    ]


def test_validated_window_geometry_crops_only_after_root_capture() -> None:
    reader = FakeReader(snapshot=_snapshot())
    backend = xorg_capture.XorgCaptureBackend(reader=reader, monotonic_ns=lambda: 1_000_000_000)

    frame = asyncio.run(backend.capture(_request(metadata=_window_metadata())))

    assert reader.calls == 1
    assert (frame.width, frame.height, frame.stride) == (2, 2, 6)
    assert frame.pixels == bytes([6, 7, 8, 9, 10, 11, 18, 19, 20, 21, 22, 23])
    assert frame.capture_provenance is not None
    assert frame.capture_provenance.region.x == 0
    assert frame.capture_provenance.region.width == 2


def test_untrusted_window_geometry_falls_back_to_full_desktop() -> None:
    reader = FakeReader(snapshot=_snapshot())
    backend = xorg_capture.XorgCaptureBackend(reader=reader, monotonic_ns=lambda: 1_000_000_000)

    frame = asyncio.run(
        backend.capture(_request(metadata=_window_metadata(source_id="unknown-source")))
    )

    assert (frame.width, frame.height) == (4, 2)
    assert frame.pixels == bytes(range(24))


def test_expired_deadline_fails_before_reader_is_invoked() -> None:
    reader = FakeReader(snapshot=_snapshot())
    backend = xorg_capture.XorgCaptureBackend(reader=reader, monotonic_ns=lambda: 10_000_000_000)

    with pytest.raises(xorg_capture.XorgCaptureError, match="capture-deadline-expired"):
        asyncio.run(backend.capture(_request(deadline=9_000_000_000)))

    assert reader.calls == 0


def test_reader_failure_is_sanitized() -> None:
    private_value = "DISPLAY=:77 secret-window-title"
    reader = FakeReader(
        error=xorg_capture.XorgCaptureError("capture-failed", private_detail=private_value)
    )
    backend = xorg_capture.XorgCaptureBackend(reader=reader, monotonic_ns=lambda: 1_000_000_000)

    with pytest.raises(xorg_capture.XorgCaptureError) as caught:
        asyncio.run(backend.capture(_request()))

    rendered = f"{caught.value!r} {caught.value}"
    assert "capture-failed" in rendered
    assert private_value not in rendered


def test_capture_backend_rejects_unapproved_request_at_runtime() -> None:
    backend = xorg_capture.XorgCaptureBackend(
        reader=FakeReader(snapshot=_snapshot()), monotonic_ns=lambda: 1
    )
    intent = capture_domain.CaptureIntent(
        job_id=uuid4(),
        generation=lifecycle_domain.CaptureGeneration(1),
        requested_at=NOW,
        deadline_monotonic_ns=2,
        configuration_revision="config-v1",
    )

    with pytest.raises(TypeError, match="approved capture request required"):
        backend.validate_request(cast(capture_domain.ApprovedCaptureRequest, intent))
