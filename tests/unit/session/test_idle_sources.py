from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.metadata.activitywatch import ActivityWatchMetadataSource
from local_recall.session.idle import (
    ActivityWatchIdleStateSource,
    IdleCommandResult,
    XorgIdleStateSource,
)
from local_recall.session.safety import (
    IdleState,
    SafetyObservationRequest,
    SessionSafetyFailureCode,
)

NOW = datetime(2026, 8, 12, 19, 30, tzinfo=UTC)


@dataclass
class FakeIdleRunner:
    result: IdleCommandResult | None
    available: bool = True

    async def run(
        self,
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> IdleCommandResult:
        assert timeout_seconds > 0
        assert max_output_bytes == 128
        if self.result is None:
            raise RuntimeError("FAKE_TOKEN_123 alice@example.test")
        return self.result


class FakeActivityWatch:
    def __init__(self, value: bool | None, seconds: float | None = None) -> None:
        self.value = value
        self.seconds = seconds

    async def collect(self, request: object) -> ContextMetadata:
        del request
        if self.value is None:
            raise RuntimeError("FAKE_TOKEN_123 sensitive.example")
        provenance = MetadataProvenance(
            source_id="activitywatch",
            observed_at=NOW,
            confidence=SourceConfidence(0.98),
            adapter_revision="activitywatch-v1",
        )
        fields = [ContextField(name="idle", value=self.value, provenance=(provenance,))]
        if self.seconds is not None:
            fields.append(
                ContextField(
                    name="idle.seconds",
                    value=self.seconds,
                    provenance=(provenance,),
                )
            )
        return ContextMetadata(observed_at=NOW, fields=tuple(fields))


def request() -> SafetyObservationRequest:
    return SafetyObservationRequest(
        generation=CaptureGeneration(1),
        deadline_monotonic_ns=time.monotonic_ns() + 2_000_000_000,
    )


def test_xorg_idle_fallback_returns_bounded_duration() -> None:
    source = XorgIdleStateSource(
        runner=FakeIdleRunner(IdleCommandResult(0, b"180000\n")),
        now=lambda: NOW,
    )

    observation = asyncio.run(source.observe(request()))

    assert observation.state is IdleState.IDLE
    assert observation.idle_seconds == 180.0
    assert observation.source_id == "xorg-idle"


def test_xorg_idle_fallback_rejects_malformed_and_overflow_values() -> None:
    for payload in (b"-1\n", b"999999999999999999999\n", b"secret\n"):
        source = XorgIdleStateSource(
            runner=FakeIdleRunner(IdleCommandResult(0, payload)),
            now=lambda: NOW,
        )

        observation = asyncio.run(source.observe(request()))

        assert observation.state is IdleState.UNKNOWN
        assert observation.failure_code is SessionSafetyFailureCode.MALFORMED


def test_xorg_idle_fallback_failure_is_sanitized() -> None:
    source = XorgIdleStateSource(runner=FakeIdleRunner(None), now=lambda: NOW)

    observation = asyncio.run(source.observe(request()))

    rendered = repr(observation)
    assert observation.state is IdleState.UNKNOWN
    assert observation.failure_code is SessionSafetyFailureCode.UNAVAILABLE
    assert "FAKE_TOKEN_123" not in rendered
    assert "alice@example.test" not in rendered


def test_activitywatch_idle_source_consumes_only_normalized_idle_field() -> None:
    for raw, expected in ((True, IdleState.IDLE), (False, IdleState.ACTIVE)):
        source = ActivityWatchIdleStateSource(
            cast(ActivityWatchMetadataSource, FakeActivityWatch(raw)),
            now=lambda: NOW,
        )

        observation = asyncio.run(source.observe(request()))

        assert observation.state is expected
        assert observation.idle_seconds is None
        assert observation.source_id == "activitywatch"


def test_activitywatch_idle_duration_is_available_for_local_thresholding() -> None:
    source = ActivityWatchIdleStateSource(
        cast(ActivityWatchMetadataSource, FakeActivityWatch(True, 179.5)),
        now=lambda: NOW,
    )

    observation = asyncio.run(source.observe(request()))

    assert observation.state is IdleState.IDLE
    assert observation.idle_seconds == 179.5


def test_activitywatch_failure_does_not_expose_raw_exception() -> None:
    source = ActivityWatchIdleStateSource(
        cast(ActivityWatchMetadataSource, FakeActivityWatch(None)),
        now=lambda: NOW,
    )

    observation = asyncio.run(source.observe(request()))

    assert observation.state is IdleState.UNKNOWN
    assert observation.failure_code is SessionSafetyFailureCode.UNAVAILABLE
    assert "FAKE_TOKEN_123" not in repr(observation)
    assert "sensitive.example" not in repr(observation)
