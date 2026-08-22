from __future__ import annotations

import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from uuid import UUID

import pykka
import zmq

from local_recall.capture.adaptive import AdaptiveCaptureController
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.lifecycle.actor import LifecycleActor
from local_recall.lifecycle.errors import StaleCaptureGeneration
from local_recall.lifecycle.gate import CaptureGate
from local_recall.lifecycle.messages import FaultCapture, LifecycleFaultCode

from .actors import DrainStage, PipelineStageActor, StageMetrics, StageStatus
from .cancellation import CancellationRegistry
from .credits import CreditLedger
from .ingress import PipelineIngress
from .models import (
    PipelineFaultEvent,
    PipelineLimits,
    PipelineStage,
    RawStageItem,
    SubmissionResult,
    SubmissionStatus,
)
from .ports import (
    AnalysisStageProcessor,
    EncryptedStageSink,
    PipelineFaultSink,
    RawStageProcessor,
    RedactionStageProcessor,
)
from .transport import EndpointRegistry


class LifecyclePipelineFaultSink:
    def __init__(self, lifecycle_ref: pykka.ActorRef[LifecycleActor]) -> None:
        self._lifecycle_ref = lifecycle_ref

    def emit(self, event: PipelineFaultEvent) -> None:
        del event
        self._lifecycle_ref.tell(FaultCapture(LifecycleFaultCode.ACTOR_FAILURE))


@dataclass(frozen=True, slots=True)
class PipelineStats:
    stages: tuple[StageStatus, ...]
    raw_credits: int
    analyzed_credits: int
    redacted_credits: int
    encrypted_credits: int
    coalesced: bool


def apply_submission_feedback(
    controller: AdaptiveCaptureController,
    result: SubmissionResult,
) -> None:
    """Adapt capture cadence from the existing bounded pipeline outcome only."""
    if result.status is SubmissionStatus.ACCEPTED:
        controller.note_success()
        return
    if result.status in {SubmissionStatus.DROPPED, SubmissionStatus.COALESCED}:
        controller.note_overload()
        return
    raise ValueError("unsupported pipeline submission status")


class BoundedCapturePipeline:
    """Bounded in-memory ZeroMQ pipeline implementing CaptureWorkCoordinator."""

    def __init__(
        self,
        *,
        gate: CaptureGate,
        raw_processor: RawStageProcessor,
        analysis_processor: AnalysisStageProcessor,
        redaction_processor: RedactionStageProcessor,
        sink: EncryptedStageSink,
        fault_sink: PipelineFaultSink,
        limits: PipelineLimits | None = None,
    ) -> None:
        self._owner_thread = threading.get_ident()
        self._gate = gate
        self._limits = limits or PipelineLimits()
        self._context: zmq.Context[zmq.Socket[bytes]] = zmq.Context(io_threads=1)
        self._endpoints = EndpointRegistry()
        self._cancellation = CancellationRegistry()
        self._credits = (
            CreditLedger(self._limits.raw_queue_items),
            CreditLedger(self._limits.stage_queue_items),
            CreditLedger(self._limits.stage_queue_items),
            CreditLedger(self._limits.stage_queue_items),
        )
        self._actor_refs: list[pykka.ActorRef[PipelineStageActor]] = []
        self._stage_metrics: list[StageMetrics] = []
        self._closed = False

        stage_definitions = (
            (
                PipelineStage.ENCRYPTED,
                self._endpoints.redacted_to_encrypted,
                self._credits[3],
                self._limits.stage_queue_items,
                None,
                sink,
                None,
                None,
                None,
            ),
            (
                PipelineStage.REDACTED,
                self._endpoints.analyzed_to_redacted,
                self._credits[2],
                self._limits.stage_queue_items,
                redaction_processor,
                None,
                self._endpoints.redacted_to_encrypted,
                self._credits[3],
                self._limits.stage_queue_items,
            ),
            (
                PipelineStage.ANALYZED,
                self._endpoints.raw_to_analyzed,
                self._credits[1],
                self._limits.stage_queue_items,
                analysis_processor,
                None,
                self._endpoints.analyzed_to_redacted,
                self._credits[2],
                self._limits.stage_queue_items,
            ),
            (
                PipelineStage.RAW,
                self._endpoints.ingress,
                self._credits[0],
                self._limits.raw_queue_items,
                raw_processor,
                None,
                self._endpoints.raw_to_analyzed,
                self._credits[1],
                self._limits.stage_queue_items,
            ),
        )
        try:
            for definition in stage_definitions:
                ready = threading.Event()
                metrics = StageMetrics(definition[0])
                actor_ref = PipelineStageActor.start(
                    stage=definition[0],
                    context=self._context,
                    input_endpoint=definition[1],
                    input_credit=definition[2],
                    input_capacity=definition[3],
                    limits=self._limits,
                    cancellation=self._cancellation,
                    gate=self._gate,
                    fault_sink=fault_sink,
                    ready=ready,
                    metrics=metrics,
                    processor=definition[4],
                    sink=definition[5],
                    output_endpoint=definition[6],
                    output_credit=definition[7],
                    output_capacity=definition[8],
                )
                self._actor_refs.append(actor_ref)
                self._stage_metrics.append(metrics)
                if not ready.wait(self._limits.control_timeout_seconds):
                    raise RuntimeError("pipeline stage failed to become ready")
            self._ingress = PipelineIngress(
                context=self._context,
                endpoint=self._endpoints.ingress,
                credit=self._credits[0],
                limits=self._limits,
                cancellation=self._cancellation,
            )
        except Exception:
            self._stop_actors()
            self._context.destroy(linger=0)
            raise

    @property
    def endpoints(self) -> tuple[str, ...]:
        return tuple(endpoint.address for endpoint in self._endpoints.all())

    def submit_raw(
        self,
        *,
        record_id: UUID,
        frames: tuple[bytearray, ...],
        expected_generation: CaptureGeneration,
        deadline_monotonic_ns: int | None = None,
    ) -> SubmissionResult:
        self._assert_owner()
        deadline = deadline_monotonic_ns or time.monotonic_ns() + 30_000_000_000

        def submit(permit: object) -> SubmissionResult:
            from local_recall.lifecycle.gate import CaptureWorkPermit

            typed_permit = permit
            if not isinstance(typed_permit, CaptureWorkPermit):
                raise TypeError("capture gate returned an invalid permit")
            if typed_permit.generation != expected_generation:
                raise StaleCaptureGeneration("captured frame generation is stale")
            item = RawStageItem(
                record_id=record_id,
                generation=expected_generation,
                configuration_revision=typed_permit.configuration_revision,
                deadline_monotonic_ns=deadline,
                frames=frames,
            )
            return self._ingress.submit(item, typed_permit)

        try:
            return self._gate.run_capture(submit)
        except Exception:
            for frame in frames:
                frame[:] = b"\x00" * len(frame)
            raise

    def flush_coalesced(self) -> SubmissionResult | None:
        self._assert_owner()

        def flush(permit: object) -> SubmissionResult | None:
            from local_recall.lifecycle.gate import CaptureWorkPermit

            if not isinstance(permit, CaptureWorkPermit):
                raise TypeError("capture gate returned an invalid permit")
            return self._ingress.flush_coalesced(permit)

        return self._gate.run_capture(flush)

    def cancel_queued(self, generation: CaptureGeneration) -> None:
        self._cancellation.cancel(generation)
        self._ingress.clear_coalesced(generation.value)

    def cancel_in_flight(self, generation: CaptureGeneration) -> None:
        self._cancellation.cancel(generation)

    def wait_for_quiescence(self, generation: CaptureGeneration, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + timeout_seconds
        for credit in self._credits:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not credit.wait_for_zero(generation, remaining):
                return False
        return not self._ingress.has_coalesced(generation.value)

    def clear_volatile_buffers(self, generation: CaptureGeneration | None) -> None:
        self._ingress.clear_coalesced(None if generation is None else generation.value)
        for actor_ref in self._actor_refs:
            actor_ref.ask(DrainStage(), timeout=self._limits.control_timeout_seconds)
        if generation is not None:
            self._cancellation.clear(generation)

    def stats(self) -> PipelineStats:
        stages = tuple(metrics.snapshot() for metrics in self._stage_metrics)
        return PipelineStats(
            stages=stages,
            raw_credits=self._credits[0].in_use,
            analyzed_credits=self._credits[1].in_use,
            redacted_credits=self._credits[2].in_use,
            encrypted_credits=self._credits[3].in_use,
            coalesced=self._ingress.has_coalesced(),
        )

    def close(self) -> None:
        self._assert_owner()
        if self._closed:
            return
        self._ingress.close()
        self._stop_actors()
        self._context.destroy(linger=0)
        self._closed = True

    def _stop_actors(self) -> None:
        for actor_ref in reversed(self._actor_refs):
            with suppress(Exception):
                actor_ref.stop(block=True, timeout=self._limits.control_timeout_seconds)
        self._actor_refs.clear()

    def _assert_owner(self) -> None:
        if threading.get_ident() != self._owner_thread:
            raise RuntimeError("pipeline runtime used from a non-owner thread")
