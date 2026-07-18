from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import cast
from uuid import UUID

import pykka
import zmq

from local_recall.lifecycle.errors import CaptureGateClosed, StaleCaptureGeneration
from local_recall.lifecycle.gate import CaptureGate

from .cancellation import CancellationRegistry, PipelineCancellationToken
from .credits import CreditLedger
from .errors import PipelineProtocolError
from .framing import decode_item, encode_item, peek_record_and_generation
from .models import (
    AnalyzedStageItem,
    EncryptedStageItem,
    PipelineFaultCode,
    PipelineFaultEvent,
    PipelineItem,
    PipelineLimits,
    PipelineStage,
    RawStageItem,
    RedactedStageItem,
)
from .ports import (
    AnalysisStageProcessor,
    EncryptedStageSink,
    PipelineFaultSink,
    RawStageProcessor,
    RedactionStageProcessor,
)
from .transport import PipelineEndpoint, make_pull_socket, make_push_socket


@dataclass(frozen=True, slots=True)
class DrainStage:
    pass


@dataclass(frozen=True, slots=True)
class StageStatusRequest:
    pass


@dataclass(frozen=True, slots=True)
class StageStatus:
    stage: PipelineStage
    processing: bool
    received: int
    completed: int
    dropped: int
    faults: int
    owner_thread_id: int | None


class StageMetrics:
    def __init__(self, stage: PipelineStage) -> None:
        self._stage = stage
        self._lock = threading.RLock()
        self._processing = False
        self._received = 0
        self._completed = 0
        self._dropped = 0
        self._faults = 0
        self._owner_thread_id: int | None = None

    def set_owner(self, thread_id: int) -> None:
        with self._lock:
            self._owner_thread_id = thread_id

    def set_processing(self, value: bool) -> None:
        with self._lock:
            self._processing = value

    def received(self) -> None:
        with self._lock:
            self._received += 1

    def completed(self) -> None:
        with self._lock:
            self._completed += 1

    def dropped(self, count: int = 1) -> None:
        with self._lock:
            self._dropped += count

    def faulted(self) -> None:
        with self._lock:
            self._faults += 1

    def snapshot(self) -> StageStatus:
        with self._lock:
            return StageStatus(
                stage=self._stage,
                processing=self._processing,
                received=self._received,
                completed=self._completed,
                dropped=self._dropped,
                faults=self._faults,
                owner_thread_id=self._owner_thread_id,
            )


@dataclass(frozen=True, slots=True)
class _PollStage:
    pass


Processor = RawStageProcessor | AnalysisStageProcessor | RedactionStageProcessor


class PipelineStageActor(pykka.ThreadingActor):
    """One socket-owning Pykka pump for one typed pipeline stage."""

    def __init__(
        self,
        *,
        stage: PipelineStage,
        context: zmq.Context[zmq.Socket[bytes]],
        input_endpoint: PipelineEndpoint,
        input_credit: CreditLedger,
        input_capacity: int,
        limits: PipelineLimits,
        cancellation: CancellationRegistry,
        gate: CaptureGate,
        fault_sink: PipelineFaultSink,
        ready: threading.Event,
        metrics: StageMetrics,
        processor: Processor | None = None,
        sink: EncryptedStageSink | None = None,
        output_endpoint: PipelineEndpoint | None = None,
        output_credit: CreditLedger | None = None,
        output_capacity: int | None = None,
    ) -> None:
        super().__init__()
        self._stage = stage
        self._context = context
        self._input_endpoint = input_endpoint
        self._input_credit = input_credit
        self._input_capacity = input_capacity
        self._limits = limits
        self._cancellation = cancellation
        self._gate = gate
        self._fault_sink = fault_sink
        self._ready = ready
        self._metrics = metrics
        self._processor = processor
        self._sink = sink
        self._output_endpoint = output_endpoint
        self._output_credit = output_credit
        self._output_capacity = output_capacity
        self._pull = None
        self._push = None
        self._polling = True
        self._faulted = False

    def on_start(self) -> None:
        self._metrics.set_owner(threading.get_ident())
        self._pull = make_pull_socket(
            self._context,
            self._input_endpoint,
            capacity=self._input_capacity,
            limits=self._limits,
        )
        if self._output_endpoint is not None:
            if self._output_capacity is None:
                raise RuntimeError("output capacity is required")
            self._push = make_push_socket(
                self._context,
                self._output_endpoint,
                capacity=self._output_capacity,
                limits=self._limits,
            )
        self._ready.set()
        self.actor_ref.tell(_PollStage())

    def on_stop(self) -> None:
        self._polling = False
        if self._push is not None:
            self._push.close()
            self._push = None
        if self._pull is not None:
            self._pull.close()
            self._pull = None

    def on_receive(self, message: object) -> object:
        if isinstance(message, _PollStage):
            self._poll_once()
            if self._polling and self.actor_ref.is_alive():
                self.actor_ref.tell(_PollStage())
            return None
        if isinstance(message, DrainStage):
            return self._drain()
        if isinstance(message, StageStatusRequest):
            return self._metrics.snapshot()
        return None

    def _poll_once(self) -> None:
        pull = self._pull
        if pull is None:
            return
        try:
            parts = pull.recv_multipart()
        except zmq.Again:
            return
        except zmq.ZMQError:
            self._emit_fault(UUID(int=0), PipelineFaultCode.TRANSPORT_FAILURE)
            self._faulted = True
            return
        self._metrics.received()
        self._handle_parts(parts)

    def _handle_parts(self, parts: list[bytes]) -> None:
        item: PipelineItem | None = None
        record_id, generation = peek_record_and_generation(parts)
        try:
            item = decode_item(parts, expected_stage=self._stage, limits=self._limits)
            generation = item.generation
            record_id = item.record_id
            token = self._cancellation.token(item.generation)
            if (
                self._faulted
                or token.cancelled
                or time.monotonic_ns() >= item.deadline_monotonic_ns
            ):
                self._metrics.dropped()
                return
            try:
                self._gate.require_current_generation(item.generation)
            except CaptureGateClosed, StaleCaptureGeneration:
                self._metrics.dropped()
                return

            self._metrics.set_processing(True)
            if self._stage is PipelineStage.ENCRYPTED:
                encrypted = cast(EncryptedStageItem, item)
                self._persist(encrypted, token)
                self._metrics.completed()
                return

            output = self._process(item, token)
            if token.cancelled:
                self._metrics.dropped()
                return
            self._gate.require_current_generation(item.generation)
            self._validate_output(item, output)
            if not self._send_output(output):
                self._metrics.dropped()
                return
            self._metrics.completed()
        except CaptureGateClosed, StaleCaptureGeneration:
            self._metrics.dropped()
        except PipelineProtocolError:
            self._faulted = True
            self._emit_fault(record_id or UUID(int=0), PipelineFaultCode.PROTOCOL_FAILURE)
        except Exception:
            self._faulted = True
            code = (
                PipelineFaultCode.PERSISTENCE_FAILURE
                if self._stage is PipelineStage.ENCRYPTED
                else PipelineFaultCode.PROCESSOR_FAILURE
            )
            self._emit_fault(record_id or UUID(int=0), code)
        finally:
            self._metrics.set_processing(False)
            if isinstance(item, RawStageItem):
                item.destroy()
            if generation is not None:
                self._input_credit.release_if_acquired(generation)

    def _process(self, item: PipelineItem, token: PipelineCancellationToken) -> PipelineItem:
        processor = self._processor
        if processor is None:
            raise PipelineProtocolError("pipeline stage has no processor", record_id=item.record_id)
        if self._stage is PipelineStage.RAW:
            return cast(RawStageProcessor, processor).process(cast(RawStageItem, item), token)
        if self._stage is PipelineStage.ANALYZED:
            return cast(AnalysisStageProcessor, processor).process(
                cast(AnalyzedStageItem, item), token
            )
        return cast(RedactionStageProcessor, processor).process(
            cast(RedactedStageItem, item), token
        )

    def _persist(self, item: EncryptedStageItem, token: PipelineCancellationToken) -> None:
        sink = self._sink
        if sink is None:
            raise PipelineProtocolError("encrypted stage has no sink", record_id=item.record_id)

        def commit(_: object) -> None:
            sink.persist(item, token)

        self._gate.run_persistence(item.generation, commit)

    def _validate_output(self, source: PipelineItem, output: PipelineItem) -> None:
        expected = {
            PipelineStage.RAW: PipelineStage.ANALYZED,
            PipelineStage.ANALYZED: PipelineStage.REDACTED,
            PipelineStage.REDACTED: PipelineStage.ENCRYPTED,
        }[self._stage]
        if output.stage is not expected:
            raise PipelineProtocolError(
                "processor returned the wrong stage", record_id=source.record_id
            )
        if output.record_id != source.record_id:
            raise PipelineProtocolError(
                "processor changed the record identifier", record_id=source.record_id
            )
        if output.generation != source.generation:
            raise PipelineProtocolError(
                "processor changed the capture generation", record_id=source.record_id
            )
        if output.configuration_revision != source.configuration_revision:
            raise PipelineProtocolError(
                "processor changed the configuration revision", record_id=source.record_id
            )

    def _send_output(self, output: PipelineItem) -> bool:
        push = self._push
        credit = self._output_credit
        if push is None or credit is None:
            raise PipelineProtocolError(
                "pipeline stage has no output edge", record_id=output.record_id
            )
        if not credit.try_acquire(output.generation):
            return False
        try:
            push.send_multipart(encode_item(output, self._limits))
        except zmq.Again, zmq.ZMQError:
            credit.release_if_acquired(output.generation)
            return False
        return True

    def _drain(self) -> int:
        pull = self._pull
        if pull is None:
            return 0
        drained = 0
        while True:
            try:
                parts = pull.recv_multipart(nonblocking=True)
            except zmq.Again:
                break
            except zmq.ZMQError:
                break
            _, generation = peek_record_and_generation(parts)
            if generation is not None:
                self._input_credit.release_if_acquired(generation)
            try:
                item = decode_item(parts, expected_stage=self._stage, limits=self._limits)
            except PipelineProtocolError:
                item = None
            if isinstance(item, RawStageItem):
                item.destroy()
            drained += 1
            self._metrics.dropped()
        return drained

    def _emit_fault(self, record_id: UUID, code: PipelineFaultCode) -> None:
        self._metrics.faulted()
        try:
            self._fault_sink.emit(PipelineFaultEvent(record_id, self._stage, code))
        except Exception:
            self._polling = False
