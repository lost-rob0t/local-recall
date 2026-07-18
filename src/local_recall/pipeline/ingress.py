from __future__ import annotations

import threading

import zmq

from local_recall.lifecycle.gate import CaptureWorkPermit

from .cancellation import CancellationRegistry
from .credits import CreditLedger
from .framing import encode_item
from .models import (
    PipelineLimits,
    PipelineOverloadPolicy,
    RawStageItem,
    SubmissionResult,
    SubmissionStatus,
)
from .transport import OwnedSocket, PipelineEndpoint, make_push_socket


class PipelineIngress:
    """Single-owner raw ingress with one optional coalesced latest frame."""

    def __init__(
        self,
        *,
        context: zmq.Context[zmq.Socket[bytes]],
        endpoint: PipelineEndpoint,
        credit: CreditLedger,
        limits: PipelineLimits,
        cancellation: CancellationRegistry,
    ) -> None:
        self._owner_thread = threading.get_ident()
        self._credit = credit
        self._limits = limits
        self._cancellation = cancellation
        self._socket: OwnedSocket = make_push_socket(
            context,
            endpoint,
            capacity=limits.raw_queue_items,
            limits=limits,
        )
        self._coalesced_lock = threading.RLock()
        self._coalesced: RawStageItem | None = None
        self._closed = False

    def submit(self, item: RawStageItem, permit: CaptureWorkPermit) -> SubmissionResult:
        self._assert_owner()
        if self._closed:
            item.destroy()
            raise RuntimeError("pipeline ingress is closed")
        self._cancellation.attach(permit)
        if permit.cancelled:
            item.destroy()
            return SubmissionResult(item.record_id, SubmissionStatus.DROPPED)
        if not self._credit.try_acquire(item.generation):
            return self._handle_overload(item)
        try:
            self._socket.send_multipart(encode_item(item, self._limits))
        except zmq.Again, zmq.ZMQError:
            self._credit.release_if_acquired(item.generation)
            return self._handle_overload(item)
        item.destroy()
        return SubmissionResult(item.record_id, SubmissionStatus.ACCEPTED)

    def flush_coalesced(self, permit: CaptureWorkPermit) -> SubmissionResult | None:
        self._assert_owner()
        with self._coalesced_lock:
            item = self._coalesced
            if item is None:
                return None
            if item.generation != permit.generation or permit.cancelled:
                self._coalesced = None
                item.destroy()
                return SubmissionResult(item.record_id, SubmissionStatus.DROPPED)
            if not self._credit.try_acquire(item.generation):
                return SubmissionResult(item.record_id, SubmissionStatus.COALESCED)
            try:
                self._socket.send_multipart(encode_item(item, self._limits))
            except zmq.Again, zmq.ZMQError:
                self._credit.release_if_acquired(item.generation)
                return SubmissionResult(item.record_id, SubmissionStatus.COALESCED)
            self._coalesced = None
            item.destroy()
            return SubmissionResult(item.record_id, SubmissionStatus.ACCEPTED)

    def clear_coalesced(self, generation_value: int | None = None) -> None:
        with self._coalesced_lock:
            item = self._coalesced
            if item is None:
                return
            if generation_value is not None and item.generation.value != generation_value:
                return
            self._coalesced = None
            item.destroy()

    def has_coalesced(self, generation_value: int | None = None) -> bool:
        with self._coalesced_lock:
            if self._coalesced is None:
                return False
            return generation_value is None or self._coalesced.generation.value == generation_value

    def close(self) -> None:
        self._assert_owner()
        if self._closed:
            return
        self.clear_coalesced()
        self._socket.close()
        self._closed = True

    def _handle_overload(self, item: RawStageItem) -> SubmissionResult:
        if self._limits.overload_policy is PipelineOverloadPolicy.DROP_NEWEST:
            item.destroy()
            return SubmissionResult(item.record_id, SubmissionStatus.DROPPED)
        with self._coalesced_lock:
            previous = self._coalesced
            self._coalesced = item
            replaced = None
            if previous is not None:
                replaced = previous.record_id
                previous.destroy()
            return SubmissionResult(item.record_id, SubmissionStatus.COALESCED, replaced)

    def _assert_owner(self) -> None:
        if threading.get_ident() != self._owner_thread:
            raise RuntimeError("pipeline ingress used from a non-owner thread")
