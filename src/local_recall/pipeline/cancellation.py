from __future__ import annotations

import threading
from dataclasses import dataclass, field

from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.lifecycle.gate import CaptureWorkPermit


@dataclass(frozen=True, slots=True, repr=False)
class PipelineCancellationToken:
    generation: CaptureGeneration
    _local_event: threading.Event = field(repr=False)
    _gate_permit: CaptureWorkPermit | None = field(default=None, repr=False)

    @property
    def cancelled(self) -> bool:
        return self._local_event.is_set() or (
            self._gate_permit is not None and self._gate_permit.cancelled
        )

    def wait_cancelled(self, timeout: float | None = None) -> bool:
        if self.cancelled:
            return True
        return self._local_event.wait(timeout)


class CancellationRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._events: dict[int, threading.Event] = {}
        self._permits: dict[int, CaptureWorkPermit] = {}

    def attach(self, permit: CaptureWorkPermit) -> PipelineCancellationToken:
        with self._lock:
            event = self._events.setdefault(permit.generation.value, threading.Event())
            self._permits[permit.generation.value] = permit
            return PipelineCancellationToken(permit.generation, event, permit)

    def token(self, generation: CaptureGeneration) -> PipelineCancellationToken:
        with self._lock:
            event = self._events.setdefault(generation.value, threading.Event())
            permit = self._permits.get(generation.value)
            return PipelineCancellationToken(generation, event, permit)

    def cancel(self, generation: CaptureGeneration) -> None:
        with self._lock:
            self._events.setdefault(generation.value, threading.Event()).set()

    def clear(self, generation: CaptureGeneration) -> None:
        with self._lock:
            self._events.pop(generation.value, None)
            self._permits.pop(generation.value, None)
