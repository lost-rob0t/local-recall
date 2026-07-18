from __future__ import annotations

import threading
import time

from local_recall.domain.lifecycle import CaptureGeneration


class CreditLedger:
    """Authoritative application-level edge capacity."""

    def __init__(self, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self._condition = threading.Condition()
        self._in_use_by_generation: dict[int, int] = {}

    def try_acquire(self, generation: CaptureGeneration) -> bool:
        with self._condition:
            if self.in_use_locked >= self.capacity:
                return False
            key = generation.value
            self._in_use_by_generation[key] = self._in_use_by_generation.get(key, 0) + 1
            return True

    def release(self, generation: CaptureGeneration) -> None:
        with self._condition:
            key = generation.value
            current = self._in_use_by_generation.get(key, 0)
            if current <= 0:
                raise RuntimeError("pipeline credit released without acquisition")
            if current == 1:
                self._in_use_by_generation.pop(key, None)
            else:
                self._in_use_by_generation[key] = current - 1
            self._condition.notify_all()

    def release_if_acquired(self, generation: CaptureGeneration) -> bool:
        with self._condition:
            key = generation.value
            current = self._in_use_by_generation.get(key, 0)
            if current <= 0:
                return False
            if current == 1:
                self._in_use_by_generation.pop(key, None)
            else:
                self._in_use_by_generation[key] = current - 1
            self._condition.notify_all()
            return True

    @property
    def in_use(self) -> int:
        with self._condition:
            return self.in_use_locked

    @property
    def in_use_locked(self) -> int:
        return sum(self._in_use_by_generation.values())

    def in_use_for(self, generation: CaptureGeneration) -> int:
        with self._condition:
            return self._in_use_by_generation.get(generation.value, 0)

    def wait_for_zero(self, generation: CaptureGeneration, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            while self._in_use_by_generation.get(generation.value, 0) > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True
