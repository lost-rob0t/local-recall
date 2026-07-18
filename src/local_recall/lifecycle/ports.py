from __future__ import annotations

from typing import Protocol, runtime_checkable

from local_recall.config.manager import ConfigurationSnapshot
from local_recall.domain.lifecycle import CaptureGeneration

from .messages import LifecycleAuditEvent, LifecyclePreflightRequest, LifecyclePreflightResult


@runtime_checkable
class LifecycleConfigurationSource(Protocol):
    def snapshot(self) -> ConfigurationSnapshot: ...


@runtime_checkable
class LifecyclePreflight(Protocol):
    def check(self, request: LifecyclePreflightRequest) -> LifecyclePreflightResult: ...


@runtime_checkable
class CaptureWorkCoordinator(Protocol):
    def cancel_queued(self, generation: CaptureGeneration) -> None: ...

    def cancel_in_flight(self, generation: CaptureGeneration) -> None: ...

    def wait_for_quiescence(
        self, generation: CaptureGeneration, timeout_seconds: float
    ) -> bool: ...

    def clear_volatile_buffers(self, generation: CaptureGeneration | None) -> None: ...


@runtime_checkable
class LifecycleAuditSink(Protocol):
    def emit(self, event: LifecycleAuditEvent) -> None: ...
