from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from local_recall.audit import (
    AuditEvent,
    AuditReasonCode,
    AuditRecorder,
    LifecycleAuditAdapter,
    RuntimeHardener,
)
from local_recall.domain.lifecycle import CaptureState, TransitionReason
from local_recall.lifecycle.messages import LifecycleAuditEvent


class MemorySink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class FakeResourceLimits:
    RLIMIT_CORE = 4

    def __init__(self) -> None:
        self.limits = (1, 1)

    def setrlimit(self, resource_id: int, limits: tuple[int, int]) -> None:
        assert resource_id == self.RLIMIT_CORE
        self.limits = limits

    def getrlimit(self, resource_id: int) -> tuple[int, int]:
        assert resource_id == self.RLIMIT_CORE
        return self.limits


def test_runtime_hardening_disables_core_dumps_and_fault_handler() -> None:
    fake = FakeResourceLimits()
    masks: list[int] = []
    disabled: list[bool] = []

    result = RuntimeHardener(
        core_resource_id=fake.RLIMIT_CORE,
        set_limits=fake.setrlimit,
        get_limits=fake.getrlimit,
        set_umask=lambda value: masks.append(value) or 0,
        disable_fault_handler=lambda: disabled.append(True),
    ).apply()

    assert fake.limits == (0, 0)
    assert masks == [0o077]
    assert disabled == [True]
    assert result.core_dumps_disabled
    assert result.restrictive_umask_installed
    assert result.fault_handler_disabled
    assert result.validated_storage_roots == 0


def test_lifecycle_adapter_hashes_revision_and_records_states() -> None:
    sink = MemorySink()
    adapter = LifecycleAuditAdapter(
        AuditRecorder(sink, clock=lambda: datetime(2026, 7, 18, tzinfo=UTC))
    )
    source = LifecycleAuditEvent(
        previous=CaptureState.OFF,
        current=CaptureState.STARTING,
        reason=TransitionReason.STARTUP_OPT_IN,
        generation=7,
        configuration_revision="synthetic-private-config-revision",
        occurred_at=datetime(2026, 7, 18, tzinfo=UTC),
        event_id=uuid4(),
    )

    adapter.emit(source)

    assert len(sink.events) == 1
    event = sink.events[0]
    assert event.reason is AuditReasonCode.STARTUP_OPT_IN
    assert event.previous_state is CaptureState.OFF
    assert event.current_state is CaptureState.STARTING
    assert event.configuration_revision_digest is not None
    assert "synthetic-private-config-revision" not in repr(event)
