from __future__ import annotations

from datetime import UTC, datetime

import pytest

from local_recall.config import LocalRecallConfig, PrivacyProfile, RuleEffect, RuleSettings
from local_recall.domain.lifecycle import CaptureState
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.domain.policy import PolicyOperation
from local_recall.lifecycle import CaptureGateClosed
from local_recall.policy import PolicyEnforcementBoundary, PolicyEngine, PolicyEvaluationContext
from local_recall.session.safety import (
    LifecycleAutomaticCaptureBlockSink,
    LockObservation,
    LockState,
    SessionSafetyController,
)
from tests.unit.lifecycle.support import start_actor, wait_for_state

NOW = datetime(2026, 8, 12, 20, 0, tzinfo=UTC)


class FixedClock:
    def now(self) -> datetime:
        return NOW

    def monotonic_ns(self) -> int:
        return 1_000_000_000


def policy_engine() -> PolicyEngine:
    return PolicyEngine(
        LocalRecallConfig(
            profile=PrivacyProfile.LOCAL_FIRST,
            rules=RuleSettings(default_effect=RuleEffect.ALLOW),
        ),
        revision="session-safety-integration-v1",
    )


def metadata() -> ContextMetadata:
    provenance = MetadataProvenance(
        source_id="xorg-generic",
        observed_at=NOW,
        confidence=SourceConfidence(0.95),
        adapter_revision="synthetic-v1",
    )
    return ContextMetadata(
        observed_at=NOW,
        fields=(
            ContextField(name="application", value="editor", provenance=(provenance,)),
            ContextField(name="workspace", value="dev", provenance=(provenance,)),
            ContextField(name="window.id", value=7, provenance=(provenance,)),
        ),
    )


def observation(state: LockState) -> LockObservation:
    return LockObservation(
        state=state,
        observed_at=NOW,
        source_id="logind",
        source_revision="login1-v1",
    )


def test_lock_after_capture_before_persistence_invalidates_lifecycle_and_policy_authorization() -> (
    None
):
    actor_ref, _gate, _source, coordinator, _audit = start_actor(enabled=True)
    try:
        initial = wait_for_state(actor_ref, CaptureState.RECORDING)
        assert initial.generation is not None
        engine = policy_engine()
        controller = SessionSafetyController(
            policy=engine,
            lifecycle=LifecycleAutomaticCaptureBlockSink(actor_ref),
            clock=FixedClock(),
        )
        controller.apply_lock(observation(LockState.UNLOCKED))
        boundary = PolicyEnforcementBoundary(engine)
        context = PolicyEvaluationContext(
            metadata=metadata(),
            evaluated_at=NOW,
            capture_generation=initial.generation,
        )
        authorization, _pixels = boundary.capture(context, lambda: b"synthetic-pixels")
        persistence: list[str] = []

        controller.apply_lock(observation(LockState.LOCKED))
        controller.apply_lock(observation(LockState.UNLOCKED))
        current = wait_for_state(actor_ref, CaptureState.RECORDING)
        assert current.generation is not None

        with pytest.raises(PermissionError):
            boundary.persist(
                context,
                authorization,
                lambda: persistence.append("persisted"),
            )
        assert persistence == []
        assert current.generation != initial.generation
        assert ("cancel_queued", initial.generation.value) in coordinator.calls
        assert ("cancel_in_flight", initial.generation.value) in coordinator.calls
    finally:
        actor_ref.stop(block=True, timeout=2)


def test_lock_prevents_capture_and_all_new_downstream_callbacks() -> None:
    actor_ref, gate, _source, _coordinator, _audit = start_actor(enabled=True)
    try:
        current = wait_for_state(actor_ref, CaptureState.RECORDING)
        assert current.generation is not None
        engine = policy_engine()
        controller = SessionSafetyController(
            policy=engine,
            lifecycle=LifecycleAutomaticCaptureBlockSink(actor_ref),
            clock=FixedClock(),
        )
        controller.apply_lock(observation(LockState.UNLOCKED))
        controller.apply_lock(observation(LockState.LOCKED))
        calls: list[str] = []
        boundary = PolicyEnforcementBoundary(engine)
        context = PolicyEvaluationContext(
            metadata=metadata(),
            evaluated_at=NOW,
            capture_generation=current.generation,
        )

        with pytest.raises(PermissionError):
            boundary.capture(context, lambda: calls.append("screenshot"))
        for operation in (
            PolicyOperation.OCR,
            PolicyOperation.INDEXING,
            PolicyOperation.SUMMARIZATION,
            PolicyOperation.REMOTE_PROVIDER,
        ):
            with pytest.raises(PermissionError):
                boundary.downstream(operation, context, lambda: calls.append("downstream"))
        with pytest.raises(CaptureGateClosed):
            gate.run_capture(lambda _permit: calls.append("gate-capture"))

        assert calls == []
    finally:
        actor_ref.stop(block=True, timeout=2)
