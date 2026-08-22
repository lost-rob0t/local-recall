"""Daemon-authoritative, content-free recording indicator domain model."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from local_recall.cli_contract import CliCommand, CliLifecycleState, CliOutcome
from local_recall.cli_service import DaemonClient, execute_command


class IndicatorState(StrEnum):
    """Closed display states safe for desktop status surfaces."""

    OFF = "off"
    PAUSED = "paused"
    RECORDING = "recording"
    PRIVACY = "privacy"
    LOCKED = "locked"
    OVERLOADED = "overloaded"
    FAULTED = "faulted"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True, repr=False)
class IndicatorSnapshot:
    """One current daemon observation safe for desktop status rendering."""

    state: IndicatorState
    privacy_mode: bool
    observed_at: datetime
    capture_backend: str | None = None
    metadata_source: str | None = None
    last_capture_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.last_capture_at is not None and (
            self.last_capture_at.tzinfo is None or self.last_capture_at.utcoffset() is None
        ):
            raise ValueError("last_capture_at must be timezone-aware")

    def __repr__(self) -> str:
        return (
            "IndicatorSnapshot("
            f"state={self.state.value!r}, privacy_mode={self.privacy_mode}, "
            "capture_backend=<opaque>, metadata_source=<opaque>, "
            "last_capture_at=<timestamp>, observed_at=<timestamp>)"
        )


_LIFECYCLE_TO_INDICATOR = {
    CliLifecycleState.OFF: IndicatorState.OFF,
    CliLifecycleState.PAUSED: IndicatorState.PAUSED,
    CliLifecycleState.RECORDING: IndicatorState.RECORDING,
    CliLifecycleState.LOCKED: IndicatorState.LOCKED,
    CliLifecycleState.OVERLOADED: IndicatorState.OVERLOADED,
    CliLifecycleState.FAULTED: IndicatorState.FAULTED,
}


@dataclass(slots=True)
class IndicatorController:
    """Thin view controller over authoritative daemon status and controls."""

    client: DaemonClient
    timeout: timedelta

    def refresh(self, *, now: datetime) -> IndicatorSnapshot:
        """Discard prior display state and render one fresh daemon observation."""
        result = execute_command(
            client=self.client,
            command=CliCommand.STATUS,
            now=now,
            timeout=self.timeout,
        )
        response = result.response
        if response.outcome is not CliOutcome.SUCCESS:
            return self._failure_snapshot(outcome=response.outcome, now=now)

        lifecycle_state = response.lifecycle_state
        status_payload = response.status_payload
        if lifecycle_state is None or status_payload is None:
            return self._empty_snapshot(state=IndicatorState.FAULTED, now=now)

        state = _LIFECYCLE_TO_INDICATOR.get(lifecycle_state, IndicatorState.FAULTED)
        if status_payload.privacy_mode and state in {
            IndicatorState.OFF,
            IndicatorState.PAUSED,
            IndicatorState.RECORDING,
        }:
            state = IndicatorState.PRIVACY

        return IndicatorSnapshot(
            state=state,
            privacy_mode=status_payload.privacy_mode,
            observed_at=now,
            capture_backend=status_payload.capture_backend,
            metadata_source=status_payload.metadata_source,
            last_capture_at=status_payload.last_capture_at,
        )

    def stop(self, *, now: datetime) -> IndicatorSnapshot:
        """Request quiescence, then display only a fresh authoritative status."""
        execute_command(
            client=self.client,
            command=CliCommand.STOP,
            now=now,
            timeout=self.timeout,
        )
        return self.refresh(now=now)

    def privacy_on(self, *, now: datetime) -> IndicatorSnapshot:
        """Enable privacy mode, then re-query rather than mutating UI state."""
        execute_command(
            client=self.client,
            command=CliCommand.PRIVACY_ON,
            now=now,
            timeout=self.timeout,
        )
        return self.refresh(now=now)

    def privacy_off(self, *, now: datetime) -> IndicatorSnapshot:
        """Disable privacy mode, then re-query rather than mutating UI state."""
        execute_command(
            client=self.client,
            command=CliCommand.PRIVACY_OFF,
            now=now,
            timeout=self.timeout,
        )
        return self.refresh(now=now)

    @staticmethod
    def _empty_snapshot(*, state: IndicatorState, now: datetime) -> IndicatorSnapshot:
        return IndicatorSnapshot(state=state, privacy_mode=False, observed_at=now)

    @classmethod
    def _failure_snapshot(
        cls,
        *,
        outcome: CliOutcome,
        now: datetime,
    ) -> IndicatorSnapshot:
        if outcome is CliOutcome.LOCKED:
            state = IndicatorState.LOCKED
        elif outcome is CliOutcome.OVERLOADED:
            state = IndicatorState.OVERLOADED
        elif outcome in {CliOutcome.FAULTED, CliOutcome.INTERNAL_FAILURE}:
            state = IndicatorState.FAULTED
        else:
            state = IndicatorState.UNAVAILABLE
        return cls._empty_snapshot(state=state, now=now)
