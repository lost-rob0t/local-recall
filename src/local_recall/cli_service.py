"""Command execution across the Local Recall CLI/daemon boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from local_recall.cli_contract import (
    MAX_DEADLINE,
    CliCommand,
    CliDiagnosticCategory,
    CliLifecycleState,
    CliOutcome,
    CliRequest,
    CliResponse,
)

_LIFECYCLE_COMMANDS = frozenset(
    {
        CliCommand.START,
        CliCommand.PAUSE,
        CliCommand.RESUME,
        CliCommand.STOP,
        CliCommand.STATUS,
        CliCommand.PRIVACY_ON,
        CliCommand.PRIVACY_OFF,
    }
)


class DaemonClient(Protocol):
    """Narrow client port implemented by authenticated daemon transports."""

    def request(self, request: CliRequest) -> CliResponse:
        """Send one bounded typed request and return its typed response."""
        ...


@dataclass(frozen=True, slots=True, repr=False)
class CliExecutionResult:
    """Sanitized execution result used by CLI rendering."""

    response: CliResponse
    exit_code: int

    def __repr__(self) -> str:
        return f"CliExecutionResult(response={self.response!r}, exit_code={self.exit_code})"


def exit_code_for(outcome: CliOutcome) -> int:
    """Map a closed daemon outcome to a stable process exit code."""
    if outcome is CliOutcome.SUCCESS:
        return 0
    if outcome is CliOutcome.INVALID:
        return 2
    if outcome in {CliOutcome.UNAVAILABLE, CliOutcome.TIMEOUT, CliOutcome.OVERLOADED}:
        return 3
    if outcome in {CliOutcome.UNAUTHORIZED, CliOutcome.LOCKED}:
        return 4
    if outcome in {CliOutcome.FAULTED, CliOutcome.INTERNAL_FAILURE}:
        return 5
    return 130


def _expected_diagnostic_category(command: CliCommand) -> CliDiagnosticCategory | None:
    if command is CliCommand.PROVIDERS:
        return CliDiagnosticCategory.PROVIDERS
    if command is CliCommand.HEALTH:
        return CliDiagnosticCategory.HEALTH
    if command is CliCommand.STORAGE_STATS:
        return CliDiagnosticCategory.STORAGE
    return None


def execute_command(
    *,
    client: DaemonClient,
    command: CliCommand,
    now: datetime,
    timeout: timedelta,
    query: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    record_ids: tuple[str, ...] | list[str] = (),
    cluster_id: str | None = None,
    application: str | None = None,
    target: str | None = None,
) -> CliExecutionResult:
    """Execute one CLI command without taking ownership of daemon behavior."""
    if timeout <= timedelta(0) or timeout > MAX_DEADLINE:
        response = CliResponse.failure(
            request_id="invalid-request",
            outcome=CliOutcome.INVALID,
            reason_code="invalid-timeout",
        )
        return CliExecutionResult(response=response, exit_code=exit_code_for(response.outcome))

    try:
        request = CliRequest.create(
            command=command,
            now=now,
            deadline=now + timeout,
            query=query,
            start=start,
            end=end,
            record_ids=record_ids,
            cluster_id=cluster_id,
            application=application,
            target=target,
        )
    except ValueError:
        response = CliResponse.failure(
            request_id="invalid-request",
            outcome=CliOutcome.INVALID,
            reason_code="invalid-request",
        )
        return CliExecutionResult(response=response, exit_code=exit_code_for(response.outcome))

    try:
        response = client.request(request)
    except Exception:
        response = CliResponse.failure(
            request_id=request.request_id,
            outcome=CliOutcome.INTERNAL_FAILURE,
            reason_code="client-failure",
        )

    if response.request_id != request.request_id:
        response = CliResponse.failure(
            request_id=request.request_id,
            outcome=CliOutcome.INTERNAL_FAILURE,
            reason_code="request-mismatch",
        )
    elif (
        command in _LIFECYCLE_COMMANDS
        and response.outcome is CliOutcome.SUCCESS
        and response.lifecycle_state is None
    ):
        response = CliResponse.failure(
            request_id=request.request_id,
            outcome=CliOutcome.INTERNAL_FAILURE,
            reason_code="lifecycle-state-missing",
        )
    elif (
        command is CliCommand.STOP
        and response.outcome is CliOutcome.SUCCESS
        and response.lifecycle_state is not CliLifecycleState.OFF
    ):
        response = CliResponse.failure(
            request_id=request.request_id,
            outcome=CliOutcome.INTERNAL_FAILURE,
            reason_code="stop-not-quiescent",
        )
    elif (
        command
        in {CliCommand.ASK, CliCommand.TIMELINE, CliCommand.SEARCH, CliCommand.PREVIEW_RECORD}
        and response.outcome is CliOutcome.SUCCESS
        and response.query_payload is None
    ):
        response = CliResponse.failure(
            request_id=request.request_id,
            outcome=CliOutcome.INTERNAL_FAILURE,
            reason_code="query-result-missing",
        )
    elif (
        command is CliCommand.DELETE_RECORDS
        and response.outcome is CliOutcome.SUCCESS
        and response.deletion_payload is None
    ):
        response = CliResponse.failure(
            request_id=request.request_id,
            outcome=CliOutcome.INTERNAL_FAILURE,
            reason_code="deletion-result-missing",
        )
    elif response.outcome is CliOutcome.SUCCESS:
        expected_category = _expected_diagnostic_category(command)
        if expected_category is not None:
            payload = response.diagnostic_payload
            if payload is None:
                response = CliResponse.failure(
                    request_id=request.request_id,
                    outcome=CliOutcome.INTERNAL_FAILURE,
                    reason_code="diagnostic-result-missing",
                )
            elif payload.category is not expected_category:
                response = CliResponse.failure(
                    request_id=request.request_id,
                    outcome=CliOutcome.INTERNAL_FAILURE,
                    reason_code="diagnostic-category-mismatch",
                )

    return CliExecutionResult(response=response, exit_code=exit_code_for(response.outcome))
