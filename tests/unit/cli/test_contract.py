import datetime as dt

import pytest
from local_recall.cli_contract import (
    CliCommand,
    CliOutcome,
    CliPriority,
    CliRequest,
    CliResponse,
)


def test_stop_and_privacy_commands_are_urgent_control() -> None:
    assert CliCommand.STOP.priority is CliPriority.URGENT_CONTROL
    assert CliCommand.PRIVACY_ON.priority is CliPriority.URGENT_CONTROL
    assert CliCommand.PRIVACY_OFF.priority is CliPriority.URGENT_CONTROL


@pytest.mark.parametrize(
    ("command", "priority"),
    [
        (CliCommand.START, CliPriority.CONTROL),
        (CliCommand.PAUSE, CliPriority.CONTROL),
        (CliCommand.RESUME, CliPriority.CONTROL),
        (CliCommand.STATUS, CliPriority.CONTROL),
        (CliCommand.ASK, CliPriority.QUERY),
        (CliCommand.TIMELINE, CliPriority.QUERY),
        (CliCommand.SEARCH, CliPriority.QUERY),
        (CliCommand.PROVIDERS, CliPriority.QUERY),
        (CliCommand.HEALTH, CliPriority.QUERY),
        (CliCommand.STORAGE_STATS, CliPriority.QUERY),
    ],
)
def test_command_priority_is_closed_and_deterministic(
    command: CliCommand,
    priority: CliPriority,
) -> None:
    assert command.priority is priority


def test_request_rejects_expired_deadline() -> None:
    now = dt.datetime(2026, 8, 22, 19, 0, tzinfo=dt.UTC)

    with pytest.raises(ValueError, match="deadline"):
        CliRequest.create(
            command=CliCommand.STATUS,
            now=now,
            deadline=now - dt.timedelta(milliseconds=1),
        )


def test_query_text_is_payload_not_routing_metadata() -> None:
    marker = "synthetic-question-marker"
    now = dt.datetime(2026, 8, 22, 19, 0, tzinfo=dt.UTC)
    request = CliRequest.create(
        command=CliCommand.ASK,
        now=now,
        deadline=now + dt.timedelta(seconds=2),
        query=marker,
    )

    assert request.query == marker
    assert marker not in request.routing_json()
    assert marker not in repr(request)


def test_response_outcomes_are_closed_and_sanitized() -> None:
    marker = "synthetic-exception-marker"
    response = CliResponse.failure(
        request_id="req-1",
        outcome=CliOutcome.UNAVAILABLE,
        reason_code="daemon-unavailable",
    )

    assert marker not in response.to_json()
    assert marker not in repr(response)
    assert response.outcome is CliOutcome.UNAVAILABLE
