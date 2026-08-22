import datetime as dt

import pytest

from local_recall.cli_contract import (
    CliCitation,
    CliCommand,
    CliOutcome,
    CliPriority,
    CliQueryPayload,
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


def test_query_time_filter_is_typed_and_not_routing_metadata() -> None:
    now = dt.datetime(2026, 8, 22, 19, 0, tzinfo=dt.UTC)
    start = dt.datetime(2026, 8, 16, 0, 0, tzinfo=dt.UTC)
    end = dt.datetime(2026, 8, 17, 0, 0, tzinfo=dt.UTC)
    request = CliRequest.create(
        command=CliCommand.SEARCH,
        now=now,
        deadline=now + dt.timedelta(seconds=2),
        query="work",
        start=start,
        end=end,
    )

    assert request.start == start
    assert request.end == end
    assert start.isoformat() not in request.routing_json()
    assert end.isoformat() not in repr(request)


def test_query_time_filter_requires_ordered_pair() -> None:
    now = dt.datetime(2026, 8, 22, 19, 0, tzinfo=dt.UTC)
    start = dt.datetime(2026, 8, 17, 0, 0, tzinfo=dt.UTC)
    end = dt.datetime(2026, 8, 16, 0, 0, tzinfo=dt.UTC)

    with pytest.raises(ValueError, match="time filter"):
        CliRequest.create(
            command=CliCommand.TIMELINE,
            now=now,
            deadline=now + dt.timedelta(seconds=2),
            start=start,
            end=end,
        )


def test_cited_query_payload_is_typed_and_hidden_from_repr() -> None:
    marker = "synthetic-answer-marker"
    citation = CliCitation(
        record_id="record-1",
        captured_at=dt.datetime(2026, 8, 22, 18, 30, tzinfo=dt.UTC),
    )
    payload = CliQueryPayload(text=marker, citations=(citation,))
    response = CliResponse.success(request_id="req-1", query_payload=payload)

    assert response.query_payload == payload
    assert response.query_payload is not None
    assert response.query_payload.citations == (citation,)
    assert marker not in repr(payload)
    assert marker not in repr(response)


def test_query_payload_json_preserves_citations_for_machine_output() -> None:
    citation = CliCitation(
        record_id="record-2",
        captured_at=dt.datetime(2026, 8, 22, 18, 31, tzinfo=dt.UTC),
    )
    payload = CliQueryPayload(text="summary", citations=(citation,))

    rendered = payload.to_json()

    assert '"text":"summary"' in rendered
    assert '"record_id":"record-2"' in rendered
    assert '"captured_at":"2026-08-22T18:31:00+00:00"' in rendered


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
