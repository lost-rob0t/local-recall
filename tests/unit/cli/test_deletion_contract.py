from __future__ import annotations

import datetime as dt
from uuid import uuid4

import pytest

from local_recall.cli_contract import (
    MAX_RECORD_ID_LENGTH,
    CliCommand,
    CliDeletionPayload,
    CliOutcome,
    CliPriority,
    CliQueryPayload,
    CliRequest,
    CliResponse,
)


def _now() -> tuple[dt.datetime, dt.datetime]:
    now = dt.datetime.now(dt.UTC)
    return now, now + dt.timedelta(seconds=2)


def test_delete_records_is_a_deletion_capability_command() -> None:
    assert CliCommand.DELETE_RECORDS.priority is CliPriority.QUERY
    assert CliCommand.DELETE_RECORDS.value == "delete-records"
    assert CliCommand.PREVIEW_RECORD.priority is CliPriority.QUERY
    assert CliCommand.PREVIEW_RECORD.value == "preview-record"


def test_delete_request_accepts_explicit_record_scope() -> None:
    now, deadline = _now()
    record_ids = [str(uuid4())]

    request = CliRequest.create(
        command=CliCommand.DELETE_RECORDS,
        now=now,
        deadline=deadline,
        record_ids=record_ids,
    )

    assert request.record_ids == tuple(record_ids)
    assert request.cluster_id is None
    assert request.application is None
    assert request.start is None and request.end is None


def test_delete_request_accepts_cluster_scope() -> None:
    now, deadline = _now()
    cluster_id = "a" * 32

    request = CliRequest.create(
        command=CliCommand.DELETE_RECORDS,
        now=now,
        deadline=deadline,
        cluster_id=cluster_id,
    )

    assert request.cluster_id == cluster_id
    assert request.record_ids == ()


def test_delete_request_accepts_application_scope_with_bounds() -> None:
    now, deadline = _now()
    start = dt.datetime(2026, 8, 22, 10, 0, tzinfo=dt.UTC)
    end = dt.datetime(2026, 8, 22, 11, 0, tzinfo=dt.UTC)

    request = CliRequest.create(
        command=CliCommand.DELETE_RECORDS,
        now=now,
        deadline=deadline,
        application="emacs",
        start=start,
        end=end,
    )

    assert request.application == "emacs"
    assert request.start == start and request.end == end


def test_delete_request_accepts_time_range_scope() -> None:
    now, deadline = _now()
    start = dt.datetime(2026, 8, 22, 10, 0, tzinfo=dt.UTC)
    end = dt.datetime(2026, 8, 22, 11, 0, tzinfo=dt.UTC)

    request = CliRequest.create(
        command=CliCommand.DELETE_RECORDS,
        now=now,
        deadline=deadline,
        start=start,
        end=end,
    )

    assert request.application is None


def test_delete_request_rejects_empty_or_mixed_scopes() -> None:
    now, deadline = _now()

    with pytest.raises(ValueError, match="scope"):
        CliRequest.create(
            command=CliCommand.DELETE_RECORDS,
            now=now,
            deadline=deadline,
        )
    with pytest.raises(ValueError, match="scope"):
        CliRequest.create(
            command=CliCommand.DELETE_RECORDS,
            now=now,
            deadline=deadline,
            record_ids=[str(uuid4())],
            cluster_id="b" * 32,
        )
    with pytest.raises(ValueError, match="scope"):
        CliRequest.create(
            command=CliCommand.DELETE_RECORDS,
            now=now,
            deadline=deadline,
            application="emacs",
        )
    with pytest.raises(ValueError, match="scope"):
        CliRequest.create(
            command=CliCommand.DELETE_RECORDS,
            now=now,
            deadline=deadline,
            record_ids=[],
        )


def test_delete_request_rejects_other_commands_for_deletion_fields() -> None:
    now, deadline = _now()

    with pytest.raises(ValueError, match="scope"):
        CliRequest.create(
            command=CliCommand.STATUS,
            now=now,
            deadline=deadline,
            record_ids=[str(uuid4())],
        )


def test_delete_request_rejects_oversized_or_malformed_scopes() -> None:
    now, deadline = _now()

    with pytest.raises(ValueError):
        CliRequest.create(
            command=CliCommand.DELETE_RECORDS,
            now=now,
            deadline=deadline,
            record_ids=["not-a-uuid"],
        )
    with pytest.raises(ValueError):
        CliRequest.create(
            command=CliCommand.DELETE_RECORDS,
            now=now,
            deadline=deadline,
            cluster_id="short",
        )
    with pytest.raises(ValueError):
        CliRequest.create(
            command=CliCommand.DELETE_RECORDS,
            now=now,
            deadline=deadline,
            application="x" * 300,
        )


def test_preview_request_requires_single_record_and_target() -> None:
    now, deadline = _now()

    request = CliRequest.create(
        command=CliCommand.PREVIEW_RECORD,
        now=now,
        deadline=deadline,
        record_ids=[str(uuid4())],
        target="text",
    )

    assert request.target == "text"
    with pytest.raises(ValueError, match="preview"):
        CliRequest.create(
            command=CliCommand.PREVIEW_RECORD,
            now=now,
            deadline=deadline,
        )
    with pytest.raises(ValueError, match="preview"):
        CliRequest.create(
            command=CliCommand.PREVIEW_RECORD,
            now=now,
            deadline=deadline,
            record_ids=[str(uuid4()), str(uuid4())],
            target="text",
        )
    with pytest.raises(ValueError, match="preview"):
        CliRequest.create(
            command=CliCommand.PREVIEW_RECORD,
            now=now,
            deadline=deadline,
            record_ids=[str(uuid4())],
            target="raw-unredacted",
        )
    assert MAX_RECORD_ID_LENGTH >= 36


def test_deletion_payload_is_content_free_and_serializable() -> None:
    payload = CliDeletionPayload(deleted_count=3, scope_kind="application", recovered=False)

    assert payload.deleted_count == 3
    assert payload.scope_kind == "application"
    assert payload.recovered is False
    encoded = payload.to_json()
    assert "emacs" not in encoded
    with pytest.raises(ValueError):
        CliDeletionPayload(deleted_count=-1, scope_kind="application")
    with pytest.raises(ValueError):
        CliDeletionPayload(deleted_count=1, scope_kind="window-titles")


def test_deletion_success_response_carries_deletion_payload_only() -> None:
    now, deadline = _now()
    request = CliRequest.create(
        command=CliCommand.DELETE_RECORDS,
        now=now,
        deadline=deadline,
        cluster_id="c" * 32,
    )

    response = CliResponse.success(
        request_id=request.request_id,
        deletion_payload=CliDeletionPayload(deleted_count=2, scope_kind="activity-cluster"),
    )

    assert response.outcome is CliOutcome.SUCCESS
    assert response.deletion_payload is not None
    assert response.query_payload is None

    with pytest.raises(ValueError, match="payload"):
        CliResponse.success(
            request_id=request.request_id,
            deletion_payload=CliDeletionPayload(deleted_count=1, scope_kind="application"),
            query_payload=CliQueryPayload(text="mixed"),
        )
    with pytest.raises(ValueError, match="payload"):
        CliResponse.success(
            request_id=request.request_id,
            deletion_payload=CliDeletionPayload(deleted_count=1, scope_kind="application"),
            lifecycle_state="off",
        )
