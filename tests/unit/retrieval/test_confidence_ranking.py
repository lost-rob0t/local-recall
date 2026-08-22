from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime

from local_recall.domain.frames import RedactedRecord
from local_recall.domain.metadata import ContextField, SourceConfidence
from local_recall.retrieval.time import ResolvedTimeRange

from .test_service import FakeEncryption, FakePolicy, FakeStorage, _api, _record


def _with_confidence(record: RedactedRecord, confidence: float) -> RedactedRecord:
    fields = tuple(
        ContextField(
            field.name,
            field.value,
            tuple(
                replace(item, confidence=SourceConfidence(confidence))
                for item in field.provenance
            ),
        )
        for field in record.frame.metadata.fields
    )
    metadata = replace(record.frame.metadata, fields=fields)
    return replace(record, frame=replace(record.frame, metadata=metadata))


def test_plain_retrieval_ranks_higher_confidence_before_earlier_low_confidence() -> None:
    service_type, query_type, decision_type = _api()
    earlier_low = _with_confidence(
        _record(
            datetime(2026, 8, 22, 10, 5, tzinfo=UTC),
            application="emacs",
            workspace="dev",
            text="same relevance",
        ),
        0.2,
    )
    later_high = _with_confidence(
        _record(
            datetime(2026, 8, 22, 10, 10, tzinfo=UTC),
            application="emacs",
            workspace="dev",
            text="same relevance",
        ),
        0.95,
    )
    records = (earlier_low, later_high)
    storage = FakeStorage(records)
    encryption = FakeEncryption(records)
    policy = FakePolicy(
        decision_type(
            allowed=True,
            remote_provider_eligible=False,
            policy_revision="query-policy-v1",
            reason_code="allowed",
        )
    )
    service = service_type(storage=storage, encryption=encryption, policy=policy)
    query = query_type(
        time_range=ResolvedTimeRange(
            datetime(2026, 8, 22, 10, 0, tzinfo=UTC),
            datetime(2026, 8, 22, 11, 0, tzinfo=UTC),
        ),
        limit=10,
        candidate_limit=100,
    )

    result = asyncio.run(service.retrieve(query))

    assert tuple(item.record_id for item in result.passages) == (
        later_high.record_id,
        earlier_low.record_id,
    )
    assert result.passages[0].score == 0.95
    assert result.passages[1].score == 0.2
