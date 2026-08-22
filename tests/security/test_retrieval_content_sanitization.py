from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from local_recall.retrieval.service import (
    MetadataFilter,
    RetrievedPassage,
    RetrievalQuery,
)
from local_recall.retrieval.time import ResolvedTimeRange


def test_retrieval_control_reprs_exclude_query_and_decrypted_content() -> None:
    query_secret = "QUERY-SECRET-4f3c"
    app_secret = "APP-SECRET-91d2"
    workspace_secret = "WORKSPACE-SECRET-7aa1"
    metadata_secret = "METADATA-SECRET-c812"
    excerpt_secret = "OCR-SECRET-b744"
    time_range = ResolvedTimeRange(
        datetime(2026, 8, 22, 10, 0, tzinfo=UTC),
        datetime(2026, 8, 22, 11, 0, tzinfo=UTC),
    )
    query = RetrievalQuery(
        time_range=time_range,
        application=app_secret,
        workspace=workspace_secret,
        keywords=(query_secret,),
        semantic_text=query_secret,
        metadata_filters=(MetadataFilter("layout", metadata_secret),),
    )
    passage = RetrievedPassage(
        record_id=uuid4(),
        captured_at=datetime(2026, 8, 22, 10, 30, tzinfo=UTC),
        excerpt=excerpt_secret,
        score=0.8,
        metadata_provenance=(),
        redaction_policy_revision="policy-v1",
        redaction_finding_count=1,
    )

    rendered = repr(query) + repr(query.metadata_filters[0]) + repr(passage)

    for secret in (
        query_secret,
        app_secret,
        workspace_secret,
        metadata_secret,
        excerpt_secret,
    ):
        assert secret not in rendered
    assert not hasattr(passage, "pixels")
