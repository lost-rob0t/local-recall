from datetime import UTC, datetime

import pytest

from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)


def provenance() -> MetadataProvenance:
    return MetadataProvenance(
        source_id="synthetic",
        observed_at=datetime.now(UTC),
        confidence=SourceConfidence(0.9),
    )


def test_confidence_is_bounded() -> None:
    with pytest.raises(ValueError, match="between 0 and 1"):
        SourceConfidence(1.01)


def test_context_metadata_rejects_duplicate_fields() -> None:
    field = ContextField(name="application", value="synthetic-app", provenance=(provenance(),))

    with pytest.raises(ValueError, match="duplicate metadata field"):
        ContextMetadata(observed_at=datetime.now(UTC), fields=(field, field))


def test_context_metadata_repr_does_not_expose_values() -> None:
    metadata = ContextMetadata(
        observed_at=datetime.now(UTC),
        fields=(
            ContextField(
                name="window_title",
                value="SECRET WINDOW TITLE",
                provenance=(provenance(),),
            ),
        ),
    )

    assert metadata.get("window_title") == "SECRET WINDOW TITLE"
    assert "SECRET WINDOW TITLE" not in repr(metadata)
