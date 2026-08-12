from datetime import UTC, datetime, timedelta

from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.session import compose_context_metadata

NOW = datetime(2026, 7, 19, 6, 0, tzinfo=UTC)


def field(
    name: str,
    value: str,
    source_id: str,
    confidence: float,
    observed_at: datetime = NOW,
) -> ContextField:
    return ContextField(
        name=name,
        value=value,
        provenance=(
            MetadataProvenance(
                source_id=source_id,
                observed_at=observed_at,
                confidence=SourceConfidence(confidence),
            ),
        ),
    )


def metadata(*fields: ContextField, observed_at: datetime = NOW) -> ContextMetadata:
    return ContextMetadata(observed_at=observed_at, fields=fields)


def test_higher_confidence_value_wins_and_all_provenance_is_retained() -> None:
    generic = metadata(field("application", "generic-app", "xorg-generic", 0.55))
    qtile = metadata(field("application", "qtile-app", "qtile", 0.95))

    combined = compose_context_metadata(
        (generic, qtile),
        source_order=("qtile", "xorg-generic"),
    )

    assert combined.get("application") == "qtile-app"
    application = combined.fields[0]
    assert tuple(item.source_id for item in application.provenance) == (
        "qtile",
        "xorg-generic",
    )


def test_equal_confidence_uses_configured_source_order() -> None:
    qtile = metadata(field("workspace", "one", "qtile", 0.8))
    activitywatch = metadata(field("workspace", "two", "activitywatch", 0.8))

    combined = compose_context_metadata(
        (activitywatch, qtile),
        source_order=("qtile", "activitywatch"),
    )

    assert combined.get("workspace") == "one"


def test_equal_unranked_sources_use_newest_observation() -> None:
    later = NOW + timedelta(seconds=5)
    older = metadata(field("application", "older", "source-b", 0.8, NOW))
    newer = metadata(field("application", "newer", "source-a", 0.8, later))

    combined = compose_context_metadata((older, newer), source_order=())

    assert combined.get("application") == "newer"


def test_complete_tie_uses_stable_source_identifier() -> None:
    source_b = metadata(field("application", "from-b", "source-b", 0.8))
    source_a = metadata(field("application", "from-a", "source-a", 0.8))

    combined = compose_context_metadata((source_b, source_a), source_order=())

    assert combined.get("application") == "from-a"


def test_non_conflicting_fields_are_composed_in_stable_name_order() -> None:
    qtile = metadata(
        field("workspace", "two", "qtile", 0.9),
        field("window.title", "synthetic title", "qtile", 0.9),
    )
    activitywatch = metadata(field("application", "synthetic-app", "activitywatch", 0.7))

    combined = compose_context_metadata(
        (qtile, activitywatch),
        source_order=("qtile", "activitywatch"),
    )

    assert tuple(item.name for item in combined.fields) == (
        "application",
        "window.title",
        "workspace",
    )


def test_combined_observation_time_is_latest_source_time() -> None:
    later = NOW + timedelta(seconds=5)
    first = metadata(field("workspace", "one", "qtile", 0.9), observed_at=NOW)
    second = metadata(
        field("application", "app", "activitywatch", 0.9, later),
        observed_at=later,
    )

    combined = compose_context_metadata(
        (first, second),
        source_order=("qtile", "activitywatch"),
    )

    assert combined.observed_at == later


def test_empty_context_collection_is_rejected() -> None:
    try:
        compose_context_metadata((), source_order=())
    except ValueError as error:
        assert str(error) == "at least one metadata result is required"
    else:
        raise AssertionError("empty metadata collection must be rejected")
