from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime

from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
)


def compose_context_metadata(
    results: Iterable[ContextMetadata],
    *,
    source_order: tuple[str, ...],
) -> ContextMetadata:
    items = tuple(results)
    if not items:
        raise ValueError("at least one metadata result is required")
    if len(set(source_order)) != len(source_order):
        raise ValueError("metadata source order must be unique")

    rank = {source_id: index for index, source_id in enumerate(source_order)}
    fields_by_name: dict[str, list[ContextField]] = defaultdict(list)
    for item in items:
        for field in item.fields:
            fields_by_name[field.name].append(field)

    combined_fields = tuple(
        _combine_field(name, tuple(fields_by_name[name]), rank)
        for name in sorted(fields_by_name)
    )
    return ContextMetadata(
        observed_at=max(item.observed_at for item in items),
        fields=combined_fields,
    )


def _combine_field(
    name: str,
    candidates: tuple[ContextField, ...],
    rank: dict[str, int],
) -> ContextField:
    winner = min(candidates, key=lambda item: _winner_key(item, rank))
    provenance = _combined_provenance(candidates, rank)
    return ContextField(name=name, value=winner.value, provenance=provenance)


def _winner_key(field: ContextField, rank: dict[str, int]) -> tuple[float, int, float, str]:
    confidence = max(item.confidence.value for item in field.provenance)
    primary = min(
        field.provenance,
        key=lambda item: _provenance_key(item, rank),
    )
    latest = max(item.observed_at for item in field.provenance)
    return (
        -confidence,
        rank.get(primary.source_id, len(rank)),
        -latest.timestamp(),
        primary.source_id,
    )


def _combined_provenance(
    candidates: tuple[ContextField, ...],
    rank: dict[str, int],
) -> tuple[MetadataProvenance, ...]:
    unique: set[MetadataProvenance] = set()
    for field in candidates:
        unique.update(field.provenance)
    return tuple(sorted(unique, key=lambda item: _provenance_key(item, rank)))


def _provenance_key(
    provenance: MetadataProvenance,
    rank: dict[str, int],
) -> tuple[int, str, float, datetime]:
    return (
        rank.get(provenance.source_id, len(rank)),
        provenance.source_id,
        -provenance.confidence.value,
        provenance.observed_at,
    )
