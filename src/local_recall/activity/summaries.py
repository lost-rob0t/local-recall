from __future__ import annotations

import json
from dataclasses import dataclass
from typing import cast
from uuid import UUID

from local_recall.domain._validation import require_nonempty
from local_recall.domain.frames import RedactedRecord
from local_recall.domain.privacy import PrivacyClass, ProviderLocation
from local_recall.domain.providers import (
    GenerationRequest,
    GenerationRole,
    ModelCapability,
)
from local_recall.ports.providers import GenerationProvider

from .clustering import ActivityCluster

_MAX_RECORDS = 128
_MAX_EXCERPTS = 16
_MAX_EXCERPT_LENGTH = 1024
_MAX_OUTPUT_TOKENS = 256


class ActivitySummaryFailure(RuntimeError):
    """Sanitized failure while deriving an activity summary."""


@dataclass(frozen=True, slots=True, repr=False)
class ActivitySummary:
    text: str
    source_record_ids: tuple[UUID, ...]
    provider_id: str
    model_id: str

    def __post_init__(self) -> None:
        require_nonempty(self.text, "text")
        require_nonempty(self.provider_id, "provider_id")
        require_nonempty(self.model_id, "model_id")
        if not self.source_record_ids:
            raise ValueError("activity summary requires source records")
        if len(set(self.source_record_ids)) != len(self.source_record_ids):
            raise ValueError("activity summary source records must be unique")

    def __repr__(self) -> str:
        return (
            "ActivitySummary("
            f"source_count={len(self.source_record_ids)}, "
            "provider_id=redacted, model_id=redacted, text=redacted)"
        )


class ActivitySummarizer:
    __slots__ = ("_provider",)

    def __init__(self, provider: GenerationProvider) -> None:
        self._provider = provider

    def __repr__(self) -> str:
        return "ActivitySummarizer(provider=redacted)"

    async def summarize(
        self,
        cluster: ActivityCluster,
        records: tuple[RedactedRecord, ...],
    ) -> ActivitySummary:
        record_by_id = _validate_membership(cluster, records)
        capabilities = await self._provider.capabilities()
        if capabilities.location is not ProviderLocation.LOCAL:
            raise ActivitySummaryFailure("local generation provider required")
        if not capabilities.available:
            raise ActivitySummaryFailure("local generation provider unavailable")
        if ModelCapability.GENERATION not in capabilities.capabilities:
            raise ActivitySummaryFailure("generation capability required")
        if not capabilities.accepts(PrivacyClass.REDACTED_CONTENT):
            raise ActivitySummaryFailure("generation provider rejects redacted content")
        if not capabilities.supports_structured_output:
            raise ActivitySummaryFailure("structured generation output required")

        ordered_records = tuple(record_by_id[source_id] for source_id in cluster.source_record_ids)
        context = tuple(_record_text(record) for record in ordered_records)
        if any(not text for text in context):
            raise ActivitySummaryFailure("activity summary requires redacted text evidence")
        total_bytes = sum(len(text.encode("utf-8")) for text in context)
        if total_bytes > capabilities.max_input_bytes:
            raise ActivitySummaryFailure("activity summary input exceeds provider limit")

        response = await self._provider.generate(
            GenerationRequest(
                prompt=_summary_prompt(cluster.source_record_ids),
                context=context,
                privacy_class=PrivacyClass.REDACTED_CONTENT,
                max_output_tokens=_MAX_OUTPUT_TOKENS,
                role=GenerationRole.SUMMARIZATION,
            )
        )
        if response.provider_id != capabilities.provider_id:
            raise ActivitySummaryFailure("generation provider identity mismatch")

        evidence = _validate_evidence(response.text, record_by_id)
        return ActivitySummary(
            text="\n".join(excerpt for _, excerpt in evidence),
            source_record_ids=tuple(source_id for source_id, _ in evidence),
            provider_id=response.provider_id,
            model_id=response.model_id,
        )


def _validate_membership(
    cluster: ActivityCluster,
    records: tuple[RedactedRecord, ...],
) -> dict[UUID, RedactedRecord]:
    if not records:
        raise ActivitySummaryFailure("activity summary requires source records")
    if len(records) > _MAX_RECORDS:
        raise ActivitySummaryFailure("activity summary exceeds source record limit")
    record_by_id = {record.record_id: record for record in records}
    if len(record_by_id) != len(records):
        raise ActivitySummaryFailure("duplicate source records")
    if set(record_by_id) != set(cluster.source_record_ids):
        raise ActivitySummaryFailure("activity summary source membership mismatch")
    return record_by_id


def _record_text(record: RedactedRecord) -> str:
    return "\n".join(part for part in record.frame.ocr_text if part)


def _summary_prompt(source_ids: tuple[UUID, ...]) -> str:
    mapping = ",".join(str(source_id) for source_id in source_ids)
    return (
        "Use only evidence explicitly present in the corresponding redacted context. "
        "Return JSON with exactly one top-level key named evidence. evidence must be a non-empty "
        "array of objects with exactly source_id and excerpt. source_id must be one of these IDs "
        f"in the same order as the supplied context: {mapping}. excerpt must be a non-empty exact "
        "contiguous substring copied verbatim out of that source context. Do not infer, "
        "paraphrase, combine, reconstruct, or invent actions."
    )


def _validate_evidence(
    payload: str,
    record_by_id: dict[UUID, RedactedRecord],
) -> tuple[tuple[UUID, str], ...]:
    try:
        decoded_raw: object = json.loads(payload)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ActivitySummaryFailure("invalid activity summary output") from exc
    if not isinstance(decoded_raw, dict):
        raise ActivitySummaryFailure("invalid activity summary output")
    decoded = cast(dict[str, object], decoded_raw)
    if set(decoded) != {"evidence"}:
        raise ActivitySummaryFailure("invalid activity summary output")
    raw_evidence_obj = decoded["evidence"]
    if not isinstance(raw_evidence_obj, list):
        raise ActivitySummaryFailure("invalid activity summary output")
    raw_evidence = cast(list[object], raw_evidence_obj)
    if not 1 <= len(raw_evidence) <= _MAX_EXCERPTS:
        raise ActivitySummaryFailure("invalid activity summary output")

    evidence: list[tuple[UUID, str]] = []
    seen: set[UUID] = set()
    for raw_item in raw_evidence:
        if not isinstance(raw_item, dict):
            raise ActivitySummaryFailure("invalid activity summary output")
        item = cast(dict[str, object], raw_item)
        if set(item) != {"source_id", "excerpt"}:
            raise ActivitySummaryFailure("invalid activity summary output")
        source_text = item["source_id"]
        excerpt = item["excerpt"]
        if not isinstance(source_text, str) or not isinstance(excerpt, str):
            raise ActivitySummaryFailure("invalid activity summary output")
        try:
            source_id = UUID(source_text)
        except ValueError as exc:
            raise ActivitySummaryFailure("invalid activity summary output") from exc
        if source_id not in record_by_id or source_id in seen:
            raise ActivitySummaryFailure("invalid activity summary evidence")
        if not excerpt or len(excerpt) > _MAX_EXCERPT_LENGTH:
            raise ActivitySummaryFailure("invalid activity summary evidence")
        source_record_text = _record_text(record_by_id[source_id])
        if excerpt not in source_record_text:
            raise ActivitySummaryFailure("invalid activity summary evidence")
        seen.add(source_id)
        evidence.append((source_id, excerpt))
    return tuple(evidence)
