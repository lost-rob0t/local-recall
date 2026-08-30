"""Bounded, content-free retention planning over canonical storage."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Protocol
from uuid import UUID

from local_recall.domain.crypto import EncryptedRecordEnvelope
from local_recall.domain.frames import RedactedRecord
from local_recall.ports.encryption import DecryptionRequest, EncryptionProvider
from local_recall.ports.storage import CatalogPage, StorageUsageReport

_MAX_DECRYPT_BUDGET = 10_000
_PAGE_LIMIT = 10_000
_CONTEXT_FIELDS = frozenset({"application", "workspace"})
_MAX_CONTEXT_VALUE_LENGTH = 256
_DAY = timedelta(days=1)


class RetentionStorage(Protocol):
    """Canonical storage surface required for retention planning."""

    async def stats(self) -> StorageUsageReport: ...

    async def page_ready(
        self,
        *,
        after_day: date | None = None,
        after_id: UUID | None = None,
        limit: int,
    ) -> CatalogPage: ...

    async def get(self, record_id: UUID) -> EncryptedRecordEnvelope | None: ...


class ScopeBudgetExceeded(RuntimeError):
    """Sanitized retention planning budget failure."""


@dataclass(frozen=True, slots=True)
class ContextRetentionRule:
    """Expire records carrying a named redacted context field sooner or later."""

    field_name: str
    value: str
    max_age_days: int

    def __post_init__(self) -> None:
        if self.field_name not in _CONTEXT_FIELDS:
            raise ValueError("retention context field is invalid")
        if not self.value or len(self.value) > _MAX_CONTEXT_VALUE_LENGTH:
            raise ValueError("retention context value has invalid length")
        if any(character in "\r\n\x00" or ord(character) < 0x20 for character in self.value):
            raise ValueError("retention context value contains invalid characters")
        if not 1 <= self.max_age_days <= 3650:
            raise ValueError("retention context age limit is invalid")

    def __repr__(self) -> str:
        return (
            "ContextRetentionRule("
            f"field_name={self.field_name!r}, value=<redacted>, "
            f"max_age_days={self.max_age_days})"
        )


@dataclass(frozen=True, slots=True)
class RetentionRules:
    """Closed retention policy: age, watermarks, record cap, context overrides."""

    max_age_days: int
    max_bytes: int
    max_records: int
    low_watermark_bytes: int | None = None
    context_rules: tuple[ContextRetentionRule, ...] = field(default=())

    def __post_init__(self) -> None:
        if not 1 <= self.max_age_days <= 3650:
            raise ValueError("retention age limit is invalid")
        if self.max_bytes <= 0 or self.max_records <= 0:
            raise ValueError("retention limits must be positive")
        low = self.low_watermark_bytes
        if low is None:
            object.__setattr__(self, "low_watermark_bytes", (self.max_bytes * 4) // 5)
        elif low > self.max_bytes:
            raise ValueError("retention low watermark must not exceed the high watermark")
        fields = tuple(rule.field_name for rule in self.context_rules)
        if len(set(fields)) != len(fields):
            raise ValueError("retention context fields must be unique")

    def __repr__(self) -> str:
        return (
            "RetentionRules("
            f"max_age_days={self.max_age_days}, max_bytes={self.max_bytes}, "
            f"max_records={self.max_records}, "
            f"low_watermark_bytes={self.low_watermark_bytes}, "
            f"context_rule_count={len(self.context_rules)})"
        )


@dataclass(frozen=True, slots=True)
class RetentionPlan:
    """Opaque record selection produced by one policy evaluation."""

    expired: tuple[UUID, ...]
    evicted: tuple[UUID, ...]
    reclaimed_bytes: int
    dry_run: bool

    def __post_init__(self) -> None:
        if self.reclaimed_bytes < 0:
            raise ValueError("reclaimed bytes must be non-negative")


@dataclass(frozen=True, slots=True)
class _Candidate:
    record_id: UUID
    day_bucket: date
    blob_bytes: int


class RetentionPlanner:
    """Evaluate the configured retention policy into opaque record IDs.

    Planning never exposes captured text. Context overrides are evaluated
    with decrypt-on-demand inside a bounded budget; budget exhaustion fails
    closed. Watermark eviction is oldest-first and never deletes records
    outside the configured policy.
    """

    def __init__(
        self,
        *,
        storage: RetentionStorage,
        encryption: EncryptionProvider | None,
        rules: RetentionRules,
        today: date,
        decrypt_budget: int = _MAX_DECRYPT_BUDGET,
    ) -> None:
        if not 1 <= decrypt_budget <= _MAX_DECRYPT_BUDGET:
            raise ValueError("retention decrypt budget is invalid")
        self._storage = storage
        self._encryption = encryption
        self._rules = rules
        self._today = today
        self._decrypt_budget = decrypt_budget

    def __repr__(self) -> str:
        return "RetentionPlanner(rules=configured, dependencies=redacted)"

    async def plan(self, *, dry_run: bool = False) -> RetentionPlan:
        global_cutoff = self._today - self._rules.max_age_days * _DAY
        rule_cutoffs = {
            rule: self._today - rule.max_age_days * _DAY for rule in self._rules.context_rules
        }
        floor_cutoff = min((global_cutoff, *rule_cutoffs.values()))
        ceil_cutoff = max((global_cutoff, *rule_cutoffs.values()))

        expired: list[UUID] = []
        candidates: list[_Candidate] = []
        decrypted = 0
        after_day: date | None = None
        after_id: UUID | None = None
        while True:
            page = await self._storage.page_ready(
                after_day=after_day,
                after_id=after_id,
                limit=_PAGE_LIMIT,
            )
            for entry in page.entries:
                candidate = _Candidate(entry.record_id, entry.day_bucket, entry.blob_bytes)
                candidates.append(candidate)
                if candidate.day_bucket < floor_cutoff:
                    expired.append(candidate.record_id)
                    continue
                if candidate.day_bucket >= ceil_cutoff:
                    continue
                decrypted += 1
                if decrypted > self._decrypt_budget:
                    raise ScopeBudgetExceeded("retention decrypt budget exceeded")
                if await self._expires_in_window(candidate, global_cutoff, rule_cutoffs):
                    expired.append(candidate.record_id)
            if page.complete:
                break
            last = page.entries[-1]
            after_day = last.day_bucket
            after_id = last.record_id

        evicted = self._eviction_set(candidates, expired)
        selected = frozenset((*expired, *evicted))
        return RetentionPlan(
            expired=tuple(expired),
            evicted=tuple(evicted),
            reclaimed_bytes=sum(
                candidate.blob_bytes for candidate in candidates if candidate.record_id in selected
            ),
            dry_run=dry_run,
        )

    def _eviction_set(
        self,
        candidates: list[_Candidate],
        expired: list[UUID],
    ) -> tuple[UUID, ...]:
        usage_bytes = sum(candidate.blob_bytes for candidate in candidates)
        overflow = max(len(candidates) - self._rules.max_records, 0)
        pressure = max(usage_bytes - self._rules.max_bytes, 0)
        if overflow == 0 and pressure == 0:
            return ()
        low = self._rules.low_watermark_bytes
        assert low is not None
        must_free = max(usage_bytes - low, 0) if pressure > 0 else 0
        evicted: list[UUID] = []
        freed = 0
        already = frozenset(expired)
        for candidate in candidates:
            if len(evicted) >= overflow and freed >= must_free:
                break
            if candidate.record_id in already:
                continue
            evicted.append(candidate.record_id)
            freed += candidate.blob_bytes
        return tuple(evicted)

    async def _expires_in_window(
        self,
        candidate: _Candidate,
        global_cutoff: date,
        rule_cutoffs: dict[ContextRetentionRule, date],
    ) -> bool:
        assert self._encryption is not None
        envelope = await self._storage.get(candidate.record_id)
        if envelope is None:
            return True
        record = await self._encryption.decrypt(DecryptionRequest(envelope, envelope.key))
        matched = [cutoff for rule, cutoff in rule_cutoffs.items() if _matches_rule(record, rule)]
        effective = max(matched) if matched else global_cutoff
        return candidate.day_bucket < effective


def _matches_rule(record: RedactedRecord, rule: ContextRetentionRule) -> bool:
    value = record.frame.metadata.get(rule.field_name)
    return isinstance(value, str) and value.casefold() == rule.value.casefold()
