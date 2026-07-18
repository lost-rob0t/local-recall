from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from local_recall.domain._validation import require_aware


@dataclass(frozen=True, slots=True)
class StorageQuota:
    max_bytes: int = 20 * 1024**3
    max_records: int = 250_000

    def __post_init__(self) -> None:
        if self.max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if self.max_records <= 0:
            raise ValueError("max_records must be positive")


@dataclass(frozen=True, slots=True)
class TimeRangeQuery:
    start_at: datetime
    end_at: datetime
    limit: int = 1_000

    def __post_init__(self) -> None:
        require_aware(self.start_at, "start_at")
        require_aware(self.end_at, "end_at")
        if self.end_at <= self.start_at:
            raise ValueError("end_at must be later than start_at")
        if not 1 <= self.limit <= 100_000:
            raise ValueError("limit must be between 1 and 100000")
