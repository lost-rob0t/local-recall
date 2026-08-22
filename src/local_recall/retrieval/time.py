from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from local_recall.domain._validation import require_aware

_DURATION_PATTERN = re.compile(
    r"last ([1-9][0-9]{0,3}) (minute|minutes|hour|hours|day|days)",
    re.IGNORECASE,
)
_DATE_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_WEEKDAYS = {
    "monday": 0,
    "tuesday": 1,
    "wednesday": 2,
    "thursday": 3,
    "friday": 4,
    "saturday": 5,
    "sunday": 6,
}


@dataclass(frozen=True, slots=True)
class ResolvedTimeRange:
    start_at: datetime
    end_at: datetime

    def __post_init__(self) -> None:
        require_aware(self.start_at, "start_at")
        require_aware(self.end_at, "end_at")
        if self.end_at <= self.start_at:
            raise ValueError("time range end must be later than start")


def resolve_time_range(
    expression: str,
    *,
    now: datetime,
    timezone: str,
) -> ResolvedTimeRange:
    require_aware(now, "now")
    normalized = " ".join(expression.strip().casefold().split())
    if not normalized:
        raise ValueError("unsupported time expression")

    try:
        zone = ZoneInfo(timezone)
    except ZoneInfoNotFoundError as exc:
        raise ValueError("time expression timezone is unavailable") from exc

    local_now = now.astimezone(zone)
    if normalized == "today":
        return _calendar_day(local_now.date(), zone)
    if normalized == "yesterday":
        return _calendar_day(local_now.date() - timedelta(days=1), zone)
    if normalized in _WEEKDAYS:
        days_ago = (local_now.weekday() - _WEEKDAYS[normalized]) % 7
        return _calendar_day(local_now.date() - timedelta(days=days_ago), zone)
    if _DATE_PATTERN.fullmatch(normalized):
        try:
            explicit_day = date.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError("unsupported time expression") from exc
        return _calendar_day(explicit_day, zone)

    duration = _DURATION_PATTERN.fullmatch(normalized)
    if duration is not None:
        amount = int(duration.group(1))
        unit = duration.group(2).casefold()
        if unit.startswith("minute"):
            delta = timedelta(minutes=amount)
        elif unit.startswith("hour"):
            delta = timedelta(hours=amount)
        else:
            delta = timedelta(days=amount)
        end_at = now.astimezone(UTC)
        return ResolvedTimeRange(end_at - delta, end_at)

    raise ValueError("unsupported time expression")


def _calendar_day(day: date, zone: ZoneInfo) -> ResolvedTimeRange:
    start_local = datetime.combine(day, time.min, tzinfo=zone)
    end_local = datetime.combine(day + timedelta(days=1), time.min, tzinfo=zone)
    return ResolvedTimeRange(start_local.astimezone(UTC), end_local.astimezone(UTC))
