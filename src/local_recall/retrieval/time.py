from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from local_recall.domain._validation import require_aware

_DURATION_PATTERN = re.compile(
    r"\blast ([1-9][0-9]{0,3}) (minute|minutes|hour|hours|day|days)\b",
    re.IGNORECASE,
)
_DATE_PATTERN = re.compile(r"\b[0-9]{4}-[0-9]{2}-[0-9]{2}\b")
_WEEKDAYS = {
    "monday": 0,
    "tuesday": 1,
    "wednesday": 2,
    "thursday": 3,
    "friday": 4,
    "saturday": 5,
    "sunday": 6,
}
_WEEKDAY_PATTERN = re.compile(r"\b(" + "|".join(_WEEKDAYS) + r")\b", re.IGNORECASE)
_DIRECTIONAL_WEEKDAY_PATTERN = re.compile(
    r"\b(?:last|next|this)\s+(?:" + "|".join(_WEEKDAYS) + r")\b",
    re.IGNORECASE,
)
_RELATIVE_DAY_PATTERN = re.compile(r"\b(today|yesterday)\b", re.IGNORECASE)


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

    selector = _extract_selector(normalized)
    return _resolve_selector(selector, now=now, zone=zone)


def _extract_selector(expression: str) -> str:
    if _DIRECTIONAL_WEEKDAY_PATTERN.search(expression) is not None:
        raise ValueError("unsupported time expression")

    exact = _exact_selector(expression)
    if exact is not None:
        return exact

    candidates: list[tuple[int, int, str]] = []
    for pattern in (_DURATION_PATTERN, _DATE_PATTERN, _RELATIVE_DAY_PATTERN, _WEEKDAY_PATTERN):
        for match in pattern.finditer(expression):
            candidates.append((match.start(), match.end(), match.group(0).casefold()))

    candidates.sort()
    non_overlapping: list[tuple[int, int, str]] = []
    for candidate in candidates:
        if non_overlapping and candidate[0] < non_overlapping[-1][1]:
            continue
        non_overlapping.append(candidate)
    if len(non_overlapping) != 1:
        raise ValueError("unsupported or ambiguous time expression")
    return non_overlapping[0][2]


def _exact_selector(expression: str) -> str | None:
    if expression in {"today", "yesterday", *_WEEKDAYS}:
        return expression
    if _DATE_PATTERN.fullmatch(expression) is not None:
        return expression
    if _DURATION_PATTERN.fullmatch(expression) is not None:
        return expression
    return None


def _resolve_selector(selector: str, *, now: datetime, zone: ZoneInfo) -> ResolvedTimeRange:
    local_now = now.astimezone(zone)
    if selector == "today":
        return _calendar_day(local_now.date(), zone)
    if selector == "yesterday":
        return _calendar_day(local_now.date() - timedelta(days=1), zone)
    if selector in _WEEKDAYS:
        days_ago = (local_now.weekday() - _WEEKDAYS[selector]) % 7
        return _calendar_day(local_now.date() - timedelta(days=days_ago), zone)
    if _DATE_PATTERN.fullmatch(selector) is not None:
        try:
            explicit_day = date.fromisoformat(selector)
        except ValueError as exc:
            raise ValueError("unsupported time expression") from exc
        return _calendar_day(explicit_day, zone)

    duration = _DURATION_PATTERN.fullmatch(selector)
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
