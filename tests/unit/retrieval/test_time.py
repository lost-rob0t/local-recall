from __future__ import annotations

import importlib
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol, cast

import pytest


class _ResolvedTimeRange(Protocol):
    start_at: datetime
    end_at: datetime


type _Resolver = Callable[..., _ResolvedTimeRange]


def _resolver() -> _Resolver:
    module = importlib.import_module("local_recall.retrieval.time")
    return cast(_Resolver, module.__dict__["resolve_time_range"])


def test_weekday_resolves_to_most_recent_local_calendar_day() -> None:
    resolve = _resolver()
    now = datetime(2026, 8, 22, 14, 30, tzinfo=UTC)

    result = resolve("Saturday", now=now, timezone="America/New_York")

    assert result.start_at == datetime(2026, 8, 22, 4, 0, tzinfo=UTC)
    assert result.end_at == datetime(2026, 8, 23, 4, 0, tzinfo=UTC)


def test_question_extracts_one_unambiguous_weekday() -> None:
    resolve = _resolver()
    now = datetime(2026, 8, 22, 14, 30, tzinfo=UTC)

    result = resolve("What was I doing Saturday?", now=now, timezone="America/New_York")

    assert result.start_at == datetime(2026, 8, 22, 4, 0, tzinfo=UTC)
    assert result.end_at == datetime(2026, 8, 23, 4, 0, tzinfo=UTC)


def test_explicit_date_uses_dst_aware_local_midnight_boundaries() -> None:
    resolve = _resolver()
    now = datetime(2026, 3, 10, 12, 0, tzinfo=UTC)

    result = resolve("2026-03-08", now=now, timezone="America/New_York")

    assert result.start_at == datetime(2026, 3, 8, 5, 0, tzinfo=UTC)
    assert result.end_at == datetime(2026, 3, 9, 4, 0, tzinfo=UTC)


def test_last_hours_is_an_exact_instant_range() -> None:
    resolve = _resolver()
    now = datetime(2026, 8, 22, 14, 30, tzinfo=UTC)

    result = resolve("last 2 hours", now=now, timezone="America/New_York")

    assert result.start_at == datetime(2026, 8, 22, 12, 30, tzinfo=UTC)
    assert result.end_at == now


@pytest.mark.parametrize(
    "expression",
    ["", "someday", "next Saturday", "last zero hours", "Saturday or Sunday"],
)
def test_unknown_or_ambiguous_time_language_is_rejected(expression: str) -> None:
    resolve = _resolver()
    now = datetime(2026, 8, 22, 14, 30, tzinfo=UTC)

    with pytest.raises(ValueError, match="time expression"):
        resolve(expression, now=now, timezone="America/New_York")
