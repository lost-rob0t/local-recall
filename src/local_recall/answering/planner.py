"""Deterministic question-to-retrieval planning."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from local_recall.domain._validation import require_aware, require_nonempty
from local_recall.retrieval.service import RetrievalQuery
from local_recall.retrieval.time import resolve_time_range

_WEEKDAYS = "monday|tuesday|wednesday|thursday|friday|saturday|sunday"
_TIME_SELECTOR = re.compile(
    rf"\b(?:today|yesterday|{_WEEKDAYS}|[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}|"
    r"last [1-9][0-9]{0,3} (?:minute|minutes|hour|hours|day|days))\b",
    re.IGNORECASE,
)
_APPLICATION_SELECTOR = re.compile(
    r"\bin app (?P<value>[A-Za-z0-9_.-]{1,64})(?=\s+in workspace\b|[?.!,]|$)",
    re.IGNORECASE,
)
_WORKSPACE_SELECTOR = re.compile(
    r"\bin workspace (?P<value>[A-Za-z0-9_.-]{1,64})(?=[?.!,]|$)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True, repr=False)
class PlannedAnswerQuery:
    """One bounded retrieval query derived from a user question."""

    retrieval_query: RetrievalQuery
    resolved_time_expression: str

    def __post_init__(self) -> None:
        require_nonempty(self.resolved_time_expression, "resolved_time_expression")

    def __repr__(self) -> str:
        query = self.retrieval_query
        return (
            "PlannedAnswerQuery("
            f"query_id={query.query_id!r}, "
            f"application_filter={query.application is not None}, "
            f"workspace_filter={query.workspace is not None}, "
            f"semantic_filter={query.semantic_text is not None})"
        )


def plan_answer_query(
    question: str,
    *,
    now: datetime,
    timezone: str,
) -> PlannedAnswerQuery:
    """Resolve one explicit question scope without model-directed widening."""

    require_nonempty(question, "question")
    require_nonempty(timezone, "timezone")
    require_aware(now, "now")

    time_matches = tuple(_TIME_SELECTOR.finditer(question))
    if len(time_matches) != 1:
        raise ValueError("answer question requires one time scope")
    time_match = time_matches[0]
    time_expression = time_match.group(0)

    application_match = _single_optional_match(_APPLICATION_SELECTOR, question, "application")
    workspace_match = _single_optional_match(_WORKSPACE_SELECTOR, question, "workspace")

    resolved_range = resolve_time_range(time_expression, now=now, timezone=timezone)
    semantic_text = _semantic_text(
        question,
        spans=tuple(
            span
            for span in (
                time_match.span(),
                application_match.span() if application_match is not None else None,
                workspace_match.span() if workspace_match is not None else None,
            )
            if span is not None
        ),
    )

    return PlannedAnswerQuery(
        retrieval_query=RetrievalQuery(
            time_range=resolved_range,
            application=(
                application_match.group("value") if application_match is not None else None
            ),
            workspace=workspace_match.group("value") if workspace_match is not None else None,
            semantic_text=semantic_text,
        ),
        resolved_time_expression=time_expression,
    )


def _single_optional_match(
    pattern: re.Pattern[str],
    question: str,
    selector_name: str,
) -> re.Match[str] | None:
    matches = tuple(pattern.finditer(question))
    if len(matches) > 1:
        raise ValueError(f"answer question has ambiguous {selector_name} scope")
    return matches[0] if matches else None


def _semantic_text(question: str, *, spans: tuple[tuple[int, int], ...]) -> str:
    chars = list(question)
    for start, end in spans:
        for index in range(start, end):
            chars[index] = " "
    normalized = " ".join("".join(chars).split())
    normalized = re.sub(r"\s+([?.!,])", r"\1", normalized)
    require_nonempty(normalized, "answer semantic text")
    return normalized
