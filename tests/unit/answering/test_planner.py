import importlib
from datetime import UTC, datetime

planner = importlib.import_module("local_recall.answering.planner")


def test_plan_question_resolves_saturday_and_preserves_concept_query() -> None:
    plan = planner.plan_answer_query(
        "What was I doing Saturday?",
        now=datetime(2026, 8, 24, 15, 30, tzinfo=UTC),
        timezone="America/New_York",
    )

    assert plan.retrieval_query.time_range.start_at == datetime(
        2026,
        8,
        22,
        4,
        0,
        tzinfo=UTC,
    )
    assert plan.retrieval_query.time_range.end_at == datetime(
        2026,
        8,
        23,
        4,
        0,
        tzinfo=UTC,
    )
    assert plan.retrieval_query.semantic_text == "What was I doing?"
    assert plan.resolved_time_expression == "Saturday"


def test_plan_question_extracts_explicit_application_and_workspace_filters() -> None:
    plan = planner.plan_answer_query(
        "What did I do yesterday in app Emacs in workspace research?",
        now=datetime(2026, 8, 24, 15, 30, tzinfo=UTC),
        timezone="America/New_York",
    )

    assert plan.retrieval_query.application == "Emacs"
    assert plan.retrieval_query.workspace == "research"
    assert plan.retrieval_query.semantic_text == "What did I do?"
    assert plan.resolved_time_expression == "yesterday"


def test_plan_question_rejects_missing_or_ambiguous_time_scope() -> None:
    for question in (
        "What was I doing?",
        "What was I doing Saturday and Sunday?",
    ):
        try:
            planner.plan_answer_query(
                question,
                now=datetime(2026, 8, 24, 15, 30, tzinfo=UTC),
                timezone="America/New_York",
            )
        except ValueError as exc:
            assert "answer question requires one time scope" in str(exc)
        else:
            raise AssertionError("expected deterministic planning failure")


def test_planned_query_repr_does_not_expose_question_text() -> None:
    plan = planner.plan_answer_query(
        "What was I doing Saturday?",
        now=datetime(2026, 8, 24, 15, 30, tzinfo=UTC),
        timezone="America/New_York",
    )

    assert "What was I doing" not in repr(plan)
    assert "Saturday" not in repr(plan)
