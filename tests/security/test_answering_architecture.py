from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from local_recall.answering.models import (
    AnswerCitation,
    AnswerClaim,
    AnswerClaimKind,
    AnswerMode,
    CitedAnswer,
)
from local_recall.answering.planner import plan_answer_query

_ANSWERING_ROOT = Path("src/local_recall/answering")
_FORBIDDEN_PREFIXES = (
    "local_recall.capture",
    "local_recall.lifecycle",
    "local_recall.storage",
    "local_recall.providers.remote",
    "local_recall.providers.remote_client",
)


def test_answering_source_has_no_capture_lifecycle_storage_or_remote_transport_imports() -> None:
    imported: set[str] = set()

    for path in _ANSWERING_ROOT.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module)

    offenders = sorted(
        module
        for module in imported
        if any(
            module == prefix or module.startswith(f"{prefix}.") for prefix in _FORBIDDEN_PREFIXES
        )
    )
    assert offenders == []


def test_answering_reprs_do_not_expose_question_or_generated_claim_text() -> None:
    secret_question = "What was I doing Saturday with PRIVATE-QUESTION-9f2c?"
    secret_claim = "PRIVATE-CLAIM-6d31"
    planned = plan_answer_query(
        secret_question,
        now=datetime(2026, 8, 24, 15, 30, tzinfo=UTC),
        timezone="America/New_York",
    )
    claim = AnswerClaim(
        kind=AnswerClaimKind.INFERENCE,
        text=secret_claim,
        citations=(
            AnswerCitation(
                record_id=UUID("00000000-0000-0000-0000-000000000501"),
                captured_at=datetime(2026, 8, 22, 14, 0, tzinfo=UTC),
            ),
        ),
    )
    answer = CitedAnswer(
        mode=AnswerMode.CONCISE,
        claims=(claim,),
        insufficient_evidence=False,
        policy_revision="policy-v1",
    )

    rendered = repr(planned) + repr(answer) + repr(claim)
    assert "PRIVATE-QUESTION-9f2c" not in rendered
    assert secret_claim not in rendered
