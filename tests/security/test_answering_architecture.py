from __future__ import annotations

import ast
from pathlib import Path

from local_recall.answering.models import AnswerClaim, AnswerClaimKind, AnswerMode, CitedAnswer
from local_recall.answering.service import AnsweringService
from local_recall.routing import RoutingMode, RoutingPolicy

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
        if any(module == prefix or module.startswith(f"{prefix}.") for prefix in _FORBIDDEN_PREFIXES)
    )
    assert offenders == []


def test_answering_reprs_do_not_expose_question_or_generated_claim_text() -> None:
    secret_question = "what happened with PRIVATE-QUESTION-9f2c?"
    secret_claim = "PRIVATE-CLAIM-6d31"
    claim = AnswerClaim(
        kind=AnswerClaimKind.INFERENCE,
        text=secret_claim,
        citations=(),
    )
    answer = CitedAnswer(
        mode=AnswerMode.CONCISE,
        claims=(claim,),
        insufficient_evidence=False,
        policy_revision="policy-v1",
    )

    class Retrieval:
        async def retrieve(self, query: object) -> object:
            del query
            raise AssertionError(secret_question)

    service = AnsweringService(
        retrieval=Retrieval(),  # type: ignore[arg-type]
        routing=RoutingPolicy(RoutingMode.LOCAL_ONLY),
        local_providers=(object(),),  # type: ignore[arg-type]
    )

    rendered = repr(answer) + repr(claim) + repr(service)
    assert secret_question not in rendered
    assert secret_claim not in rendered
