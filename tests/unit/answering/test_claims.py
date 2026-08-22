from __future__ import annotations

from importlib import import_module


EXPECTED_SYMBOLS = (
    "AnswerCitation",
    "AnswerClaim",
    "AnswerClaimKind",
    "AnswerMode",
    "CitedAnswer",
)


def test_answering_models_expose_typed_claim_contract() -> None:
    module = import_module("local_recall.answering.models")

    missing = tuple(name for name in EXPECTED_SYMBOLS if not hasattr(module, name))
    assert missing == ()
