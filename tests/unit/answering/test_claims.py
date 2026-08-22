EXPECTED_SYMBOLS = (
    "AnswerCitation",
    "AnswerClaim",
    "AnswerClaimKind",
    "AnswerMode",
    "CitedAnswer",
)


def test_answering_models_expose_typed_claim_contract() -> None:
    module = __import__("local_recall.answering.models", fromlist=("*",))

    missing = tuple(name for name in EXPECTED_SYMBOLS if not hasattr(module, name))
    assert missing == ()
