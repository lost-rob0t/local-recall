from importlib import import_module


def test_answering_models_module_exists() -> None:
    module = import_module("local_recall.answering.models")

    assert module.__name__ == "local_recall.answering.models"
