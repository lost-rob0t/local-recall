from __future__ import annotations

import ast
from pathlib import Path

import pykka

from local_recall.pipeline.actors import PipelineStageActor

_PIPELINE_ROOT = Path("src/local_recall/pipeline")


def test_pipeline_source_never_imports_pickle_or_filesystem_spooling_modules() -> None:
    forbidden = {"pickle", "shelve", "tempfile"}
    imported: set[str] = set()

    for path in _PIPELINE_ROOT.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module.split(".", maxsplit=1)[0])

    assert imported.isdisjoint(forbidden)


def test_pipeline_actor_registry_is_clean_after_tests() -> None:
    assert pykka.ActorRegistry.get_by_class(PipelineStageActor) == []
