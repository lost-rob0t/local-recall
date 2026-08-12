from __future__ import annotations

import ast
from pathlib import Path

_ACTIVITYWATCH_MODULES = (
    Path("src/local_recall/metadata/activitywatch.py"),
    Path("src/local_recall/metadata/activitywatch_client.py"),
    Path("src/local_recall/metadata/activitywatch_http.py"),
    Path("src/local_recall/metadata/activitywatch_types.py"),
)


def test_activitywatch_adapter_has_no_persistence_or_provider_imports() -> None:
    forbidden_prefixes = (
        "local_recall.storage",
        "local_recall.providers",
        "local_recall.audit",
        "local_recall.crypto",
    )
    imports: set[str] = set()

    for path in _ACTIVITYWATCH_MODULES:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imports.add(node.module)

    assert not any(name.startswith(prefix) for name in imports for prefix in forbidden_prefixes)
