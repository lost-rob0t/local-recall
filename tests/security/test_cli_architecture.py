from __future__ import annotations

import ast
import datetime as dt
from pathlib import Path

from local_recall.cli_contract import CliCommand, CliRequest

_CLI_SOURCES = (
    Path("src/local_recall/cli.py"),
    Path("src/local_recall/cli_contract.py"),
    Path("src/local_recall/cli_service.py"),
)
_FORBIDDEN_PREFIXES = (
    "local_recall.capture",
    "local_recall.lifecycle",
    "local_recall.storage",
    "local_recall.retrieval",
    "local_recall.answering",
    "local_recall.providers",
    "local_recall.routing",
)


def test_cli_boundary_has_no_daemon_authority_implementation_imports() -> None:
    imported: set[str] = set()

    for path in _CLI_SOURCES:
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


def test_query_content_never_enters_routing_metadata_or_repr() -> None:
    marker = "PRIVATE-CLI-QUERY-7f31"  # pragma: allowlist secret
    now = dt.datetime(2026, 8, 22, 21, 0, tzinfo=dt.UTC)
    request = CliRequest.create(
        command=CliCommand.ASK,
        now=now,
        deadline=now + dt.timedelta(seconds=2),
        query=marker,
    )

    assert marker not in request.routing_json()
    assert marker not in repr(request)
