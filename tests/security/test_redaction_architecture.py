from __future__ import annotations

import ast
from pathlib import Path

_REDACTION_ROOT = Path("src/local_recall/redaction")
_FORBIDDEN_IMPORT_ROOTS = {
    "httpx",
    "pickle",
    "requests",
    "socket",
    "tempfile",
    "urllib3",
}
_FORBIDDEN_CALLS = {
    "NamedTemporaryFile",
    "mkstemp",
    "mkdtemp",
    "open",
    "write_bytes",
    "write_text",
}


def _python_sources() -> tuple[Path, ...]:
    return tuple(sorted(_REDACTION_ROOT.glob("*.py")))


def test_redaction_boundary_has_no_network_storage_or_temporary_file_dependency() -> None:
    violations: list[str] = []
    for path in _python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".", 1)[0] in _FORBIDDEN_IMPORT_ROOTS:
                        violations.append(f"{path}:{node.lineno}:import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".", 1)[0]
                if root in _FORBIDDEN_IMPORT_ROOTS or root == "storage":
                    violations.append(f"{path}:{node.lineno}:from {node.module}")
            elif isinstance(node, ast.Call):
                name = None
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name in _FORBIDDEN_CALLS:
                    violations.append(f"{path}:{node.lineno}:call {name}")

    assert violations == []


def test_ocr_subprocess_uses_exec_without_shell_or_file_arguments() -> None:
    source = (_REDACTION_ROOT / "tesseract.py").read_text(encoding="utf-8")

    assert "create_subprocess_exec" in source
    assert "create_subprocess_shell" not in source
    assert "NamedTemporaryFile" not in source
    assert '"stdin"' in source
    assert '"stdout"' in source
