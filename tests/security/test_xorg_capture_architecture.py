from __future__ import annotations

import ast
from pathlib import Path

_CAPTURE_MODULES = (
    Path("src/local_recall/capture/bus_portal.py"),
    Path("src/local_recall/capture/composition.py"),
    Path("src/local_recall/capture/native.py"),
    Path("src/local_recall/capture/png.py"),
    Path("src/local_recall/capture/portal.py"),
    Path("src/local_recall/capture/wayland.py"),
    Path("src/local_recall/capture/xorg.py"),
)
_FORBIDDEN_IMPORTS = ("tempfile", "PIL", "imageio")
_FORBIDDEN_CALLS = {"open", "mkstemp", "NamedTemporaryFile", "write_bytes", "write_text"}


def test_xorg_capture_modules_have_no_plaintext_artifact_capability() -> None:
    imports: set[str] = set()
    called_names: set[str] = set()

    for path in _CAPTURE_MODULES:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imports.add(node.module)
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    called_names.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    receiver = node.func.value
                    if (
                        isinstance(receiver, ast.Name)
                        and receiver.id == "os"
                        and node.func.attr == "open"
                    ):
                        continue
                    called_names.add(node.func.attr)

    assert not any(name.startswith(prefix) for name in imports for prefix in _FORBIDDEN_IMPORTS)
    assert called_names.isdisjoint(_FORBIDDEN_CALLS)
