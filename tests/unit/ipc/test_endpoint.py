from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from local_recall.ipc import IpcPaths, IpcSecurityError


def _runtime_dir(tmp_path: Path) -> Path:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    runtime_dir.chmod(0o700)
    return runtime_dir


def _expect_security_error(code: str, action: Callable[[], object]) -> None:
    try:
        action()
    except IpcSecurityError as exc:
        assert str(exc) == code
    else:
        raise AssertionError(f"expected {code}")


def test_ipc_paths_use_owner_only_runtime_directory(tmp_path: Path) -> None:
    runtime_dir = _runtime_dir(tmp_path)

    paths = IpcPaths.from_runtime_dir(runtime_dir, expected_uid=runtime_dir.stat().st_uid)

    assert paths.runtime_dir == runtime_dir
    assert paths.socket_path == runtime_dir / "local-recall" / "control.sock"
    assert paths.token_path == runtime_dir / "local-recall" / "session.token"


def test_ipc_paths_reject_group_accessible_runtime_directory(tmp_path: Path) -> None:
    runtime_dir = _runtime_dir(tmp_path)
    runtime_dir.chmod(0o750)

    _expect_security_error(
        "runtime-dir-mode",
        lambda: IpcPaths.from_runtime_dir(runtime_dir, expected_uid=runtime_dir.stat().st_uid),
    )


def test_ipc_paths_reject_relative_runtime_directory() -> None:
    _expect_security_error(
        "runtime-dir-absolute",
        lambda: IpcPaths.from_runtime_dir(Path("runtime"), expected_uid=0),
    )


def test_ipc_paths_reject_symlink_runtime_directory(tmp_path: Path) -> None:
    runtime_dir = _runtime_dir(tmp_path)
    link = tmp_path / "runtime-link"
    link.symlink_to(runtime_dir, target_is_directory=True)

    _expect_security_error(
        "runtime-dir-symlink",
        lambda: IpcPaths.from_runtime_dir(link, expected_uid=runtime_dir.stat().st_uid),
    )
