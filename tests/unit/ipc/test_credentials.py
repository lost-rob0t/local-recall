from __future__ import annotations

import stat
from collections.abc import Callable
from pathlib import Path

from local_recall.ipc import IpcCredentialStore, IpcPaths, IpcSecurityError, SessionToken


def _paths(tmp_path: Path) -> IpcPaths:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    runtime_dir.chmod(0o700)
    return IpcPaths.from_runtime_dir(runtime_dir, expected_uid=runtime_dir.stat().st_uid)


def _expect_security_error(code: str, action: Callable[[], object]) -> None:
    try:
        action()
    except IpcSecurityError as exc:
        assert str(exc) == code
    else:
        raise AssertionError(f"expected {code}")


def test_initialize_creates_owner_only_service_dir_and_rotating_token(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    store = IpcCredentialStore(paths=paths, expected_uid=paths.runtime_dir.stat().st_uid)

    first = store.initialize()
    first_bytes = paths.token_path.read_bytes()
    second = store.initialize()
    second_bytes = paths.token_path.read_bytes()

    assert isinstance(first, SessionToken)
    assert isinstance(second, SessionToken)
    assert first != second
    assert first_bytes != second_bytes
    assert len(first_bytes) == SessionToken.BYTE_LENGTH
    assert stat.S_IMODE(paths.service_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths.token_path.stat().st_mode) == 0o600


def test_load_rejects_group_readable_token(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    store = IpcCredentialStore(paths=paths, expected_uid=paths.runtime_dir.stat().st_uid)
    store.initialize()
    paths.token_path.chmod(0o640)

    _expect_security_error("token-mode", store.load)


def test_load_rejects_token_symlink(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.service_dir.mkdir(mode=0o700)
    target = tmp_path / "outside-token"
    target.write_bytes(b"x" * SessionToken.BYTE_LENGTH)
    paths.token_path.symlink_to(target)
    store = IpcCredentialStore(paths=paths, expected_uid=paths.runtime_dir.stat().st_uid)

    _expect_security_error("token-symlink", store.load)


def test_load_rejects_wrong_length_token(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.service_dir.mkdir(mode=0o700)
    paths.token_path.write_bytes(b"short")
    paths.token_path.chmod(0o600)
    store = IpcCredentialStore(paths=paths, expected_uid=paths.runtime_dir.stat().st_uid)

    _expect_security_error("token-length", store.load)


def test_token_repr_never_contains_secret_bytes() -> None:
    secret = b"SYNTHETIC-IPC-TOKEN-SECRET-12345"
    token = SessionToken(secret)

    assert secret.decode() not in repr(token)
