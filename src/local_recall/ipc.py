"""Owner-only local IPC security primitives."""

from __future__ import annotations

import hmac
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar


class IpcSecurityError(RuntimeError):
    """Fixed, content-free IPC security failure."""


@dataclass(frozen=True, slots=True, repr=False)
class IpcPaths:
    """Validated owner-only runtime paths for Local Recall IPC."""

    runtime_dir: Path
    service_dir: Path
    socket_path: Path
    token_path: Path

    @classmethod
    def from_runtime_dir(cls, runtime_dir: Path, *, expected_uid: int) -> IpcPaths:
        """Validate an XDG-style runtime directory without following symlinks."""
        _validate_directory(
            runtime_dir,
            expected_uid=expected_uid,
            expected_mode=0o700,
            prefix="runtime-dir",
        )
        service_dir = runtime_dir / "local-recall"
        return cls(
            runtime_dir=runtime_dir,
            service_dir=service_dir,
            socket_path=service_dir / "control.sock",
            token_path=service_dir / "session.token",
        )

    def __repr__(self) -> str:
        return (
            "IpcPaths(runtime_dir=<private>, service_dir=<private>, "
            "socket_path=<private>, token_path=<private>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class SessionToken:
    """Fixed-size daemon-session authentication token."""

    BYTE_LENGTH: ClassVar[int] = 32
    _value: bytes

    def __post_init__(self) -> None:
        if len(self._value) != self.BYTE_LENGTH:
            raise IpcSecurityError("token-length")

    @classmethod
    def generate(cls) -> SessionToken:
        return cls(secrets.token_bytes(cls.BYTE_LENGTH))

    def frame(self) -> bytes:
        """Return token bytes only for the authenticated transport frame."""
        return self._value

    def matches(self, candidate: bytes) -> bool:
        """Compare authentication material without data-dependent early exit."""
        return hmac.compare_digest(self._value, candidate)

    def __repr__(self) -> str:
        return "SessionToken(<secret>)"


@dataclass(frozen=True, slots=True, repr=False)
class IpcCredentialStore:
    """Create, rotate, and load owner-only daemon session credentials."""

    paths: IpcPaths
    expected_uid: int

    def initialize(self) -> SessionToken:
        """Create the service directory and rotate authentication on daemon start."""
        self._ensure_service_dir()
        self._remove_existing_token()
        token = SessionToken.generate()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.paths.token_path, flags, 0o600)
        except OSError:
            raise IpcSecurityError("token-create") from None
        try:
            os.fchmod(descriptor, 0o600)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != self.expected_uid:
                raise IpcSecurityError("token-owner")
            _write_all(descriptor, token.frame())
        except OSError:
            raise IpcSecurityError("token-write") from None
        finally:
            os.close(descriptor)
        return self.load()

    def load(self) -> SessionToken:
        """Load an exact owner-only token without following replacement symlinks."""
        self._validate_service_dir()
        before = _token_metadata(self.paths.token_path, expected_uid=self.expected_uid)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.paths.token_path, flags)
        except OSError:
            raise IpcSecurityError("token-open") from None
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise IpcSecurityError("token-replaced")
            if not stat.S_ISREG(opened.st_mode) or opened.st_uid != self.expected_uid:
                raise IpcSecurityError("token-owner")
            if stat.S_IMODE(opened.st_mode) != 0o600:
                raise IpcSecurityError("token-mode")
            value = os.read(descriptor, SessionToken.BYTE_LENGTH + 1)
        except OSError:
            raise IpcSecurityError("token-read") from None
        finally:
            os.close(descriptor)
        return SessionToken(value)

    def _ensure_service_dir(self) -> None:
        try:
            self.paths.service_dir.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError:
            raise IpcSecurityError("service-dir-create") from None
        self._validate_service_dir()

    def _validate_service_dir(self) -> None:
        _validate_directory(
            self.paths.service_dir,
            expected_uid=self.expected_uid,
            expected_mode=0o700,
            prefix="service-dir",
        )

    def _remove_existing_token(self) -> None:
        try:
            self.paths.token_path.lstat()
        except FileNotFoundError:
            return
        except OSError:
            raise IpcSecurityError("token-unavailable") from None
        _token_metadata(self.paths.token_path, expected_uid=self.expected_uid)
        try:
            self.paths.token_path.unlink()
        except OSError:
            raise IpcSecurityError("token-remove") from None

    def __repr__(self) -> str:
        return "IpcCredentialStore(paths=<private>, expected_uid=<uid>)"


def _validate_directory(
    path: Path,
    *,
    expected_uid: int,
    expected_mode: int,
    prefix: str,
) -> os.stat_result:
    if not path.is_absolute():
        raise IpcSecurityError(f"{prefix}-absolute")
    try:
        metadata = path.lstat()
    except OSError:
        raise IpcSecurityError(f"{prefix}-unavailable") from None
    if stat.S_ISLNK(metadata.st_mode):
        raise IpcSecurityError(f"{prefix}-symlink")
    if not stat.S_ISDIR(metadata.st_mode):
        raise IpcSecurityError(f"{prefix}-type")
    if metadata.st_uid != expected_uid:
        raise IpcSecurityError(f"{prefix}-owner")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise IpcSecurityError(f"{prefix}-mode")
    return metadata


def _token_metadata(path: Path, *, expected_uid: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError:
        raise IpcSecurityError("token-unavailable") from None
    if stat.S_ISLNK(metadata.st_mode):
        raise IpcSecurityError("token-symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise IpcSecurityError("token-type")
    if metadata.st_uid != expected_uid:
        raise IpcSecurityError("token-owner")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise IpcSecurityError("token-mode")
    return metadata


def _write_all(descriptor: int, value: bytes) -> None:
    written = 0
    while written < len(value):
        count = os.write(descriptor, value[written:])
        if count <= 0:
            raise IpcSecurityError("token-write")
        written += count
