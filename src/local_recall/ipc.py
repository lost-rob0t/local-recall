"""Owner-only local IPC security primitives."""

from __future__ import annotations

import stat
from dataclasses import dataclass
from pathlib import Path


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
        if not runtime_dir.is_absolute():
            raise IpcSecurityError("runtime-dir-absolute")

        try:
            metadata = runtime_dir.lstat()
        except OSError:
            raise IpcSecurityError("runtime-dir-unavailable") from None

        if stat.S_ISLNK(metadata.st_mode):
            raise IpcSecurityError("runtime-dir-symlink")
        if not stat.S_ISDIR(metadata.st_mode):
            raise IpcSecurityError("runtime-dir-type")
        if metadata.st_uid != expected_uid:
            raise IpcSecurityError("runtime-dir-owner")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise IpcSecurityError("runtime-dir-mode")

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
