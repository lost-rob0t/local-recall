"""Optional GPG recipient encryption for portable export archives."""

from __future__ import annotations

import asyncio
import shutil

from local_recall.backup.archive import RestoreFailure

_GPG_TIMEOUT_SECONDS = 60


class GpgUnavailable(RuntimeError):
    """Sanitized failure when the gpg executable is missing."""


class GpgRecipientCrypter:
    """Encrypt archive bytes to one recipient; decrypt on restore.

    Strict argument lists, no shell, bounded timeout, and no passphrase or
    key material ever touches the archive or logs.
    """

    def __init__(self, *, recipient: str, gnupg_home: str | None = None) -> None:
        if not recipient:
            raise ValueError("gpg recipient must not be empty")
        self._recipient = recipient
        self._gnupg_home = gnupg_home

    def __repr__(self) -> str:
        return "GpgRecipientCrypter(recipient=redacted)"

    def _binary(self) -> str:
        binary = shutil.which("gpg")
        if binary is None:
            raise GpgUnavailable("gpg executable is unavailable")
        return binary

    def _base_args(self) -> list[str]:
        args = [self._binary(), "--batch", "--no-tty", "--yes"]
        if self._gnupg_home is not None:
            args.extend(("--homedir", self._gnupg_home))
        return args

    async def encrypt(self, data: bytes) -> bytes:
        process = await asyncio.create_subprocess_exec(
            *self._base_args(),
            "--trust-model",
            "always",
            "--recipient",
            self._recipient,
            "--output",
            "-",
            "--encrypt",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _stderr = await _communicate(process, data)
        return stdout

    async def decrypt(self, data: bytes) -> bytes:
        process = await asyncio.create_subprocess_exec(
            *self._base_args(),
            "--output",
            "-",
            "--decrypt",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _stderr = await _communicate(process, data)
        return stdout


async def _communicate(process, data: bytes) -> tuple[bytes, bytes]:
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(input=data), timeout=_GPG_TIMEOUT_SECONDS
        )
    except TimeoutError as exc:
        process.kill()
        raise RestoreFailure("gpg operation timed out") from exc
    if process.returncode != 0:
        raise RestoreFailure("gpg operation failed")
    return stdout, stderr
