from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import PurePath
from typing import Protocol, runtime_checkable

from local_recall.domain.crypto import KeyHandle, KeyRequest

from .errors import (
    AuthenticationFailed,
    EnvelopeFormatError,
    KeyProviderUnavailable,
    RotationError,
)
from .models import KeyDestructionResult, KeyProviderHealth, KeyProviderState
from .primitives import digest
from .provider_shared import KEY_BYTES, require_provider, require_reference

_GPG_MAGIC = b"LRGPG\x01"
_MAX_GPG_OUTPUT_BYTES = 1024 * 1024


class CommandResult(Protocol):
    returncode: int
    stdout: bytes


@runtime_checkable
class CommandRunner(Protocol):
    def __call__(
        self, args: list[str], *, input: bytes | None, timeout: float
    ) -> CommandResult: ...


@dataclass(frozen=True, slots=True)
class _CommandOutput:
    returncode: int
    stdout: bytes


class _AsyncioCommandRunner:
    def __call__(self, args: list[str], *, input: bytes | None, timeout: float) -> _CommandOutput:
        return asyncio.run(self._run(tuple(args), input, timeout))

    async def _run(
        self, args: tuple[str, ...], input_bytes: bytes | None, timeout: float
    ) -> _CommandOutput:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=_MAX_GPG_OUTPUT_BYTES,
        )
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(input_bytes), timeout)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise
        if len(stdout) > _MAX_GPG_OUTPUT_BYTES:
            raise RuntimeError("GPG output limit exceeded")
        return _CommandOutput(process.returncode or 0, stdout)


class GPGKeyProvider:
    def __init__(
        self,
        *,
        executable: str = "gpg",
        timeout_seconds: float = 10.0,
        runner: CommandRunner | None = None,
    ) -> None:
        if PurePath(executable).name != "gpg" or any(char in executable for char in "\x00\n\r"):
            raise ValueError("GPG executable must resolve to the gpg binary")
        if timeout_seconds <= 0:
            raise ValueError("GPG timeout must be positive")
        self._executable = executable
        self._timeout = timeout_seconds
        self._runner = runner or _AsyncioCommandRunner()

    @property
    def provider_id(self) -> str:
        return "gpg"

    def health_check(self) -> KeyProviderHealth:
        try:
            result = self._runner(
                [self._executable, "--batch", "--no-tty", "--version"],
                input=None,
                timeout=self._timeout,
            )
        except Exception:
            return KeyProviderHealth(
                self.provider_id, KeyProviderState.UNAVAILABLE, "gpg_unavailable"
            )
        state = KeyProviderState.HEALTHY if result.returncode == 0 else KeyProviderState.UNAVAILABLE
        code = "healthy" if state is KeyProviderState.HEALTHY else "gpg_unavailable"
        return KeyProviderHealth(self.provider_id, state, code)

    def active_key(self, request: KeyRequest) -> KeyHandle:
        reference = require_reference(request)
        self._require_healthy()
        result = self._runner(
            [
                self._executable,
                "--batch",
                "--no-tty",
                "--with-colons",
                "--list-keys",
                reference,
            ],
            input=None,
            timeout=self._timeout,
        )
        if result.returncode != 0:
            raise KeyProviderUnavailable("gpg_recipient_unavailable")
        return KeyHandle(reference, self.provider_id, 1)

    def wrap_data_key(self, key: KeyHandle, data_key: bytes, associated_data: bytes) -> bytes:
        require_provider(key, self.provider_id)
        self._require_healthy()
        payload = _GPG_MAGIC + digest(associated_data) + data_key
        result = self._runner(
            [
                self._executable,
                "--batch",
                "--yes",
                "--no-tty",
                "--trust-model",
                "always",
                "--encrypt",
                "--recipient",
                key.key_id,
                "--output",
                "-",
            ],
            input=payload,
            timeout=self._timeout,
        )
        if result.returncode != 0 or not result.stdout:
            raise KeyProviderUnavailable("gpg_encrypt_failed")
        return bytes(result.stdout)

    def unwrap_data_key(
        self, key: KeyHandle, wrapped_data_key: bytes, associated_data: bytes
    ) -> bytearray:
        require_provider(key, self.provider_id)
        self._require_healthy()
        result = self._runner(
            [self._executable, "--batch", "--yes", "--no-tty", "--decrypt", "--output", "-"],
            input=wrapped_data_key,
            timeout=self._timeout,
        )
        if result.returncode != 0:
            raise AuthenticationFailed("gpg_decrypt_failed")
        expected_prefix = _GPG_MAGIC + digest(associated_data)
        if not result.stdout.startswith(expected_prefix):
            raise AuthenticationFailed("gpg_associated_data_mismatch")
        key_bytes = result.stdout[len(expected_prefix) :]
        if len(key_bytes) != KEY_BYTES:
            raise EnvelopeFormatError("gpg_data_key_length_invalid")
        return bytearray(key_bytes)

    def rotate(self, current: KeyHandle, reason_code: str) -> KeyHandle:
        del current, reason_code
        raise RotationError("gpg_rotation_requires_new_recipient")

    def destroy(self, key: KeyHandle, reason_code: str) -> KeyDestructionResult:
        del reason_code
        require_provider(key, self.provider_id)
        return KeyDestructionResult(key, False)

    def _require_healthy(self) -> None:
        if not self.health_check().healthy:
            raise KeyProviderUnavailable("gpg_unavailable")
