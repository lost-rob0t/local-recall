from __future__ import annotations

import asyncio
import hashlib
import secrets
from dataclasses import dataclass
from typing import Protocol

from local_recall.domain.crypto import KeyHandle, KeyRequest, SecretKeyMaterial
from local_recall.ports.keys import (
    KeyDestructionRequest,
    KeyDestructionResult,
    KeyHealthReport,
    KeyHealthStatus,
    KeyRotationRequest,
    KeyUnwrapRequest,
    KeyWrapRequest,
)

from .bindings import KEY_BYTES
from .errors import KeyProviderFailure, KeyProviderFailureCode


@dataclass(frozen=True, slots=True, repr=False)
class GPGCommandResult:
    returncode: int
    stdout: bytes


class GPGCommandRunner(Protocol):
    async def run(
        self,
        arguments: tuple[str, ...],
        input_data: bytes,
        timeout_seconds: float,
    ) -> GPGCommandResult: ...


class SubprocessGPGRunner:
    async def run(
        self,
        arguments: tuple[str, ...],
        input_data: bytes,
        timeout_seconds: float,
    ) -> GPGCommandResult:
        process = await asyncio.create_subprocess_exec(
            *arguments,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _stderr = await asyncio.wait_for(
                process.communicate(input_data),
                timeout=timeout_seconds,
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            raise
        return GPGCommandResult(process.returncode or 0, stdout)


class GPGKeyProvider:
    provider_id = "gpg"

    def __init__(
        self,
        recipient: str,
        *,
        runner: GPGCommandRunner | None = None,
        executable: str = "gpg",
        timeout_seconds: float = 10.0,
    ) -> None:
        if not recipient.strip():
            raise ValueError("GPG recipient must not be empty")
        if not executable.strip():
            raise ValueError("GPG executable must not be empty")
        if timeout_seconds <= 0:
            raise ValueError("GPG timeout must be positive")
        self._recipient = recipient
        self._runner = runner or SubprocessGPGRunner()
        self._executable = executable
        self._timeout_seconds = timeout_seconds

    async def health(self, request: KeyRequest) -> KeyHealthReport:
        del request
        try:
            result = await self._run(
                (
                    self._executable,
                    "--batch",
                    "--with-colons",
                    "--list-keys",
                    self._recipient,
                ),
                b"",
            )
        except KeyProviderFailure:
            return KeyHealthReport(self.provider_id, KeyHealthStatus.UNAVAILABLE)
        if result.returncode != 0 or not result.stdout:
            return KeyHealthReport(self.provider_id, KeyHealthStatus.UNAVAILABLE)
        return KeyHealthReport(
            self.provider_id,
            KeyHealthStatus.READY,
            self._handle(),
        )

    async def active_key(self, request: KeyRequest) -> KeyHandle:
        health = await self.health(request)
        if not health.ready or health.key is None:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.PROVIDER_UNAVAILABLE)
        return health.key

    async def wrap_data_key(self, request: KeyWrapRequest) -> bytes:
        self._validate_handle(request.key)
        payload = hashlib.sha256(request.associated_data).digest() + request.material.copy_bytes()
        result = await self._run(
            (
                self._executable,
                "--batch",
                "--yes",
                "--trust-model",
                "always",
                "--recipient",
                self._recipient,
                "--encrypt",
            ),
            payload,
        )
        if result.returncode != 0 or not result.stdout:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.PROVIDER_UNAVAILABLE)
        return result.stdout

    async def unwrap_data_key(self, request: KeyUnwrapRequest) -> SecretKeyMaterial:
        self._validate_handle(request.key)
        result = await self._run(
            (self._executable, "--batch", "--decrypt"),
            request.wrapped_data_key,
        )
        expected_digest = hashlib.sha256(request.associated_data).digest()
        if result.returncode != 0 or len(result.stdout) != len(expected_digest) + KEY_BYTES:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.INVALID_KEY)
        digest = result.stdout[: len(expected_digest)]
        if not secrets.compare_digest(digest, expected_digest):
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.INVALID_KEY)
        return SecretKeyMaterial.from_bytes(result.stdout[len(expected_digest) :])

    async def rotate(self, request: KeyRotationRequest) -> KeyHandle:
        del request
        raise KeyProviderFailure(
            self.provider_id,
            KeyProviderFailureCode.ROTATION_REQUIRES_RECONFIGURATION,
        )

    async def destroy(self, request: KeyDestructionRequest) -> KeyDestructionResult:
        del request
        raise KeyProviderFailure(
            self.provider_id,
            KeyProviderFailureCode.ROTATION_REQUIRES_RECONFIGURATION,
        )

    async def _run(
        self,
        arguments: tuple[str, ...],
        input_data: bytes,
    ) -> GPGCommandResult:
        try:
            return await self._runner.run(
                arguments,
                input_data,
                self._timeout_seconds,
            )
        except (OSError, TimeoutError) as exc:
            raise KeyProviderFailure(
                self.provider_id, KeyProviderFailureCode.PROVIDER_UNAVAILABLE
            ) from exc

    def _handle(self) -> KeyHandle:
        digest = hashlib.sha256(self._recipient.encode("utf-8")).hexdigest()[:32]
        return KeyHandle(f"recipient-{digest}", self.provider_id, 1)

    def _validate_handle(self, handle: KeyHandle) -> None:
        if handle != self._handle():
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.INVALID_KEY)
