"""Allowlisted, sandboxed user-script metadata adapter (issue #34)."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from local_recall.domain.capture import MetadataRequest
from local_recall.domain.metadata import ContextField, ContextMetadata, MetadataProvenance

_MAX_FIELD_LENGTH = 4096
_KILL_GRACE_SECONDS = 1.0

create_subprocess_exec = asyncio.create_subprocess_exec


class ScriptAdapterFailure(RuntimeError):
    """Sanitized script-adapter failure."""


@dataclass(frozen=True, slots=True)
class ScriptAdapterConfig:
    """Closed configuration for one user-supplied metadata script."""

    name: str
    path: Path
    args: tuple[str, ...] = ()
    timeout_seconds: float = 5.0
    max_output_bytes: int = 65_536
    schema_version: int = 1
    pin_sha256: str | None = None
    env_allowlist: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name or len(self.name) > 128 or "/" in self.name:
            raise ValueError("script adapter name is invalid")
        if not self.path.is_absolute():
            raise ValueError("script path must be absolute")
        if not 0 < self.timeout_seconds <= 60:
            raise ValueError("script timeout is invalid")
        if not 1 <= self.max_output_bytes <= 1 << 20:
            raise ValueError("script output limit is invalid")
        if self.schema_version != 1:
            raise ValueError("script schema version is invalid")
        if (
            any(not arg for arg in self.args)
            or len(self.args) > 8
            or any(character in "\x00\r\n" for arg in self.args for character in arg)
        ):
            raise ValueError("script argument template is invalid")
        if self.pin_sha256 is not None and (
            len(self.pin_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.pin_sha256)
        ):
            raise ValueError("script pin digest is invalid")

    def __repr__(self) -> str:
        return (
            f"ScriptAdapterConfig(name={self.name!r}, path=<redacted>, "
            f"arg_count={len(self.args)}, pin={self.pin_sha256 is not None})"
        )


class ScriptMetadataAdapter:
    """Run one owner-approved script with fixed arguments and no shell.

    The script is validated before every run: absolute path, regular file,
    no symlink, current-owner, owner-only permissions, and an optional
    SHA-256 pin. Output is a strict versioned JSON schema; environment is an
    allowlist; the working directory is a fresh private directory. Captured
    desktop values are never part of the command line.
    """

    def __init__(
        self,
        config: ScriptAdapterConfig,
        *,
        now: datetime | None = None,
        environ: dict[str, str] | None = None,
    ) -> None:
        self._config = config
        self._now = now or datetime.now(UTC)
        self._environ = environ if environ is not None else dict(os.environ)
        _validate_script(config)

    def __repr__(self) -> str:
        return f"ScriptMetadataAdapter(config={self._config!r})"

    @property
    def source_id(self) -> str:
        return self._config.name

    @property
    def script_digest(self) -> str | None:
        try:
            return _validate_script(self._config)
        except ScriptAdapterFailure:
            return None

    async def is_available(self) -> bool:
        try:
            _validate_script(self._config)
        except ScriptAdapterFailure:
            return False
        return True

    async def collect(self, request: MetadataRequest) -> ContextMetadata:
        del request
        observed_at = self._now if self._now.tzinfo else self._now.astimezone(UTC)
        digest = _validate_script(self._config)
        stdout = await self._run(digest)
        payload = _parse(stdout, self._config.schema_version)
        revision = digest[:12]
        provenance = MetadataProvenance(
            source_id=self._config.name,
            observed_at=observed_at,
            confidence=_confidence(1.0),
            adapter_revision=revision,
        )
        fields: list[ContextField] = []
        for name in ("application", "workspace"):
            value = payload[name]
            if value is not None:
                fields.append(ContextField(name, value, (provenance,)))
        return ContextMetadata(observed_at=observed_at, fields=tuple(fields))

    async def _run(self, digest: str) -> bytes:
        env = {
            name: self._environ[name]
            for name in self._config.env_allowlist
            if name in self._environ
        }
        with tempfile.TemporaryDirectory(prefix="local-recall-script-") as cwd:
            process = await create_subprocess_exec(
                str(self._config.path),
                *self._config.args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env=env,
                cwd=cwd,
            )
            try:
                stdout, _stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self._config.timeout_seconds,
                )
            except TimeoutError:
                await _kill(process)
                raise ScriptAdapterFailure("script timeout") from None
            if process.returncode != 0:
                raise ScriptAdapterFailure("script failed")
            if len(stdout) > self._config.max_output_bytes:
                raise ScriptAdapterFailure("script output exceeds limit")
            del digest
            return stdout


def _confidence(value: float):
    from local_recall.domain.metadata import SourceConfidence

    return SourceConfidence(value)


def _validate_script(config: ScriptAdapterConfig) -> str:
    try:
        info = config.path.lstat()
    except OSError as exc:
        raise ScriptAdapterFailure("script unavailable") from exc
    if stat.S_ISLNK(info.st_mode):
        raise ScriptAdapterFailure("script symlink rejected")
    if not stat.S_ISREG(info.st_mode):
        raise ScriptAdapterFailure("script is not a regular file")
    if info.st_uid != os.getuid():
        raise ScriptAdapterFailure("script owner mismatch")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ScriptAdapterFailure("script permission rejected")
    digest = hashlib.sha256(config.path.read_bytes()).hexdigest()
    if config.pin_sha256 is not None and digest != config.pin_sha256:
        raise ScriptAdapterFailure("script pin mismatch; re-approval required")
    return digest


def _parse(stdout: bytes, schema_version: int) -> dict[str, str | None]:
    try:
        loaded = cast(object, json.loads(stdout.decode("utf-8", errors="strict")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScriptAdapterFailure("script output is invalid") from exc
    if not isinstance(loaded, dict):
        raise ScriptAdapterFailure("script output is invalid")
    mapping = cast(dict[str, object], loaded)
    if set(mapping) != {"application", "schema_version", "workspace"}:
        raise ScriptAdapterFailure("script output is invalid")
    if mapping["schema_version"] != schema_version:
        raise ScriptAdapterFailure("script output is invalid")
    payload: dict[str, str | None] = {}
    for name in ("application", "workspace"):
        value = mapping[name]
        if value is not None:
            if not isinstance(value, str) or not value or len(value) > _MAX_FIELD_LENGTH:
                raise ScriptAdapterFailure("script output is invalid")
        payload[name] = value
    return payload


async def _kill(process: asyncio.subprocess.Process) -> None:
    process.kill()
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(process.wait(), timeout=_KILL_GRACE_SECONDS)
