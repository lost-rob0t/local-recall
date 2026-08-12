from __future__ import annotations

import asyncio
import os
import shutil
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, runtime_checkable
from uuid import uuid4

from local_recall.domain.capture import MetadataRequest
from local_recall.metadata.activitywatch import ActivityWatchMetadataSource
from local_recall.metadata.activitywatch_types import ActivityWatchMetadataFailure

from .safety import (
    IdleObservation,
    IdleState,
    SafetyObservationRequest,
    SessionSafetyFailureCode,
)

_XORG_SOURCE_ID = "xorg-idle"
_XORG_SOURCE_REVISION = "xprintidle-v1"
_ACTIVITYWATCH_SOURCE_REVISION = "activitywatch-afk-v1"
_DEFAULT_TIMEOUT_SECONDS = 0.25
_MAX_OUTPUT_BYTES = 128
_MAX_IDLE_MILLISECONDS = 7 * 24 * 60 * 60 * 1000


@dataclass(frozen=True, slots=True, repr=False)
class IdleCommandResult:
    return_code: int
    stdout: bytes = field(repr=False)
    stderr: bytes = field(default=b"", repr=False)

    def __repr__(self) -> str:
        return (
            f"IdleCommandResult(return_code={self.return_code}, "
            f"stdout_bytes={len(self.stdout)}, stderr_bytes={len(self.stderr)})"
        )


@runtime_checkable
class IdleCommandRunner(Protocol):
    @property
    def available(self) -> bool: ...

    async def run(
        self,
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> IdleCommandResult: ...


class FixedXprintidleRunner:
    def __init__(
        self,
        executable: Path | None = None,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        environment = os.environ if environ is None else environ
        search_path = environment.get("PATH")
        resolved = (
            shutil.which("xprintidle", path=search_path) if executable is None else str(executable)
        )
        self._executable = None if resolved is None else Path(resolved).resolve()
        if self._executable is not None and self._executable.name != "xprintidle":
            raise ValueError("idle fallback must use the fixed xprintidle executable")
        self._environment = dict(environment)
        self._environment["LC_ALL"] = "C"
        self._environment["LANG"] = "C"

    @property
    def available(self) -> bool:
        path = self._executable
        return bool(path is not None and path.is_file() and os.access(path, os.X_OK))

    async def run(
        self,
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> IdleCommandResult:
        executable = self._executable
        if executable is None or not self.available:
            raise FileNotFoundError("xprintidle unavailable")
        process = await asyncio.create_subprocess_exec(
            str(executable),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._environment,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout_seconds)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise
        if len(stdout) > max_output_bytes or len(stderr) > max_output_bytes:
            raise ValueError("idle source output exceeded bound")
        return IdleCommandResult(process.returncode or 0, stdout, stderr)


class XorgIdleStateSource:
    def __init__(
        self,
        *,
        runner: IdleCommandRunner | None = None,
        now: Callable[[], datetime] | None = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        monotonic_ns: Callable[[], int] | None = None,
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 5:
            raise ValueError("idle source timeout must be between 0 and 5 seconds")
        self._runner = runner or FixedXprintidleRunner()
        self._now = now or (lambda: datetime.now(UTC))
        self._timeout_seconds = timeout_seconds
        self._monotonic_ns = monotonic_ns or time.monotonic_ns

    @property
    def source_id(self) -> str:
        return _XORG_SOURCE_ID

    async def observe(self, request: SafetyObservationRequest) -> IdleObservation:
        observed_at = self._now()
        if not self._runner.available:
            return self._unknown(observed_at, SessionSafetyFailureCode.UNAVAILABLE)
        try:
            result = await self._runner.run(
                timeout_seconds=self._remaining_timeout(request),
                max_output_bytes=_MAX_OUTPUT_BYTES,
            )
        except TimeoutError:
            return self._unknown(observed_at, SessionSafetyFailureCode.TIMEOUT)
        except PermissionError:
            return self._unknown(observed_at, SessionSafetyFailureCode.PERMISSION_DENIED)
        except Exception:
            return self._unknown(observed_at, SessionSafetyFailureCode.UNAVAILABLE)
        if result.return_code != 0:
            return self._unknown(observed_at, SessionSafetyFailureCode.UNAVAILABLE)
        try:
            text = result.stdout.decode("ascii").strip()
            if not text or not text.isascii() or not text.isdigit():
                raise ValueError
            milliseconds = int(text)
        except UnicodeDecodeError, ValueError:
            return self._unknown(observed_at, SessionSafetyFailureCode.MALFORMED)
        if not 0 <= milliseconds <= _MAX_IDLE_MILLISECONDS:
            return self._unknown(observed_at, SessionSafetyFailureCode.MALFORMED)
        return IdleObservation(
            state=IdleState.ACTIVE if milliseconds == 0 else IdleState.IDLE,
            observed_at=observed_at,
            source_id=self.source_id,
            source_revision=_XORG_SOURCE_REVISION,
            idle_seconds=milliseconds / 1000.0,
        )

    def _remaining_timeout(self, request: SafetyObservationRequest) -> float:
        remaining_ns = request.deadline_monotonic_ns - self._monotonic_ns()
        if remaining_ns <= 0:
            raise TimeoutError
        return min(self._timeout_seconds, remaining_ns / 1_000_000_000)

    def _unknown(self, observed_at: datetime, failure: SessionSafetyFailureCode) -> IdleObservation:
        return IdleObservation(
            state=IdleState.UNKNOWN,
            observed_at=observed_at,
            source_id=self.source_id,
            source_revision=_XORG_SOURCE_REVISION,
            failure_code=failure,
        )


class ActivityWatchIdleStateSource:
    def __init__(
        self,
        source: ActivityWatchMetadataSource,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._source = source
        self._now = now or (lambda: datetime.now(UTC))

    @property
    def source_id(self) -> str:
        return "activitywatch"

    async def observe(self, request: SafetyObservationRequest) -> IdleObservation:
        try:
            metadata = await self._source.collect(
                MetadataRequest(
                    job_id=uuid4(),
                    generation=request.generation,
                    deadline_monotonic_ns=request.deadline_monotonic_ns,
                    requested_fields=frozenset({"idle", "idle.seconds"}),
                )
            )
        except ActivityWatchMetadataFailure:
            return self._unknown(SessionSafetyFailureCode.UNAVAILABLE)
        except TimeoutError:
            return self._unknown(SessionSafetyFailureCode.TIMEOUT)
        except Exception:
            return self._unknown(SessionSafetyFailureCode.UNAVAILABLE)

        field = next((item for item in metadata.fields if item.name == "idle"), None)
        if field is None or type(field.value) is not bool:
            return self._unknown(SessionSafetyFailureCode.MALFORMED)
        if not field.provenance or any(
            item.source_id != self.source_id for item in field.provenance
        ):
            return self._unknown(SessionSafetyFailureCode.MALFORMED)
        duration = metadata.get("idle.seconds")
        idle_seconds: float | None = None
        if duration is not None:
            if isinstance(duration, bool) or not isinstance(duration, (int, float)):
                return self._unknown(SessionSafetyFailureCode.MALFORMED)
            idle_seconds = float(duration)
            if not 0.0 <= idle_seconds <= _MAX_IDLE_MILLISECONDS / 1000.0:
                return self._unknown(SessionSafetyFailureCode.MALFORMED)
        return IdleObservation(
            state=IdleState.IDLE if field.value else IdleState.ACTIVE,
            observed_at=metadata.observed_at,
            source_id=self.source_id,
            source_revision=_ACTIVITYWATCH_SOURCE_REVISION,
            idle_seconds=idle_seconds,
        )

    def _unknown(self, failure: SessionSafetyFailureCode) -> IdleObservation:
        return IdleObservation(
            state=IdleState.UNKNOWN,
            observed_at=self._now(),
            source_id=self.source_id,
            source_revision=_ACTIVITYWATCH_SOURCE_REVISION,
            failure_code=failure,
        )
