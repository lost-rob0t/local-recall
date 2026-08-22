"""Production composition for the Xorg capture stack."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic_ns as system_monotonic_ns

from local_recall.capture.native import BoundedNativeCommandExecutor
from local_recall.capture.xorg import FixedXwdNativeRunner, XorgCaptureBackend, XwdSnapshotReader


def _utc_now() -> datetime:
    return datetime.now(UTC)


def build_xorg_capture_backend(
    *,
    xwd_executable: Path,
    xrandr_executable: Path,
    environment: Mapping[str, str],
    monotonic_ns: Callable[[], int] = system_monotonic_ns,
    now: Callable[[], datetime] = _utc_now,
) -> XorgCaptureBackend:
    """Compose the fixed memory-only Xorg capture implementation."""
    executor = BoundedNativeCommandExecutor(
        executables={
            "xwd": xwd_executable,
            "xrandr": xrandr_executable,
        },
        environment=environment,
        monotonic_ns=monotonic_ns,
    )
    runner = FixedXwdNativeRunner(executor=executor)
    reader = XwdSnapshotReader(runner=runner, now=now)
    return XorgCaptureBackend(reader=reader, monotonic_ns=monotonic_ns)
