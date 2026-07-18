from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from local_recall.ports.clock import Clock

from .errors import ConfigurationError
from .loader import (
    LoadedConfiguration,
    configuration_revision,
    load_configuration_file,
    load_configuration_mapping,
)
from .models import LocalRecallConfig


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic_ns(self) -> int:
        import time

        return time.monotonic_ns()


@dataclass(frozen=True, slots=True)
class ConfigurationSnapshot:
    configuration: LocalRecallConfig
    revision: str
    source: str
    loaded_at: datetime


@dataclass(frozen=True, slots=True)
class ReloadOutcome:
    accepted: bool
    snapshot: ConfigurationSnapshot
    error_code: str | None = None
    error_message: str | None = None


class ConfigurationManager:
    def __init__(self, clock: Clock | None = None) -> None:
        self._clock = clock or SystemClock()
        self._lock = threading.RLock()
        self._snapshot = self._safe_snapshot("safe-default")

    def snapshot(self) -> ConfigurationSnapshot:
        with self._lock:
            return self._snapshot

    def reload_mapping(
        self,
        data: Mapping[str, Any],
        *,
        environ: Mapping[str, str] | None = None,
        source: str = "mapping",
    ) -> ReloadOutcome:
        try:
            loaded = load_configuration_mapping(data, environ=environ, source=source)
        except ConfigurationError as exc:
            return self._fail_closed(exc)
        return self._commit(loaded)

    def reload_file(
        self,
        path: Path,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> ReloadOutcome:
        try:
            loaded = load_configuration_file(path, environ=environ)
        except ConfigurationError as exc:
            return self._fail_closed(exc)
        return self._commit(loaded)

    def _commit(self, loaded: LoadedConfiguration) -> ReloadOutcome:
        snapshot = ConfigurationSnapshot(
            configuration=loaded.configuration,
            revision=loaded.revision,
            source=loaded.source,
            loaded_at=self._clock.now(),
        )
        with self._lock:
            self._snapshot = snapshot
        return ReloadOutcome(accepted=True, snapshot=snapshot)

    def _fail_closed(self, error: ConfigurationError) -> ReloadOutcome:
        snapshot = self._safe_snapshot("reload-rejected")
        with self._lock:
            self._snapshot = snapshot
        return ReloadOutcome(
            accepted=False,
            snapshot=snapshot,
            error_code=type(error).__name__,
            error_message=str(error),
        )

    def _safe_snapshot(self, source: str) -> ConfigurationSnapshot:
        configuration = LocalRecallConfig.safe_default()
        return ConfigurationSnapshot(
            configuration=configuration,
            revision=configuration_revision(configuration),
            source=source,
            loaded_at=self._clock.now(),
        )
