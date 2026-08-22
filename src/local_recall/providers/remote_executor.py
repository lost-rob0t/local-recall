from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from .remote import RemoteHttpRequest, RemoteTransportError


class RemoteJsonTransport(Protocol):
    async def request_json(self, request: RemoteHttpRequest) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class RemoteExecutionSettings:
    max_attempts: int = 2
    deadline_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 4:
            raise ValueError("remote max_attempts must be between 1 and 4")
        if self.deadline_seconds <= 0:
            raise ValueError("remote deadline must be positive")


class RemoteRequestExecutor:
    _TRANSIENT_REASONS = frozenset(
        {
            "remote-timeout",
            "remote-connection-failed",
            "remote-response-incomplete",
        }
    )

    def __init__(
        self,
        transport: RemoteJsonTransport,
        settings: RemoteExecutionSettings,
    ) -> None:
        self._transport = transport
        self._settings = settings

    async def execute(self, request: RemoteHttpRequest) -> Mapping[str, object]:
        try:
            async with asyncio.timeout(self._settings.deadline_seconds):
                for attempt in range(1, self._settings.max_attempts + 1):
                    try:
                        return await self._transport.request_json(request)
                    except asyncio.CancelledError:
                        raise
                    except RemoteTransportError as exc:
                        if (
                            exc.reason_code not in self._TRANSIENT_REASONS
                            or attempt >= self._settings.max_attempts
                        ):
                            raise
        except asyncio.CancelledError:
            raise
        except TimeoutError as exc:
            raise RemoteTransportError("remote-deadline-exceeded") from exc

        raise RemoteTransportError("remote-execution-invariant")
