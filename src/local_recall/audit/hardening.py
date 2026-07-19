from __future__ import annotations

import faulthandler
import os
import resource
from collections.abc import Callable
from dataclasses import dataclass

from .errors import AuditFailure, AuditFailureCode


@dataclass(frozen=True, slots=True)
class RuntimeHardeningResult:
    core_dumps_disabled: bool
    restrictive_umask_installed: bool
    fault_handler_disabled: bool


class RuntimeHardener:
    def __init__(
        self,
        *,
        core_resource_id: int = resource.RLIMIT_CORE,
        set_limits: Callable[[int, tuple[int, int]], None] = resource.setrlimit,
        get_limits: Callable[[int], tuple[int, int]] = resource.getrlimit,
        set_umask: Callable[[int], int] = os.umask,
        disable_fault_handler: Callable[[], None] = faulthandler.disable,
    ) -> None:
        self._core_resource_id = core_resource_id
        self._set_limits = set_limits
        self._get_limits = get_limits
        self._set_umask = set_umask
        self._disable_fault_handler = disable_fault_handler

    def apply(self) -> RuntimeHardeningResult:
        try:
            self._set_umask(0o077)
            self._set_limits(self._core_resource_id, (0, 0))
            soft, hard = self._get_limits(self._core_resource_id)
            if soft != 0 or hard != 0:
                raise AuditFailure(AuditFailureCode.HARDENING_FAILURE)
            self._disable_fault_handler()
        except AuditFailure:
            raise
        except Exception as exc:
            raise AuditFailure(AuditFailureCode.HARDENING_FAILURE) from exc
        return RuntimeHardeningResult(True, True, True)
