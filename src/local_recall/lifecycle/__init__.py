"""Authoritative capture lifecycle and hard capture gate."""

from .actor import LifecycleActor
from .errors import (
    CaptureGateClosed,
    CaptureGateError,
    CaptureGateOwnershipError,
    LifecycleError,
    StaleCaptureGeneration,
)
from .gate import CaptureGate, CaptureWorkPermit
from .messages import (
    FaultCapture,
    GetLifecycleSnapshot,
    LifecycleAuditEvent,
    LifecycleCommandResult,
    LifecycleFaultCode,
    LifecyclePreflightRequest,
    LifecyclePreflightResult,
    PauseCapture,
    ResumeCapture,
    SetAutomaticCaptureBlock,
    StartCapture,
    StopCapture,
)
from .ports import (
    CaptureWorkCoordinator,
    LifecycleAuditSink,
    LifecycleConfigurationSource,
    LifecyclePreflight,
)

__all__ = [
    "CaptureGate",
    "CaptureGateClosed",
    "CaptureGateError",
    "CaptureGateOwnershipError",
    "CaptureWorkCoordinator",
    "CaptureWorkPermit",
    "FaultCapture",
    "GetLifecycleSnapshot",
    "LifecycleActor",
    "LifecycleAuditEvent",
    "LifecycleAuditSink",
    "LifecycleCommandResult",
    "LifecycleConfigurationSource",
    "LifecycleError",
    "LifecycleFaultCode",
    "LifecyclePreflight",
    "LifecyclePreflightRequest",
    "LifecyclePreflightResult",
    "PauseCapture",
    "ResumeCapture",
    "SetAutomaticCaptureBlock",
    "StaleCaptureGeneration",
    "StartCapture",
    "StopCapture",
]
