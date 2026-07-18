class LifecycleError(RuntimeError):
    """Base lifecycle error."""


class CaptureGateError(LifecycleError):
    """Base capture-gate rejection."""


class CaptureGateClosed(CaptureGateError):
    """Raised when an operation is attempted while the gate is closed."""


class StaleCaptureGeneration(CaptureGateError):
    """Raised when work belongs to an invalidated capture generation."""


class CaptureGateOwnershipError(LifecycleError):
    """Raised when a non-owner thread attempts a state transition."""
