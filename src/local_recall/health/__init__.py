"""Health checks, diagnostics, and safe repair."""

from .bundle import DiagnosticBundle, build_diagnostic_bundle
from .checks import HealthCheck, build_health_checks
from .guard import PrivacyDependencyFault, ensure_capture_allowed, ensure_persistence_allowed
from .models import (
    HealthCheckCriticality,
    HealthCheckId,
    HealthCheckResult,
    HealthReport,
    HealthState,
    criticality_for,
)
from .payload import (
    health_report_diagnostic_entries,
    health_report_diagnostic_payload,
)
from .ports import (
    CaptureBackendHealth,
    DiskUsage,
    IndexHealth,
    IpcHealth,
    MetadataSourceHealth,
    OcrHealth,
    ProviderHealth,
    RedactionHealth,
    StorageHealth,
)
from .repair import (
    RepairCommand,
    RepairLedger,
    RepairOutcome,
    RepairRequest,
    RepairStatus,
    SafeRepairService,
)
from .service import HealthService

__all__ = [
    "CaptureBackendHealth",
    "DiagnosticBundle",
    "DiskUsage",
    "HealthCheck",
    "HealthCheckCriticality",
    "HealthCheckId",
    "HealthCheckResult",
    "HealthReport",
    "HealthService",
    "HealthState",
    "IndexHealth",
    "IpcHealth",
    "MetadataSourceHealth",
    "OcrHealth",
    "PrivacyDependencyFault",
    "ProviderHealth",
    "RedactionHealth",
    "RepairCommand",
    "RepairLedger",
    "RepairOutcome",
    "RepairRequest",
    "RepairStatus",
    "SafeRepairService",
    "StorageHealth",
    "build_diagnostic_bundle",
    "build_health_checks",
    "criticality_for",
    "ensure_capture_allowed",
    "ensure_persistence_allowed",
    "health_report_diagnostic_entries",
    "health_report_diagnostic_payload",
]
