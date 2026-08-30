# Health checks, diagnostics, and safe repair

**Status:** v0.1 implementation for issue #37.
**Authority:** the health subsystem is read-only by construction; only explicitly requested repair operations mutate anything, and they never delete records or alter privacy policy.

## Model

`src/local_recall/health/` defines a closed set of eleven checks (`HealthCheckId`):

| check id | criticality | failure state |
| --- | --- | --- |
| `lifecycle` | privacy-critical | `capture-blocking` only when the lifecycle is `faulted` |
| `capture-backend` | privacy-critical | `capture-blocking` when no usable backend |
| `metadata-sources` | optional | `degraded` |
| `ocr` | optional | `degraded` |
| `encryption-keys` | privacy-critical | `capture-blocking` (locked/unavailable/invalid/revoked) |
| `redaction` | privacy-critical | `capture-blocking` (functional self-test failed) |
| `storage-integrity` | privacy-critical | `capture-blocking` when unavailable; `degraded` when quarantined records exist |
| `indexes` | optional | `degraded` (missing manifest or behind storage) |
| `model-providers` | optional | `degraded` |
| `disk-quota` | privacy-critical | `capture-blocking` below the configured free-byte floor |
| `daemon-ipc` | optional | `degraded` |

`HealthReport` derives:

- `capture_blocked`: any check is `capture-blocking`;
- `overall`: `capture-blocking` > `degraded` > `healthy`.

This is the required distinction: a degraded optional feature (OCR down, index behind storage, IPC unresponsive) never stops capture or persistence, while a failing privacy-critical dependency does.

## Checks and ports

Every check consumes a narrow port (`health/ports.py`); the production composition provides adapters over real subsystems:

- lifecycle: `CaptureStateSnapshot` (already tracks `critical_dependencies_healthy`);
- capture backend: `backend_health()` (Xorg availability, or the Wayland portal backend `status()`);
- encryption: existing `KeyProvider.health()` reports;
- redaction: a functional self-test port — the detector must classify a fixed synthetic sample exactly as expected, otherwise redaction is broken and capture MUST stop;
- storage: read-only availability/counters (health never calls the mutating `recover()`);
- indexes: `EncryptedSemanticIndex.manifest()` cross-checked against the storage record count;
- providers: capability availability;
- disk quota: free-byte floor from configuration;
- daemon IPC: authenticated endpoint responsiveness.

`HealthService` runs all checks concurrently with a per-check timeout. Exceptions and timeouts are mapped to fixed reason codes (`health-check-failed`, `health-check-timed-out`) with the state derived from criticality; no exception text is ever retained.

## Privacy gates

`health/guard.py`:

- `ensure_capture_allowed(report)` raises `PrivacyDependencyFault` while `capture_blocked`;
- `ensure_persistence_allowed(report)` raises when the encryption, redaction, or storage checks are `capture-blocking`.

The lifecycle `FaultCapture` path (state `faulted`, `critical_dependencies_healthy=false`, generation invalidated) is the enforcement point for "capture faults when a critical privacy dependency fails"; persistence refuses to commit while those checks are blocking.

## Diagnostic bundle

`build_diagnostic_bundle()` produces a read-only, content-free JSON document:

- timestamps, application version, Python version, platform family (`linux`);
- the health-check results (closed check ids, states, fixed reason codes);
- opaque counts (records, storage bytes) and sanitized revision tokens.

It contains **no** filesystem paths, hostnames, usernames, environment values, window titles, or message text — revisions and reason codes are validated against strict character sets, so the bundle cannot carry content. Automated verification includes a `detect-secrets` scan over a bundle produced with seeded marker content (see `tests/security/test_health_architecture.py`).

The IPC mapping (`health/payload.py`) renders the report into the closed `CliDiagnosticPayload` (category `health`) served behind the authenticated IPC boundary for the `health` CLI command.

## Safe repair

`SafeRepairService` supports exactly four explicit operations (`RepairCommand`, closed enum):

- `index-rebuild`: rebuild derived index state from storage survivors;
- `orphan-cleanup`: forward-only storage hygiene via the existing `recover()` semantics (temporary files, orphaned derived state, recovered writes);
- `migration-resume`: resume pending configuration migrations;
- `provider-reprobe`: re-run provider capability probes.

Invariants, enforced by tests:

- **Never automatic**: repairs run only through an explicit request (`RepairRequest` with a reason code); no scheduler or capture path invokes them.
- **Never destructive**: no operation deletes records, destroys keys, or touches privacy policy; the command set is closed and contains no deletion or policy operations, and a spy-backed test proves no storage delete path is reached.
- **Restartable**: every operation is idempotent, outcomes are journaled in `RepairLedger`, and a failed run can simply be issued again.
- **Audited**: each run emits a sanitized `REPAIR_OPERATION` audit event (fixed command token, outcome, `count`/`success`/`restartable` attributes only).

## Testing

- `tests/unit/health/` — models, checks (all eleven, healthy/degraded/blocking), service sanitization, bundle scrubbing, repair semantics, guards, IPC payload mapping;
- `tests/unit/audit/test_health_and_repair_events.py` — audit event validation;
- `tests/integration/health/` — lifecycle fault wiring through the real `CaptureGate`/`LifecycleActor`;
- `tests/security/test_health_architecture.py` — seeded-content leak probes across report/bundle/payload/repair surfaces, `detect-secrets` bundle scan, non-destructive repair invariants, persistence prevention.
