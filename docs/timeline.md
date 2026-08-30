# Timeline inspection and selective deletion

Issue #30 lets the owner see exactly what was retained and delete it explicitly, without relying on AI summaries and without relying on storage internals.

## Design summary

Encrypted canonical storage is the only record-existence authority. The catalog deliberately holds only coarse, opaque metadata, so no deletion scope may be resolved from catalog columns alone. Instead, every scope is resolved by bounded candidate enumeration plus decrypt-on-demand, with decrypted records kept memory-only for the operation lifetime.

Destructive operations follow a forward-only journal-protected state machine:

1. `planned`: an owner-only, content-free deletion journal durably binds the opaque request ID to the exact selected record UUIDs.
2. Each selected record is deleted through the canonical storage state machine (`ready` → `deleting` → blob unlink/fsync → catalog row removal).
3. `records-deleted`: written only after every canonical delete succeeds; deleted records can no longer be loaded by retrieval even while derived snapshots are stale.
4. Derived state is reconciled: selected IDs are removed from the encrypted semantic index, and the encrypted activity snapshot is rebuilt from surviving canonical records only.
5. `derived-reconciled`: written only after both derived operations succeed; then the journal is cleared and its owner-only directory is fsynced.

A crash at any phase resumes forward on recovery. No rollback ever makes a deleted record visible again. One deletion transaction is active at a time; repeated or retried requests with the same record identity are idempotent.

The deletion journal is an owner-only directory (mode `0700`) holding a bounded owner-only JSON intent (mode `0600`) with opaque identifiers only: request ID, record UUIDs, closed phase, version. Construction and every load revalidate the directory and file for type, owner, mode, and size without following symlinks; interrupted journal replacement removes only the journal's private temporary path (including a dangling or hostile symlink placed at that exact path) and never follows it.

## Closed typed scopes

Every destructive action requires exactly one explicit scope. Implicit or empty "everything" scopes are invalid:

- `record-ids`: explicit, unique, bounded set of record UUIDs;
- `activity-cluster`: the opaque 32-hex identifier of one activity cluster, resolved to its source record IDs from the encrypted snapshot;
- `application`: case-insensitive application match plus mandatory explicit time bounds;
- `time-range`: explicit, timezone-aware start/end window (bounded span).

Scope resolution fails closed when the bounded scan exceeds its candidate budget or selects nothing, when the cluster identifier is unknown, and when scope fields conflict. Application-wide or retention-driven purges without explicit bounds belong to #31 (retention, quotas, and cryptographic deletion), not to this surface.

## Inspection surface

`TimelineInspector` lists entries by explicit bounded window (optionally filtered by application), newest first. Each entry exposes only user-requested redacted metadata: opaque record ID, capture time, application and workspace names, the opaque cluster identifier, the redaction policy revision, the redaction finding count, and capture provenance (field name, metadata source, observation time, confidence, adapter revision). Listing never includes OCR text, screenshot bytes, or finding spans.

`preview` is an explicit decrypt-on-demand operation for exactly one record, returning either the redacted text or the redacted screenshot (as bounded JSON with base64 pixels). Previews are never cached and never persisted; decrypted content exists only in memory for the call.

Cluster identifiers are derived deterministically from the cluster's source-record identity, cluster window, and source fingerprint, so a listed cluster can be referenced back for scoped deletion without persisting a separate cluster registry.

## IPC and CLI

The daemon-side `TimelineDeletionHandler` is the only authority for this surface. It serves three authenticated commands over the owner-only IPC boundary:

- `timeline --start --end [--application] [--json]` — bounded listing through the `query` capability;
- `preview RECORD_ID [--image]` — explicit decrypt-on-demand preview through the `query` capability;
- `delete --record-id … | --cluster ID | --application NAME --start --end | --start --end` — destructive operation through the dedicated `delete` capability.

Every destructive request must arrive with exactly one closed scope; the transport rejects conflicting or empty scope frames before dispatch, and the handler maps resolution failures to fixed sanitized reasons (`deletion-scope-invalid`, `preview-unavailable`, `timeline-requires-bounds`, `deletion-failed`). Audit failure after a durable deletion returns `internal-failure`/`audit-failed` rather than silently bypassing the audit trail; the deletion itself remains durable and idempotent to retry.

Destructive requests emit a sanitized `deletion_request` audit event containing only the request correlation ID, the closed scope class, the selected record count, success/failure, and timing. No application names, workspace names, scope text, record contents, or prompts are recorded. Preview and listing output remain within the authenticated query boundary described in `ipc.md`.

## Privacy invariants

- Scope resolution, activity rebuilds, and previews keep decrypted records memory-only; no plaintext is written to temporary files, caches, or logs at any point.
- Deleted records are removed from canonical storage first; derived snapshots are then rebuilt exclusively from survivors, so deleted records cannot reappear in search, summaries, clusters, or answers.
- Interrupted deletions resume forward; a partially completed deletion never leaves orphaned plaintext and never resurrects deleted records.
- Retention, quota eviction, purge-all, and cryptographic erasure remain owned by issue #31.

## CLI

```text
local-recall timeline --start ISO-8601 --end ISO-8601 [--application NAME] [--json]
local-recall preview RECORD_ID [--image] [--json]
local-recall delete --record-id UUID [--record-id UUID …] [--json]
local-recall delete --cluster CLUSTER_ID [--json]
local-recall delete --application NAME --start ISO-8601 --end ISO-8601 [--json]
local-recall delete --start ISO-8601 --end ISO-8601 [--json]
```

The CLI is a client of the authenticated IPC boundary only; it imports no storage, retrieval, index, activity, or deletion internals.

## Verification

Issue #30 tests cover encrypted index removal, canonical-visibility rechecking under concurrent retrieval, journal write/recovery including stale-temporary and symlink-abuse cases, forward-only coordinator recovery after derived-state failure, surviving-record activity rebuilds (membership exclusion, bounded window, concurrent-deletion skips, candidate overflow fail-closed, no plaintext artifacts), bounded deletion-scope resolution (record/cluster/application/time-range, exact capture-time bounds, empty and conflicting scope rejection), typed timeline listing and memory-only previews, sanitized destructive audit events, and a full authenticated IPC round trip (timeline → preview → delete → post-deletion timeline and audit) over the real transport with the real SQLite storage backend.
