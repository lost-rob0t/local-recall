# Retention, garbage collection, and purge-all

Issue #31 bounds the amount and lifetime of retained personal activity data. Canonical encrypted storage remains the sole record-existence authority; every derived structure is reconciled from it, never the other way around.

## Retention policy

The policy is a closed typed rule set (`RetentionRules`) evaluated by a bounded planner:

- **Age**: records older than `max_age_days` are expired. The catalog stores only a content-free day bucket per record, so age selection needs no decryption.
- **Context overrides**: per-application or per-workspace rules (`ContextRetentionRule`) can expire a named value sooner or keep it longer than the global age limit. Matching requires decrypt-on-demand over the candidates inside the disputed window only; values are compared case-insensitively and never logged. When several overrides match, the most aggressive expiry wins.
- **Watermarks**: when storage bytes exceed `max_bytes` (high watermark), oldest-first eviction runs until usage reaches `low_watermark_bytes` (default 80% of high). Order is the canonical catalog order (day bucket, record ID) and is fully predictable.
- **Record cap**: when the ready record count exceeds `max_records`, the same oldest-first eviction applies.

Planning never exposes captured text: the plan contains only opaque record IDs, counts, and reclaimed-byte estimates. Context evaluation has a strict decrypt budget; exceeding it fails closed rather than silently scanning unbounded content. Retention planning cannot delete anything outside the configured policy — selection is computed purely from the closed rule set, and every sweep is audited.

## Sweep execution

`RetentionEngine.sweep()` plans first, then deletes each selected record through the idempotent canonical storage state machine (`ready` → `deleting` → blob unlink/fsync → catalog removal). Sweeps are repeatable and safe after interruption: already-deleted records are skipped by the idempotent delete, and the next sweep re-plans from canonical state. Dry runs report planned counts without touching storage.

## Garbage collection

`GarbageCollector.collect()` reconciles derived state with canonical storage:

1. storage recovery runs first, completing any interrupted per-record deletions and cleaning temporary artifacts;
2. semantic-index entries whose record IDs are no longer canonically ready are pruned;
3. activity-snapshot clusters referencing non-existent canonical records are removed by rebuilding the snapshot from surviving canonical records only.

Every step recomputes from canonical state and is idempotent, so an interrupted collection resumes safely by running again. The collector never mutates canonical storage.

## Purge-all

`PurgeAllEngine.purge()` is the manual, explicit destruction path:

1. every ready record is deleted through the canonical state machine;
2. the encrypted semantic index is invalidated (uninitialized until the next rebuild);
3. the encrypted activity snapshot is replaced with an empty one;
4. the active record key is destroyed, so no capture record remains decryptable with the active key material.

Purge-all is idempotent and audited with the deleted count, outcome, and whether key material was destroyed. Dry runs report the planned count without side effects. Keys of past rotations were never able to decrypt records whose per-record wrapped data keys were removed with their envelopes.

## Audit and privacy

All three paths emit sanitized audit events (`retention_sweep`, `garbage_collection`, `purge_all`) carrying only non-negative counts, reclaimed-byte totals, boolean outcomes, and timing. No application names, workspace names, record contents, or scope values enter the audit stream. Decrypted records used for context-rule evaluation live only in memory for the evaluation lifetime; nothing plaintext is persisted.

## Scheduling and scope

The engines are daemon-side authorities designed to be invoked by the daemon composition (packaged in #40) on a schedule or by an owner command; the retention policy itself comes from validated configuration (`RetentionSettings`). Retention decisions are policy-only: no capture, lifecycle, or privacy-mode state is modified by retention work.
