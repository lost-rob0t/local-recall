# Sanitized audit logging and operational hardening

Issue #12 adds an inspectable operational record without creating a second captured-content store.

## Security boundary

Audit events are typed structures rather than arbitrary log messages. The persistent schema permits only:

- UUIDv4 event, correlation, and optional record identifiers;
- fixed category, action, outcome, and reason enums;
- capture generation and key version integers;
- bounded provider identifiers;
- one-way BLAKE2b digests for configuration revisions and key references;
- a small allowlist of boolean and non-negative integer attributes.

There is no field for screenshots, OCR text, window titles, URLs, command lines, usernames, prompts, model output, tokens, exception text, or free-form messages. Invalid event objects fail before a write. The debug entry point calls the same serializer and cannot bypass validation.

## Covered decisions

`AuditRecorder` exposes explicit methods for lifecycle, capture, policy, provider, record, export, key, and system-hardening events.

The operational adapters connect those events to existing contracts:

- `LifecycleAuditAdapter` converts lifecycle transitions and hashes configuration revisions.
- `PipelineAuditAdapter` records accepted, overloaded, coalesced, and rejected capture work using record IDs, generations, queue depth, and fixed failure codes only.
- `AuditedCapturePolicy` records policy allow, deny, and evaluation failure without metadata values.
- `AuditedModelRoutingPolicy` records local selection, explicitly authorized remote selection, and routing rejection without prompts or egress tokens.
- `AuditedStorageBackend` records successful, missing, and failed deletion attempts without deletion-request text.
- `AuditedKeyProvider` records rotation and destruction outcomes while persisting key references only as digests.

Export decisions use the recorder directly until the export strategy is implemented. The recorder accepts only record counts and fixed authorization outcomes, never exported content.

## Files, permissions, and retention

`OwnerOnlyAuditFileSink` writes canonical JSON Lines to `audit.jsonl`.

- The audit directory is mode `0700`.
- Current and rotated files are mode `0600`.
- Symlinked path components, log files, and non-regular files are rejected.
- Existing group- or world-accessible audit paths fail closed at startup; they are not silently repaired.
- Rotated files are validated before the active log is opened.
- Writes use `O_APPEND`, `O_CLOEXEC`, and `O_NOFOLLOW` where available.
- Rotation uses opaque UUID filenames, atomic rename, and directory synchronization.
- Maximum event size, file size, rotated-file count, age, and per-event synchronization are explicit `AuditFileSettings` values.

Retention deletes only validated owner-owned rotated audit files. Unknown filesystem objects are not followed or removed.

## Runtime hardening

`RuntimeHardener` installs a restrictive `0077` process umask, validates configured storage trees, sets both core-dump limits to zero, verifies the resulting limits, and disables Python's fault handler. Any failure produces a fixed code rather than exception text.

`validate_owner_only_storage_tree()` checks existing storage roots before capture startup. Directories must be owner-owned mode `0700`; files must be owner-owned regular files mode `0600`; symlinks and special files are rejected. A storage root that does not exist yet is permitted because the storage backend creates it under the restrictive process umask.

The daemon must apply runtime hardening before opening capture, provider, storage, or audit components. Audit-path permission validation is performed when the sink is constructed and therefore also precedes capture startup.

## Failure behavior

Audit failures use fixed codes only. Lifecycle already treats its audit sink as authoritative: a failed transition audit faults or closes capture instead of continuing silently. The operational wrappers emit the audit result before propagating policy, routing, deletion, or key-operation failures.

## Verification

Synthetic tests verify:

- arbitrary reason strings and attribute names are rejected;
- key references and configuration revisions are persisted only as digests;
- owner-only modes are used for directories and files;
- insecure active, rotated, and storage-tree permissions fail closed;
- symlinked paths fail closed;
- rotation and retention stay bounded;
- the debug path uses the identical serializer;
- seeded titles, OCR, URLs, command lines, usernames, tokens, and prompts never appear in audit files;
- policy, routing, pipeline, deletion, and key wrappers emit only fixed operational facts;
- core dumps, permissive umasks, and the fault handler are disabled through a verifiable hardening adapter.
