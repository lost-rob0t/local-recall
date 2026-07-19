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

`AuditRecorder` exposes explicit methods for:

- lifecycle transitions;
- capture and policy decisions;
- provider selection and remote authorization;
- rejected and deleted records;
- export decisions;
- key creation, rotation, revocation, and destruction;
- runtime hardening results.

The lifecycle adapter implements the existing `LifecycleAuditSink` contract and hashes configuration revisions before persistence. Other components use the recorder rather than Python logging calls.

## Files, permissions, and retention

`OwnerOnlyAuditFileSink` writes canonical JSON Lines to `audit.jsonl`.

- The audit directory is mode `0700`.
- Current and rotated files are mode `0600`.
- Symlinked path components, log files, and non-regular files are rejected.
- Existing group- or world-accessible audit paths fail closed at startup; they are not silently repaired.
- Writes use `O_APPEND`, `O_CLOEXEC`, and `O_NOFOLLOW` where available.
- Rotation uses opaque UUID filenames, atomic rename, and directory synchronization.
- Maximum event size, file size, file count, age, and per-event synchronization are explicit settings.

Retention deletes only validated owner-owned rotated audit files. Unknown filesystem objects are not followed or removed.

## Runtime hardening

`RuntimeHardener` installs a restrictive `0077` process umask, sets both core-dump limits to zero, verifies the resulting limits, and disables Python's fault handler. Any failure produces the fixed `hardening_failure` code rather than exception text.

The daemon must apply runtime hardening before opening capture, provider, storage, or audit components. Audit-path permission validation is performed when the sink is constructed and therefore also precedes capture startup.

## Failure behavior

Audit failures use fixed codes only. Lifecycle already treats its audit sink as authoritative: a failed transition audit faults or closes capture instead of continuing silently. Callers of the generic recorder must preserve the same fail-closed rule for security-relevant operations.

## Verification

Synthetic tests verify:

- arbitrary reason strings and attribute names are rejected;
- key references and configuration revisions are persisted only as digests;
- owner-only modes are used for directories and files;
- insecure existing modes and symlinked logs fail closed;
- rotation and retention stay bounded;
- the debug path uses the identical serializer;
- seeded titles, OCR, URLs, command lines, usernames, tokens, and prompts never appear in audit files;
- core dumps, permissive umasks, and the fault handler are disabled through a verifiable hardening adapter.
