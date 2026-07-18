# Encrypted storage, catalog, and migrations

Issue #11 implements the storage boundary defined by ADR-0003 and the threat model. Storage receives `EncryptedRecordEnvelope` values only. Raw frames, OCR, redacted plaintext, titles, URLs, prompts, summaries, embeddings, and exact timestamps have no storage API or catalog column.

## Layout

The configured root is owner-only and contains:

```text
catalog.sqlite3
blobs/<uuid-prefix>/<uuid>.lre
tmp/<opaque>.tmp
quarantine/<opaque>.lrq
```

Directories are mode `0700`; the catalog, WAL/SHM files, encrypted blobs, and quarantined blobs are mode `0600`. Symlinked roots, directory components, catalog files, blob shards, and blob files are rejected. Blob names use random UUIDv4 identifiers and disclose no application, title, timestamp, or record content.

## Persistent envelope format

The `.lre` format is versioned and bounded. It stores:

- opaque record UUID;
- capture generation and immutable configuration revision inside the encrypted-envelope header;
- envelope schema and algorithm identifiers;
- non-secret key provider, key ID, and key version;
- exact encrypted-envelope frame sizes;
- wrapped DEK, nonce, ciphertext, and associated-data digest.

The complete envelope is treated as an opaque authenticated blob by storage. The parser rejects unsupported versions, unknown or missing header fields, invalid UUIDs, malformed lengths, oversized sections, truncated content, and appended content.

## Minimal SQLite catalog

SQLite contains only the fields approved by the threat model for locating encrypted records:

- opaque record ID;
- fixed artifact kind;
- envelope schema version;
- key provider, key ID, and key version;
- ciphertext and complete blob lengths;
- coarse UTC day bucket;
- opaque blob token;
- SHA-256 blob integrity digest;
- transaction state and migration version.

The catalog intentionally excludes exact timestamps, configuration revisions, application names, workspace names, window titles, URLs, OCR text, prompts, summaries, embeddings, thumbnails, and deletion scope. The coarse day bucket leaks approximate activity timing and record volume; this is the accepted residual leakage already documented in the threat model.

## Atomic writes and recovery

A write proceeds as follows:

1. Validate that the input is exactly an `EncryptedRecordEnvelope` with a UUIDv4 record ID.
2. Encode and bound the envelope before opening a destination file.
3. Insert a SQLite write intent containing only minimal catalog metadata and the expected blob digest.
4. Write the encrypted blob to an owner-only temporary file and `fsync` it.
5. Atomically rename the blob into its final opaque path and `fsync` the directory.
6. Insert the ready catalog row and remove the write intent in one SQLite transaction.

Startup recovery removes stale temporary files, validates pending write intents, completes interrupted deletions, verifies every ready row against its blob, and examines orphan `.lre` files. A valid orphan is reindexed. A malformed, mismatched, or cross-linked blob is moved to the opaque quarantine directory and removed from query visibility.

## Deletion and quotas

Deletion first marks the catalog row as `deleting`, removes the encrypted blob, synchronizes the shard directory, and then deletes the catalog row. Restart completes any interrupted deletion. This issue removes the stored envelope but does not claim key-provider cryptographic deletion; key destruction and DEK rewrap remain explicit key-provider operations.

Quota enforcement counts encrypted blobs, temporary files, and quarantined files already present under the storage root. A write that would exceed `retention.max_bytes` fails before creating a new blob. Individual blobs are also bounded independently.

## Schema migration

The current catalog schema is version 2. Migrations are forward-only, transactional, and restartable. The version-1 fixture is verified against its encrypted blobs before conversion; migration adds the fixed artifact kind, blob digest, and migration version without decrypting record content. Unknown future versions and unexpected table layouts fail closed.

## Verification

Synthetic tests cover:

- encrypted-envelope round trips and strict malformed-input rejection;
- runtime rejection of bytes and non-random record identifiers;
- owner-only paths and symlink rejection;
- quota enforcement;
- interrupted write and deletion recovery;
- corruption quarantine and orphan repair;
- coarse day lookup;
- a real version-1 catalog migration fixture;
- direct catalog and filesystem scans proving seeded titles, OCR text, URLs, exact timestamps, and configuration revisions are absent.
