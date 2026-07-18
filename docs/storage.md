# Encrypted storage

Local Recall persists capture records through `FilesystemStorageBackend`, which implements ADR-0003 with two owner-only components:

1. a SQLite catalog containing minimized routing and transaction metadata; and
2. opaque `.lre` files containing authenticated-encrypted storage blobs.

The catalog is not a content database. It contains only an opaque record ID, storage and envelope versions, a non-secret key ID, encrypted-blob size, a coarse UTC day bucket, opaque path tokens, integrity data, migration state, and transaction state. It does not contain exact timestamps, application names, workspace names, window titles, URLs, OCR, screenshots, summaries, prompts, embeddings, or model output.

## Exact time retrieval

The coarse UTC day bucket only narrows which encrypted blobs must be opened. It does not limit query precision.

`TimeRangeQuery` accepts exact timezone-aware datetimes and uses a half-open interval:

```text
start_at <= record.created_at < end_at
```

For queries such as “what was I doing five minutes ago?” or “what was I doing eighteen hours ago?”, storage selects candidate day buckets, authenticates and decrypts those candidates, filters them using the exact encrypted timestamps, sorts the matches, and returns only the requested limit. Seconds and microseconds are preserved inside the encrypted record.

## Blob encryption

The existing record envelope is serialized inside a second authenticated-encryption envelope using a fresh per-blob data-encryption key and the configured index-key provider. This outer layer hides the inner envelope's exact timestamp, configuration revision, ciphertext, nonce, wrapped record key, and frame metadata from filesystem inspection.

Blob headers expose only the opaque record ID, storage format/version, algorithm, payload format, non-secret key handle, and exact encrypted frame sizes. Header bytes are authenticated as associated data.

## Atomic writes and recovery

A put operation:

1. creates a mode-0600 encrypted temporary file with exclusive creation;
2. flushes the file;
3. inserts a `pending` catalog transaction;
4. atomically publishes the opaque blob with `os.replace`;
5. flushes the containing directory; and
6. marks the catalog row `committed`.

Startup recovery completes valid pending publishes, accepts a valid already-published blob, removes transactions with no remaining artifact, and quarantines opaque corrupted or orphaned files. Queries never expose pending rows.

## Integrity, quotas, and quarantine

The outer authenticated encryption detects content or header tampering. The catalog also stores a SHA-256 digest of the encrypted blob to detect filesystem corruption before decryption. Corrupted files are moved to the owner-only quarantine directory and excluded from retrieval.

Record-count and encrypted-byte quotas include pending, committed, and quarantined artifacts. A quota failure creates no visible record.

## Migrations

Storage blobs have an independent schema version. Supported prior versions are decrypted in memory and rewritten through the same recoverable pending transaction using the current schema. No plaintext migration file is created. Future unsupported versions fail closed.

## Deletion limits

Deletion removes the catalog row and opaque local files, but the backend does not claim guaranteed physical erasure on copy-on-write filesystems, storage snapshots, or backups. The result therefore reports `cryptographic_material_destroyed = false` unless a later key-destruction transaction proves otherwise.
