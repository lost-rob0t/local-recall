# ADR-0003: Use a minimal SQLite catalog with encrypted opaque blobs

- **Status:** Accepted
- **Date:** 2026-07-17
- **Decision owners:** Local Recall project
- **Related:** #3, `FR-STO-001`–`FR-STO-012`, `FR-RET-003`, `FR-LIFE-001`–`FR-LIFE-008`, `INV-002`, `INV-013`

## Context

Local Recall must support atomic writes, time-scoped retrieval, deletion, retention, migration, backup, and crash recovery while preventing plaintext screenshots, OCR, titles, prompts, summaries, embeddings, and exact activity metadata from appearing on disk.

A conventional plaintext SQLite schema or vector database would leak substantial activity content through tables, indexes, journals, caches, or embeddings. Encrypting the entire database with a transparent extension can be viable, but it increases deployment complexity and does not by itself enforce that application code never writes raw data to another file.

The threat model permits a minimized set of plaintext routing metadata when explicitly documented.

## Decision

v0.1 uses:

1. an owner-only SQLite catalog containing only minimized routing and transaction metadata; and
2. owner-only files whose complete contents are authenticated-encrypted envelopes.

The encrypted blob is the canonical content record. The catalog is a locator and transaction coordinator, not a content database.

## Catalog fields

The catalog may contain:

- random opaque record/artifact ID;
- artifact kind enum;
- envelope and schema version;
- non-secret key identifier;
- ciphertext byte length;
- coarse UTC day bucket;
- opaque blob path token;
- lifecycle transaction state;
- deletion/retention state;
- integrity and migration version fields.

The catalog must not contain by default:

- exact timestamps;
- application or workspace names;
- window titles or URLs;
- OCR or redacted text;
- screenshots or thumbnails;
- prompts, summaries, model output, or citations;
- embeddings or semantic labels;
- user-defined deletion scope labels.

## Accepted metadata leakage

A coarse UTC day bucket leaks which days contain records and approximate volume. Ciphertext size leaks approximate artifact size. File access patterns may reveal which coarse shards are queried.

This leakage is accepted for v0.1 because it bounds the number of encrypted records that must be opened for time-scoped queries. It must be documented to the user and may be removed by a future private-index design.

Random IDs must not encode timestamps. UUIDv7 and other time-ordered identifiers are not used for record IDs unless a later threat-model update accepts the leakage.

## Blob layout

Blob filenames are derived only from random opaque identifiers and fixed extensions. Directory sharding may use a prefix of the random identifier.

Example:

```text
blobs/7f/7f02...a91.lre
indexes/4c1e...bc2.lri
```

No path contains captured or user-provided content.

## Atomic write protocol

1. Receive an `EncryptedEnvelope`; no raw or redacted plaintext type is accepted.
2. Revalidate the capture generation with lifecycle.
3. Create an owner-only random temporary file in the destination directory using exclusive creation and safe path resolution.
4. Write only the complete encrypted envelope.
5. Flush file contents and metadata as required by the durability policy.
6. Atomically rename to the final opaque path.
7. Insert the catalog row in a SQLite transaction.
8. On failure, return non-success and reconcile an encrypted orphan through recovery.

The ordering may be adjusted during implementation if crash testing demonstrates a safer transaction protocol, but no adjustment may write plaintext or make an invalid generation visible.

## SQLite mode

The initial implementation may use WAL mode or rollback journaling after tests compare crash behavior. Journals may contain catalog metadata and ciphertext but must not contain decrypted content.

SQLite files, WAL, shared-memory files, and journals are owner-only. The daemon validates permissions and ownership before capture becomes recordable.

A later implementation issue must choose the exact pragmas based on durability tests. Disabling durability purely for performance is not allowed.

## Encrypted semantic index

Embeddings are content-bearing and remain encrypted.

v0.1 uses coarse-time-partitioned encrypted vector shards:

- each shard contains vectors, opaque source IDs, embedding model identity, dimension, and exact timestamps inside the encrypted envelope;
- the catalog contains only the opaque shard ID, coarse day bucket, ciphertext size, key ID, and version;
- query execution decrypts candidate shards into bounded memory;
- ranking occurs in memory;
- the working set is discarded after completion/cancellation;
- shards are rebuildable from canonical encrypted records.

This does not provide a global plaintext ANN index. The privacy tradeoff is intentional. Performance targets will be measured against the personal-scale dataset expected by v0.1.

## Summaries and clusters

Cluster membership, summaries, prompts, model provenance, citations, and exact time spans are stored in encrypted artifact blobs. Catalog rows use opaque relationships only where transactionally necessary.

## Deletion

Deletion uses a recoverable transaction:

1. create an opaque tombstone/operation record;
2. prevent the selected source IDs from appearing in new queries;
3. remove or rewrite affected encrypted summaries and indexes;
4. remove encrypted blobs;
5. remove catalog entries;
6. clear the tombstone after verification.

Interrupted deletion resumes safely. A failed partial operation cannot report success.

Per-record DEKs enable cryptographic deletion when wrapped keys are removed or rendered unrecoverable, but filesystem and backup cleanup remains required.

## Backup and restore

Backup exports contain:

- encrypted blob bytes;
- minimized catalog reconstruction data;
- schema/envelope versions;
- a sanitized authenticated manifest.

They do not include active key material by default. Optional GPG recipient protection wraps the already encrypted archive as an explicit additional layer.

Restore validates archive paths, integrity, envelope versions, duplicate IDs, key references, and catalog constraints before making records visible.

## Consequences

### Positive

- Application structure enforces encrypted-only content persistence.
- SQLite provides mature transactions and recovery for minimized metadata.
- Opaque files avoid large screenshot BLOB churn inside SQLite.
- Encrypted indexes are rebuildable and do not leak semantic vectors at rest.
- Backup and migration can copy opaque encrypted artifacts.

### Negative

- Coarse time buckets and ciphertext sizes leak limited activity patterns.
- Exact semantic search may require decrypting many vectors in memory.
- Catalog/blob consistency needs explicit recovery logic.
- Secure deletion on copy-on-write filesystems and backups cannot be guaranteed by unlink alone.

## Alternatives considered

### Store everything as SQLite BLOBs

Simpler transactional consistency, but large image artifacts can cause database growth and maintenance costs. It remains a possible future backend behind the same `StorageBackend` port.

### SQLCipher

Provides transparent database encryption but adds packaging/native-extension complexity and does not structurally prevent raw temp files or alternate stores. It may be evaluated later as defense in depth.

### Plaintext vector database

Rejected because embeddings leak source meaning and violate the default threat model.

### Files only, no catalog

Rejected because atomic deletion, retention, migration, and bounded time retrieval would require unsafe filename metadata or expensive full scans.

## Verification

Issues #4, #10, #11, #22, #30, #31, and #32 must prove:

- storage rejects non-envelope types;
- filesystem scans find no seeded plaintext;
- temporary and orphan files contain encrypted bytes only;
- insecure ownership or permissions block capture;
- interrupted writes and deletions recover safely;
- exact timestamps and semantic content do not appear in catalog tables or journals;
- vector shards are encrypted and rebuildable;
- backup inspection reveals no captured content;
- injected storage failures return non-zero and cannot be relabeled as success.