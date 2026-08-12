# Local embeddings and encrypted semantic index

Local Recall embeds only `PrivacyClass.REDACTED_CONTENT`. The built-in Ollama adapter uses the
loopback-only transport, finite deadlines, bounded concurrency, bounded request and response sizes,
and configurable batches. It never downloads a model or falls back to a remote endpoint.

`EncryptedSemanticIndex` stores record identifiers, capture timestamps, model identity, dimensions,
and vectors inside one XChaCha20-Poly1305 authenticated snapshot. The only plaintext fields are the
format version, algorithm, key handle, nonce, wrapped data key, and ciphertext. Index directories are
owner-only and snapshots are published through an fsync-backed atomic replacement.

Search embeds the query locally, verifies the exact model identity and dimensions, decrypts the
snapshot only in memory, applies the optional half-open time range, and returns bounded scored record
references. A model or dimension mismatch fails before the active index changes.

Rebuilds accept redacted documents produced by decrypting the minimum selected source records. Each
completed batch is saved to a separate encrypted checkpoint. Cancellation or failure leaves the
active index unchanged; a later rebuild with the same ordered source records resumes the checkpoint.
The checkpoint replaces the active snapshot only after every batch succeeds, which also provides the
model-migration path.
