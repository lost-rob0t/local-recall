# Encrypted backup export and restore

Issue #32 moves or copies Local Recall data without ever creating plaintext archives. Canonical encrypted envelopes are copied verbatim into a bounded container; no content is decrypted at any point in the pipeline.

## Archive format

A `*.lrb` archive is a single file with:

1. an 8-byte magic (`LRBACKUP`) and format version;
2. a canonical-JSON manifest: format version, storage schema version, creation timestamp, record count, and a SHA-256 digest of the body;
3. a length-prefixed sequence of canonical encrypted envelopes — exactly the bytes produced by the storage codec.

Archive inspection reveals no captured text, titles, thumbnails, prompts, or credentials: everything sensitive is inside AEAD ciphertext. Capture metadata such as day buckets and envelope headers (record ID, key handle reference, schema version) appear exactly as they do inside canonical storage. No active key material is ever included; envelopes reference key handles but carry only wrapped per-record data keys.

## Export

`BackupEngine.export(path, start?, end?)` walks the paged ready-record catalog and writes envelopes. Full backups and explicit time-range exports are supported; the window filter uses content-free day buckets. Exports emit a sanitized `export_decision` audit event with counts only.

## Optional GPG recipient encryption

A `GpgRecipientCrypter` wraps the archive for portability using `gpg --encrypt --recipient <fingerprint>` with a strict argument list, no shell, a bounded timeout, and a private `--homedir` when supplied. Restore decrypts with the same recipient keyring. Wrong-recipient archives, missing gpg binaries, and timeouts fail with sanitized reasons and never produce partial restores. Passphrases and key material never enter the archive, logs, or audit events.

## Restore

`BackupEngine.restore(path, target, allow_non_empty=False)` performs integrity and compatibility checks before writing:

- the manifest schema version must match the running storage schema version (conflicting versions fail safely);
- the body digest is verified, then every envelope is decoded and authenticated;
- the target must be an empty profile unless explicitly overridden;
- identical duplicates are detected and skipped; conflicting duplicates (same record ID, different content) fail safely rather than silently overwriting.

Restores emit a sanitized `restore_decision` audit event with counts only. After the required key material is made available on the target system, restored records are searchable again because retrieval treats canonical storage as authoritative.

## Scheduling and scope

Export and restore are owner-initiated operations through the daemon-side engine; they never modify lifecycle, capture, or privacy state, and they never log archive content. Cross-version compatibility is guarded by the schema-version check; migration of older archives is a deliberate future change, not an automatic one.
