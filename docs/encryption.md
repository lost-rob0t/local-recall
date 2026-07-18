# Authenticated encryption and key providers

Issue #10 implements the encrypted boundary immediately after deterministic redaction. Every persisted record uses a random per-record data-encryption key (DEK), XChaCha20-Poly1305 authenticated encryption, and a versioned envelope. Storage receives encrypted envelope bytes only.

## Record format

Envelope schema version `2` stores:

- opaque record ID;
- algorithm and envelope version;
- non-secret wrapping-key handle and version;
- canonical associated data;
- SHA-256 associated-data digest;
- random 192-bit nonce;
- authenticated ciphertext;
- authenticated wrapped DEK;
- timezone-aware creation time.

Canonical associated data binds the record ID, capture generation, immutable configuration revision, creation time, algorithm, payload format, and exact frame sizes. Modifying any bound value, ciphertext, nonce, or wrapped key causes a sanitized authentication or format failure. No partial plaintext is returned.

The strict multipart codec uses six frames: bounded JSON header, associated data, wrapped DEK, nonce, ciphertext, and associated-data digest. It rejects unknown header fields, unsupported versions, wrong frame counts, inconsistent lengths, and oversized values.

## Configuration

A primary provider is explicit:

```toml
[encryption]
provider_id = "os-keyring"
algorithm = "xchacha20-poly1305"

[encryption.key_reference]
provider_id = "os-keyring"
reference = "local-recall-record-key"
```

GPG fallback is also explicit:

```toml
[encryption.fallback_key_reference]
provider_id = "gpg"
reference = "RECIPIENT-FINGERPRINT"
```

Effective-configuration inspection reports primary and fallback references as `<configured>` rather than exposing their configured names.

## Key providers

### OS keyring

`OSKeyringProvider` stores versioned 256-bit key-encryption keys in the configured operating-system keyring service. It distinguishes locked and unavailable backends, validates active-key pointers, supports rotation, and deletes revoked key versions. Key material is never placed in configuration, logs, exceptions, or object representations.

### Encrypted local key store

`LocalKeyStoreProvider` stores versioned key-encryption keys in an authenticated encrypted JSON document. A passphrase supplied at runtime derives the store key through Argon2id. The provider rejects symlinks, malformed or oversized documents, wrong passphrases, and revoked entries. Writes use a same-directory atomic replacement and mode `0600`; the temporary file contains encrypted key material only.

Recovery consists of restoring the encrypted key-store document and supplying the same passphrase. Loss of both makes affected records unrecoverable.

### Explicit GPG fallback

GPG is never selected implicitly. Configuration must provide `encryption.fallback_key_reference` with provider ID `gpg`. Fallback is considered only when the primary provider is unavailable. A locked or invalid primary faults closed and does not fall back.

GPG invocations use a fixed argument vector, no shell, standard input/output, finite timeout, validated executable basename, and sanitized result handling. The wrapped payload binds the record associated-data digest. GPG key creation, revocation, and recovery remain external operator actions.

## Rotation and revocation

Each record has an independent DEK. KEK rotation unwraps only the 32-byte DEK and rewraps it under the new provider key. Record ciphertext, nonce, and associated data remain byte-for-byte unchanged, and no plaintext file is created.

Old key versions remain resolvable until every dependent envelope has been rewrapped. Destroying or revoking a key makes envelopes still referencing it unreadable. Full algorithm migration is a separate bounded in-memory decrypt/re-encrypt operation and is not performed silently.

## Lifecycle and pipeline integration

`EncryptionLifecyclePreflight` health-checks and resolves the configured key before recording. Missing, locked, invalid, or unhealthy key providers return the sanitized `encryption_unavailable` lifecycle fault.

`EncryptionStageProcessor` accepts only `RedactedStageItem`, checks cancellation before and after encryption, and returns `EncryptedStageItem` containing the strict envelope codec frames. The existing pipeline performs the final generation check immediately before the encrypted sink commits.

## Residual limits

Python cannot guarantee complete memory zeroization. Mutable DEK and derived-key buffers are overwritten on best effort, but copies may exist transiently inside Python or libsodium. Root, kernel, debugger, and same-process compromise remain outside this control.
