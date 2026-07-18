# Encryption and key-provider strategies

Local Recall encrypts every persisted capture record after deterministic redaction and before the storage boundary. Storage implementations receive authenticated encrypted envelopes only.

## Record envelope

The current envelope schema is version `1` and uses `xchacha20-poly1305-ietf` through PyNaCl/libsodium.

Each record receives a new random 256-bit data-encryption key (DEK). The DEK encrypts the complete redacted pipeline payload in memory. The selected key provider wraps the DEK under a versioned master key or external recipient.

The authenticated associated data includes:

- envelope schema and algorithm;
- record UUID;
- capture generation;
- configuration revision;
- creation timestamp;
- exact plaintext frame sizes.

Changing authenticated metadata, ciphertext, nonce, frame sizes, or the wrapped key causes decryption to fail. Authentication failures expose the record UUID and a fixed error code only.

The persistent envelope contains:

- record UUID;
- capture generation and configuration revision;
- schema and algorithm identifiers;
- key-provider ID, key ID, and key version;
- authenticated plaintext frame sizes;
- wrapped DEK;
- nonce;
- ciphertext;
- associated-data digest;
- creation timestamp.

It never contains an unwrapped DEK or master key.

## OS keyring provider

`os-keyring` is the primary local key-provider strategy. Its backend stores versioned master keys and a small active-version pointer. Application configuration contains a key reference, not key material.

A master-key version is retained after rotation so existing records remain decryptable until they are rewrapped or deliberately revoked. Destroying a key version makes records still wrapped by that version unrecoverable.

The runtime keyring adapter is loaded lazily. Missing keyring support, a locked backend, malformed key material, or an unavailable key fails closed. Backend exception text is not copied into application errors.

## Explicit GPG fallback

GPG is never selected automatically. It is eligible only when configuration explicitly sets:

```toml
[encryption]
provider_id = "os-keyring"
algorithm = "xchacha20-poly1305-ietf"
fallback_provider_id = "gpg"
gpg_recipient = "configured-recipient"
gpg_executable = "gpg"
gpg_timeout_seconds = 10.0
```

The primary provider is health checked first. The configured GPG provider is considered only after primary failure and must pass its own recipient health check. Omitting `fallback_provider_id` prevents fallback even when a GPG provider is registered.

GPG receives and returns wrapped DEK material through standard input and standard output. It does not receive record ciphertext or redacted record plaintext, and no temporary plaintext key file is created. The GPG recipient is hidden from effective-configuration inspection.

GPG recipient rotation requires explicit configuration change. The application does not mutate an external GPG keyring or guess a replacement recipient.

## Rotation and rewrap

Local key rotation creates a new active master-key version. Existing records can then be rewrapped:

1. authenticate the stored envelope metadata;
2. unwrap only the record DEK with the old provider/key version;
3. wrap that DEK with the new provider/key version;
4. replace the envelope key handle and wrapped-DEK field;
5. retain the original record ciphertext and nonce unchanged.

Rewrap does not decrypt record content and does not write plaintext files. Old master keys should be revoked only after all intended records have been rewrapped and verified.

A full cryptographic migration may decrypt and re-encrypt in bounded memory when the record algorithm changes. It must use the same no-plaintext-file rule and write the replacement envelope atomically through the storage issue.

## Recovery and revocation

Recovery requires access to the exact provider and key version named by the envelope. Backups therefore need the encrypted records plus an independently protected key-provider recovery procedure.

Revocation behavior is deliberate:

- revoking an unused old version is safe after successful rewrap verification;
- revoking a version still referenced by records performs cryptographic deletion of those records;
- a missing, locked, invalid, or revoked key prevents persistence or recovery;
- there is no silent GPG, plaintext, alternate-cipher, or newly generated-key fallback for an existing envelope.

## Pipeline boundary

`EnvelopeEncryptionStageProcessor` accepts `RedactedStageItem` and produces `EncryptedStageItem`. It checks cancellation before key selection and after encryption. Provider failure produces no encrypted stage item, and the existing pipeline fault bridge transitions capture according to lifecycle policy.

The encrypted-stage codec validates record identity, capture generation, configuration revision, codec version, and exact binary frame sizes before constructing an envelope.

## Sensitive-memory limits

Python and native-library buffers may transiently contain redacted plaintext and key material. Local Recall minimizes this exposure by:

- creating one random DEK per record;
- keeping encryption and rewrap in memory;
- destroying mutable `SecretKeyMaterial` buffers after use;
- zeroing the aggregate plaintext encryption buffer;
- excluding key material, plaintext, subprocess stderr, and ciphertext from logs and exceptions;
- prohibiting plaintext temporary files and filesystem queues.

These controls do not claim protection against a compromised kernel, root process, debugger, or same-process memory disclosure.
