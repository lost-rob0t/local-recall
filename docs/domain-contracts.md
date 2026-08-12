# Domain models and strategy contracts

Issue #5 establishes the stable, backend-neutral contracts used by later capture, redaction, encryption, storage, retrieval, and model-provider implementations.

Session lock/idle sources report bounded normalized control observations only. Capture, storage, and provider effects remain behind lifecycle/policy/pipeline boundaries; see [session-safety.md](session-safety.md).

## Stage-specific data flow

The capture pipeline uses distinct immutable Python types:

```text
CaptureIntent
  -> CaptureDecision(ALLOW)
  -> CaptureAuthorization
  -> ApprovedCaptureRequest
  -> RawFrame
  -> OCRResult
  -> RedactionRequest
  -> RedactedFrame
  -> RedactedRecord
  -> EncryptionRequest[RedactedRecord]
  -> EncryptedRecordEnvelope
  -> StoredRecordRef
```

A capture backend cannot accept an unapproved `CaptureIntent`. A storage backend has no method accepting raw pixels, OCR text, metadata, a `RawFrame`, or a `RedactedRecord`; its write method accepts `EncryptedRecordEnvelope` only.

Python type checking is not a complete security boundary. Constructors therefore validate runtime invariants as well, and concrete adapters must validate external input before constructing domain objects.

## Sensitive representations

Plaintext-bearing values are excluded from default representations:

- raw and redacted pixel buffers;
- OCR block text;
- redacted OCR text;
- generation prompts and contexts;
- model responses;
- retrieval excerpts and final answers;
- wrapped keys, nonces, ciphertext, and associated-data digests.

Redaction findings store locations, detector identifiers, reason codes, actions, and confidence. They never retain the matched secret or original field value.

## Metadata and provenance

`ContextMetadata` is a tuple of uniquely named `ContextField` values. Each field contains one or more `MetadataProvenance` records with:

- source identifier;
- timezone-aware observation time;
- confidence in the closed interval 0–1;
- optional adapter revision.

The metadata model contains no Xorg-, Qtile-, ActivityWatch-, or Wayland-specific fields. Adapters normalize source-specific values into named fields.

## Provider privacy contracts

`ProviderCapabilities` explicitly declares:

- local or remote location;
- generation, embedding, or vision capabilities;
- accepted privacy classifications;
- maximum input size;
- vision support.

A remote `RoutingDecision` is invalid without an explicit egress-authorization identifier. Provider strategies expose invocation mechanics; `ModelRoutingPolicy` owns eligibility and routing decisions.

## Strategy interfaces

The `local_recall.ports` package defines runtime-checkable protocols for:

- `CaptureBackend`;
- `MetadataSource`;
- `CapturePolicy`;
- `RedactionPolicy`;
- `EncryptionProvider`;
- `KeyProvider`;
- `StorageBackend`;
- `OCRProvider`;
- `EmbeddingProvider`;
- `GenerationProvider`;
- `ModelRoutingPolicy`;
- `Clock`.

Interfaces use domain types and contain no concrete backend configuration, SDK object, transport socket, database connection, desktop-session identifier, or provider-specific response type.

## Reusable contract tests

`tests/contract/suites.py` provides reusable suites for capture, metadata, embedding, generation, and encrypted storage adapters. Concrete implementations subclass the appropriate suite and supply factories for the implementation and synthetic request data.

Contract suites use synthetic data only. Adapter-specific tests may strengthen these contracts but may not weaken them.
