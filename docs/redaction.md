# Local OCR and deterministic pre-persistence redaction

Issue #9 establishes the plaintext privacy boundary between the analyzed and redacted pipeline stages. Raw pixels, OCR text, and unredacted metadata remain process-local and may exist only before this boundary. A record that does not complete redaction is rejected; there is no partial or degraded persistence path.

## Pipeline placement

```text
RawStageItem
  -> LocalOCRStageProcessor
  -> AnalyzedStageItem         # raw pixels + OCR, memory only
  -> PrePersistenceRedactionStageProcessor
  -> RedactedStageItem         # masked pixels + scrubbed text/metadata
  -> encryption                # issue #10
```

Both plaintext edges use the existing bounded `inproc://` ZeroMQ data plane. Pykka owns worker lifecycle. The stage codecs use strict versioned JSON headers and separate binary pixel frames; they never use pickle, temporary image files, filesystem spooling, or a network service.

## Local OCR

The v0.1 OCR provider is `tesseract-local`. It invokes the `tesseract` executable with `create_subprocess_exec`, sends an in-memory P5/P6 image through standard input, and reads TSV from standard output. It does not create a temporary image or invoke a shell. The executable basename, language identifiers, input limit, and finite timeout are validated configuration.

Tesseract failures are represented by frame UUID and a fixed code only:

- `executable_unavailable`;
- `input_too_large`;
- `execution_failed`;
- `timeout`;
- `malformed_output`.

Standard error and OCR content are never included in the exception string or representation.

## Deterministic detectors

The deterministic detector runs before any optional model-assisted classification. It covers:

- common cloud and developer access/API token formats;
- authorization headers;
- private-key blocks;
- password, username, token, and client-secret assignments;
- credential-bearing database and broker connection strings;
- account keys;
- JWTs;
- email addresses;
- configurable custom regular expressions;
- configurable high-entropy tokens, including long hexadecimal values;
- percent-encoded and Base64/Base64URL representations of deterministic matches.

High-entropy matches require a minimum length, measured Shannon entropy, and multiple character classes, except for sufficiently long hexadecimal tokens. A provider-specific match takes precedence over an overlapping generic entropy match.

## Redaction behavior

For every deterministic OCR match, the policy:

1. replaces the matching text span with `[REDACTED]`;
2. masks the complete OCR bounding box in the pixel buffer;
3. records detector ID, kind, action, target, confidence, and region/span without the matched value.

For metadata, sensitive field names or detected values cause the complete field to be dropped. Low-confidence OCR blocks are conservatively replaced and masked in full. Every OCR region is validated against frame bounds before detection, so malformed or malicious OCR output rejects the entire record even when no secret pattern matches.

Metadata collected by built-in sources, including generic Xorg `application` and
`window.title`, enters this same analyzed-stage policy. Sources have no persistence port and
cannot mark a value as already redacted. Tests construct generic-Xorg metadata synthetically,
carry it through the bounded pipeline, and verify that sensitive application/title values are
dropped before the encryption processor or persistence sink can receive the record.

The policy fails closed when redaction is disabled, deterministic filters are disabled, reject-on-uncertainty is disabled, the policy revision is stale, frame identity changes, a region is invalid, a codec fails, or a detector/policy operation fails.

## Allowlists

Allowlists are deliberately narrow:

- exact values only;
- at most sixteen values per entry;
- one named built-in or configured custom detector per entry;
- unknown detector IDs are rejected during configuration validation;
- model-assisted classification cannot define an allowlist.

A successful allowlist decision records only allowlist ID, detector ID, target, optional metadata field, and a SHA-256 digest of the value. Effective-configuration inspection reports the number of configured values but not the values themselves.

## Persistence and logging boundary

`AnalyzedStageItem` may contain raw OCR and unredacted metadata, but its representation exposes only record identity and frame sizes. `RedactedStageItem` is constructed only after pixel, OCR, and metadata redaction succeeds. Downstream encryption and storage must accept only this redacted stage and later encrypted types.

Worker faults contain record UUID, stage, and fixed fault code. OCR output, matched text, metadata values, subprocess standard error, and pixel content are excluded from logs, events, exception messages, and object representations.

## Verification

Tests use synthetic frames and synthetic provider-shaped tokens only. They verify:

- common provider and credential patterns plus encoded variants;
- measured high-entropy true-positive and false-positive fixtures;
- exact, pattern-scoped allowlists and digest-only audit decisions;
- Tesseract stdin/stdout operation without temporary files;
- pixel, OCR-text, and metadata redaction;
- low-confidence conservative masking;
- codec identity and malformed-input rejection;
- full pipeline processing where storage sees only synthetic ciphertext;
- no network, storage, temporary-file, pickle, or shell dependency in the redaction package;
- complete-record rejection and sanitized fault events on redaction failure.
