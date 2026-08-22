# Activity clustering and summaries

Local Recall derives activity sessions from already-redacted capture records. The capture-record store remains canonical; clusters and summaries are rebuildable derived state.

## Inputs and trust boundary

Activity processing accepts `RedactedRecord` values only. Raw screenshots, pre-redaction OCR, unapproved metadata, and remote-provider payloads are outside this boundary.

For each record, the feature stage derives:

- capture time and redaction-policy revision;
- normalized application and workspace metadata;
- the issue #20 deterministic perceptual image hash; and
- a semantic embedding produced by a configured **local** embedding provider from bounded redacted text and approved metadata.

A remote embedding provider is rejected before record content can be sent to it.

## Session boundaries

The segmenter processes records chronologically and preserves exact ordered source-record membership. It uses conservative adjacent change-point decisions rather than global clustering.

Hard boundaries include:

- the configured maximum time gap;
- workspace changes when both workspaces are known; and
- redaction-policy revision changes.

Within those boundaries, application continuity, perceptual similarity, semantic similarity, and short time gaps contribute bounded continuity evidence. Missing or low-confidence similarity evidence splits activities instead of aggressively merging them. This keeps rapid task switching and repeated use of the same application for unrelated work separable.

## Evidence-grounded local summaries

Summaries use the configured local generation provider only. There is no remote fallback.

The model is asked to select exact evidence spans from the redacted source context and return a strict JSON structure containing source record IDs and excerpts. Local Recall validates that:

- every cited record belongs to the activity cluster;
- every excerpt is a non-empty exact contiguous substring of that record's redacted OCR text;
- duplicate, foreign, malformed, oversized, or fabricated evidence is rejected; and
- provider and model identity are retained as provenance.

The stored v0.1 summary is extractive: it joins only validated model-selected evidence spans. This intentionally trades fluency for an enforceable no-invented-actions boundary. Free-form model prose is not accepted as factual activity history.

If the configured local generation provider is temporarily unavailable, clustering can still succeed and the derived entry is stored without a summary. Invalid generated evidence is a hard failure and does not replace the previous authoritative derived snapshot.

## Incremental reconciliation

Reconciliation starts from the current canonical redacted record set, re-extracts features, and deterministically rebuilds cluster membership. Each cluster receives an internal SHA-256 source fingerprint over its exact redacted source content, policy revision, approved metadata, pixels, and capture identity.

An existing summary is reused only when both exact ordered membership and the source fingerprint are unchanged. Therefore:

- unchanged activities avoid unnecessary regeneration;
- deleting a source record recomputes affected clusters;
- changing redacted content or metadata forces regeneration; and
- changing a redaction-policy revision forces a new derived state.

The replacement is prepared completely before the encrypted activity snapshot is committed. A generation/validation failure therefore leaves the previous snapshot intact rather than publishing partial derived state.

## Encrypted derived-state store

Clusters, source IDs, policy revisions, source fingerprints, summary text, and provider/model provenance are stored in one owner-only encrypted snapshot. The store uses the existing key-provider boundary with `KeyPurpose.SUMMARY`, a random per-snapshot data key, and XChaCha20-Poly1305 authenticated encryption.

The outer file contains only the cryptographic envelope. It is written atomically through an owner-only temporary file, fsynced, replaced, and followed by a parent-directory fsync. Tampering fails closed during authentication. The activity directory must be owner-only and symlinks are rejected.

No summary text, source record IDs, policy revision strings, or model/provider identities are written as plaintext derived-state metadata.

## Failure behavior

- Local embedding provider missing, remote, malformed, or incompatible: reconciliation fails before derived state replacement.
- Local generation provider temporarily unavailable: clusters persist with no summary.
- Generated evidence malformed or unsupported by source records: reconciliation fails and preserves the previous snapshot.
- Encrypted snapshot authentication or schema validation failure: load fails with a sanitized error.
- Empty canonical record set: derived state is atomically replaced with an empty encrypted snapshot.

All content-bearing values remain out of object representations and operational error messages.
