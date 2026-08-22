# Time-scoped retrieval and provenance

Local Recall retrieves already-redacted activity records through a bounded, policy-gated working set. Storage remains canonical for record existence and the retrieval layer does not select or call model providers.

## Time selectors

Retrieval resolves time expressions with the configured IANA timezone and converts the result to an aware half-open interval `[start, end)`.

The v0.1 deterministic grammar supports:

- an ISO calendar date such as `2026-08-22`;
- `today` and `yesterday`;
- a bare weekday such as `Saturday`, resolved to the most recent occurrence including today;
- `last N minutes`, `last N hours`, and `last N days` with bounded positive `N`.

A selector may appear inside a larger question when exactly one supported selector is present. Ambiguous or unsupported expressions fail instead of guessing. Directional weekday phrases such as `last Saturday`, `next Monday`, and `this Friday` are deliberately unsupported in v0.1.

Calendar-day selectors use local midnight to the next local midnight before conversion to UTC. They therefore preserve the user's calendar-day intent across daylight-saving transitions instead of assuming every local day is exactly 24 hours.

## Candidate selection and decryption

The plaintext SQLite catalog retains only the existing coarse UTC day bucket and opaque encrypted-record metadata. Retrieval does not add exact timestamps, application names, workspace names, OCR text, titles, or other captured content to that catalog.

A query proceeds in stages:

1. resolve the exact aware time interval;
2. request only encrypted candidates in the coarse UTC day buckets intersecting that interval;
3. when semantic text is requested, use the encrypted semantic index only to narrow and score IDs that are also present in canonical storage;
4. decrypt the remaining bounded candidate set through `EncryptionProvider`;
5. apply exact timestamp, application, workspace, metadata, and keyword filters to the decrypted redacted record in memory;
6. re-check query policy before access and record policy before returning each record;
7. return bounded passages with record ID, capture timestamp, redacted excerpt, metadata provenance/confidence, redaction revision, and redaction finding count.

A stale semantic-index hit cannot resurrect a deleted storage record. Query-policy denial occurs before catalog access and decryption.

## Ranking

Ranking is deterministic. Semantic score is used when semantic retrieval is requested. Keyword-only retrieval uses exact keyword evidence. Otherwise source metadata provenance confidence supplies the ranking score. Capture timestamp and record ID provide stable tie-breaking.

Retrieved passages preserve field-level source ID, observation timestamp, adapter revision, and confidence so downstream cited answering can trace a claim back to the retained record rather than relying on generated prose as authority.

## Provider routing

Retrieval carries only whether the complete selected working set remains eligible for remote-provider use under query-time policy. It cannot mint remote authorization or perform network egress. The routing and `EgressGate` boundary from the provider-routing subsystem remains authoritative for any later model request.

A policy revision change observed while records are being selected invalidates the current result rather than mixing records authorized under different query-policy revisions.

## Working-set lifetime

Decrypted records and excerpts are scoped to the retrieval coroutine and are not written to a new plaintext cache or index. Cancellation and failures propagate instead of returning a partial successful batch.

Python can release references to decrypted objects when a query completes or is cancelled, but CPython does not provide a reliable physical-zeroization guarantee for immutable `str` or `bytes` objects. Local Recall therefore does not claim secure memory erasure; the enforceable guarantees are bounded lifetime, no new plaintext persistence, and no content in sanitized control/error representations.
