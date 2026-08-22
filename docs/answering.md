# Cited question answering

Local Recall answers personal-activity questions from the encrypted record corpus without treating generated summaries as evidence.

## Flow

1. The question planner requires one explicit or relative time scope and resolves it with the configured IANA timezone. Optional application and workspace selectors become retrieval filters.
2. The retrieval service narrows encrypted catalog candidates, decrypts only the bounded working set, applies query-time policy, and returns redacted `RetrievedPassage` evidence with canonical record IDs and capture timestamps.
3. The answering layer assigns request-local opaque labels such as `E1`. Model context contains the opaque label and redacted excerpt, not canonical record IDs.
4. The selected routing policy chooses a provider. `local-only`, `privacy-strict`, and `local-first` remain local; a local failure does not fall through to remote.
5. Generated output must use the closed structured claim schema. Local Recall validates every cited opaque label against the evidence table and reconstructs citations from canonical records.
6. Rendering adds the claim class (`Observed` or `Inference`), source record ID, and source capture timestamp. When an exact source record belongs unambiguously to a supplied activity cluster, the activity time span is included as additional provenance.

## Evidence rules

Observed claims must be supported directly by their cited redacted excerpts. Inferences are allowed only when explicitly typed as inference and still carry source citations. Unknown evidence labels, malformed output, duplicate keys, uncited claims, and unsupported observed text are rejected rather than repaired heuristically.

Empty or weak retrieval does not invoke a model. It returns `Insufficient evidence.` instead of inventing continuity.

Activity summaries are not canonical evidence. They may be regenerated and are downstream of source records, so factual citations always terminate at retrieved records and capture timestamps.

## Query scopes and output modes

The deterministic planner supports one time selector such as `today`, `yesterday`, a weekday, an ISO date, or a bounded `last N hours/days` expression. Application and workspace filters are explicit. Ambiguous or missing time scope is rejected rather than guessed.

`concise` preserves the validated claim order. `timeline` orders claims by their earliest canonical capture timestamp.

If activity-cluster membership is missing, stale, deleted, or ambiguous, rendering falls back to the record ID and capture timestamp. It never guesses a cluster.

## Provider routing and remote egress

Local answering sends a `GenerationRequest` classified as `REDACTED_CONTENT`. Provider capability and input-size limits are checked before generation.

Remote answering is opt-in only. It requires all of the following:

- the `remote-explicit` routing policy;
- retrieval policy marking the selected records remote-provider eligible;
- an explicit `EgressAuthorization` bound to the selected provider and redacted-text data class;
- the existing `EgressGate`, which rechecks data classes, payload size, and deterministic secret detection;
- a remote provider boundary that accepts only `ApprovedEgressPayload`.

The answering layer does not implement HTTP, credentials, retries, or provider-specific request formats. Those remain owned by the existing remote-provider subsystem. Canonical record IDs and timestamps are never placed in the model evidence context.

## Privacy and lifecycle boundaries

Question answering has no capture-control authority and cannot start, resume, pause, or otherwise mutate capture lifecycle state. Query work operates on the minimum policy-approved decrypted working set exposed by retrieval.

Question text, retrieved excerpts, generated output, provider prompts, and decrypted content must not be added to sanitized operational logs or exception text. Answering object representations expose only bounded structural metadata.
