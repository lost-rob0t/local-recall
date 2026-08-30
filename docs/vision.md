# Vision analysis for redacted screenshots

Issue #33 adds optional higher-level visual context extraction from already-redacted screenshots using a vision-capable model provider.

## Pipeline invariant

The only supported flow is `capture -> deterministic redaction -> authorized vision provider`. The vision boundary accepts only `RedactedFrame` values: the request type structurally rejects raw capture frames, and the service re-checks the frame type at every entry point, so an unredacted frame cannot reach any provider even through a tampered request object. Frames carry their redaction policy revision and finding counts with them; analyses are validated to be linked to the exact source record.

## Provider abstraction

`VisionProvider` is a single contract with `capabilities()` and `analyze(request)`. Providers declare the existing `ModelCapability.VISION` capability and their location. The same abstraction serves both execution modes with no separate product architecture:

- **local** providers are the default and require no network;
- **remote** providers run only through the existing `EgressGate` with an explicit per-query `EgressAuthorization` that is bound to the exact provider ID and grants `REDACTED_IMAGE`. Without that grant — or without the gate — remote analysis is refused with a sanitized reason. There is no silent local-to-remote fallback.

Provider unavailability never blocks OCR-based capture: `enrich_optional` returns no analysis instead of raising, and the bounded image input budget fails closed.

## Output schema

`VisionAnalysis` is a closed typed schema: linked record ID, provider ID, model version, visible application state, document type, broad task, and a 0..1 uncertainty value. There is no field for people, identity, biometric or personal attributes, hidden or occluded content, or free-form text; the dataclass boundary rejects malformed and out-of-range values. Outputs stay in memory with the record and are never persisted by the vision stage.

## Budgets

Image input is bounded (`max_image_bytes`, default 4 MiB) and rejected before a provider call. Providers' own `max_input_bytes` and availability are checked per request. Remote payloads pass through the egress gate's existing scanning, digest, and authorization-id binding.

## Tests

The issue tests prove: local enrichment of synthetic redacted records without network access, raw-frame rejection at construction and through tampered requests, schema validation and record linking, unavailability returning `None` from the optional path (capture continues OCR-only), remote refusal without a grant, refusal when the authorization lacks `REDACTED_IMAGE` or names a different provider, and successful gated remote analysis with a valid explicit image grant.
