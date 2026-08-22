# Remote providers and explicit egress

Remote model access is optional and disabled by default. Local Recall treats provider routing and network egress as separate security decisions: choosing a remote-capable provider never grants permission to send data.

## Routing modes

- `privacy-strict`: local providers only. Remote routing is forbidden.
- `local-only`: local providers only. Remote routing is forbidden.
- `local-first`: selects a suitable local provider. A local outage or provider error does **not** fall back to remote.
- `remote-explicit`: a remote provider may be selected only when the request carries an explicit `EgressAuthorization` for that exact provider and every requested data class.

A provider failure never causes Local Recall to retry through a different provider or a less-private route.

## Egress authorization

Remote requests require an immutable authorization containing:

- an opaque authorization ID;
- the exact remote provider ID;
- the allowed egress data classes;
- a maximum payload size.

The supported egress classes are `redacted-text`, `approved-metadata`, and `redacted-image`. Images are denied unless the authorization explicitly includes `redacted-image`.

Before any remote request is constructed, `EgressGate`:

1. verifies that every present modality is authorized;
2. deterministically scans text and metadata values for secrets;
3. rejects sensitive metadata names;
4. computes the canonical byte count and SHA-256 digest;
5. enforces the authorization byte limit;
6. returns an immutable `ApprovedEgressPayload`.

Only `ApprovedEgressPayload` values may enter the remote-provider request boundary. Raw captures, unredacted OCR, secret material, arbitrary metadata, and ordinary generation requests are not accepted by that boundary.

The approved payload exposes only control metadata in `repr`; text, metadata values, images, credentials, request bodies, and headers remain excluded.

## Provider configuration

Remote providers are individually disabled unless explicitly enabled. An enabled provider requires `kind`, an HTTPS `endpoint`, `model_id`, and a credential reference.

Example OpenAI-compatible provider:

```toml
[models]
remote_enabled = true

[[models.remote_providers]]
provider_id = "openai-main"
enabled = true
kind = "openai-compatible"
endpoint = "https://api.openai.com/v1/chat/completions"
model_id = "configured-model"

[models.remote_providers.credential_reference]
provider_id = "os-keyring"
reference = "openai-main"
```

Supported provider kinds are:

- `openai-compatible`;
- `openrouter`;
- `anthropic`;
- `google`.

Provider protocol details are kept behind project-owned request builders. OpenRouter requests explicitly disable upstream provider fallback. Google endpoints must bind the configured model ID in the `models/<model>:generateContent` path.

## Credential handling

Credentials are references in configuration, never inline secret fields. The built-in remote credential provider resolves `os-keyring` references immediately before request construction using the dedicated Local Recall remote-credential service namespace.

Resolved credentials:

- are excluded from representations;
- reject control characters;
- are inserted only into the fixed authentication header for the selected provider;
- are never returned in provider results, status, or errors.

Credential backend failures use fixed sanitized reason codes.

## HTTPS transport boundary

The built-in transport accepts only HTTPS origins and performs a direct TLS connection with normal certificate and hostname verification. It does not consume proxy configuration or follow redirects.

Requests are fixed to `POST`; host, content length, and connection headers are transport-owned. Header names and values are validated against injection. Request bytes, response headers, response bytes, and total execution time are bounded.

Responses must be HTTP/1.1 `200` with a single valid `Content-Length`. Redirects, transfer encoding, malformed or duplicate headers, oversized responses, truncated bodies, invalid JSON, TLS failures, and timeouts fail with sanitized reason codes. Provider response bodies are never included in transport errors.

Retries are bounded and remain on the same already-authorized request. Only explicitly classified transient transport failures are retried. Cancellation propagates immediately; deadline exhaustion fails closed. No retry path selects another provider.

## Remote-provider request shapes

Current remote adapters accept approved redacted text only. Metadata and images may be authorized by the central egress model, but provider request builders reject those modalities until a provider-specific safe encoding is deliberately implemented and tested.

Request builders emit only the reviewed provider fields:

- OpenAI-compatible: model plus one user message;
- OpenRouter: the OpenAI-compatible shape plus `provider.allow_fallbacks = false`;
- Anthropic: model, bounded `max_tokens`, and one user message;
- Google: one `generateContent` text part with the configured model bound in the endpoint.

This intentionally avoids arbitrary caller-provided headers, provider options, tools, routing hints, or extension dictionaries.

## Failure and privacy semantics

Remote access is fail-closed:

- local-provider failure does not create remote permission;
- a missing or mismatched authorization prevents routing;
- a provider authorization cannot be used for another provider;
- secret detection or payload-limit failure prevents request construction;
- redirects are rejected rather than followed;
- cancellation and timeout do not trigger alternate routing;
- remote provider errors never cause fallback to another provider.

Tests use injected transports and credential backends rather than real credentials or external provider traffic. The canonical repository gate remains `./scripts/check`.