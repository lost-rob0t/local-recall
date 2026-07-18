# ADR-0005: Use static capability-limited extension boundaries

- **Status:** Accepted
- **Date:** 2026-07-17
- **Decision owners:** Local Recall project
- **Related:** #3, `FR-META-003`, `FR-STO-003`, `FR-AI-001`, `FR-AI-005`–`FR-AI-013`, `INV-007`, `INV-014`, `INV-015`

## Context

Local Recall needs replaceable capture, metadata, OCR, key, storage, embedding, generation, and remote-provider implementations. A conventional Python plugin system that imports arbitrary modules from configuration would give third-party code the same process privileges as the daemon, including access to raw frames, decrypted memory, keys, storage, IPC, and network facilities.

That would make the strategy pattern cosmetically flexible while destroying the actual privacy boundary.

The architecture therefore needs extension points without treating every extension as fully trusted or granting every adapter the complete application container.

## Decision

v0.1 uses a **static built-in registry of strategy implementations** and **capability-limited ports**.

Configuration selects an adapter by a stable registered identifier such as:

```text
capture.xorg
metadata.qtile
metadata.activitywatch
ocr.local
keys.secret_service
keys.gpg
storage.sqlite_blob
generation.ollama
remote.openai_compatible
```

Configuration cannot:

- import an arbitrary Python module;
- specify an entry-point package to load;
- evaluate Python;
- invoke a shell command;
- replace a security-critical strategy with an unknown implementation.

Adding a built-in adapter requires normal source review, tests, and release packaging.

## Ports and capabilities

Each strategy implements a narrow protocol and receives only the capabilities needed for that role.

### Capture backend

Receives:

- an `ApprovedCaptureIntent`;
- a platform-specific capture client;
- bounded memory allocation and clock capabilities.

Does not receive:

- storage;
- key providers;
- model providers;
- policy mutation;
- general network access.

### Metadata source

Receives:

- a fixed local API/IPC client;
- deadlines and output-size limits;
- field-level collection policy.

Does not receive raw storage, key access, remote egress, or shell interpolation.

### OCR provider

Receives a bounded in-memory image view and OCR options. It cannot write output files or call model/provider routing.

### Key provider

Receives only non-secret key references and operation requests. It cannot access captured content, query text, storage iteration, or arbitrary audit fields.

### Storage backend

Receives only `EncryptedEnvelope`, minimized catalog values, and explicit deletion/recovery requests. There is no generic `put(bytes)` or filesystem capability for upstream components.

### Generation/embedding provider

Receives only typed, approved requests. It cannot mutate lifecycle, read arbitrary records, access key material, or choose a routing policy.

### Remote provider

Receives an `AuthorizedEgressPayload` and a restricted network client supplied by `EgressGate`. It never receives a general application client or raw/redacted internal record object.

## Central policy decisions

Adapters perform mechanics, not privacy decisions.

- `PolicyActor` decides capture and processing eligibility.
- `ProviderRouterActor` decides provider eligibility.
- `EgressGate` decides whether a specific payload may leave the machine.
- `LifecycleActor` decides whether capture work is current.
- `StorageWriterActor` performs the final generation check.

An adapter error cannot select another adapter with weaker privacy. Fallback is an explicit policy decision over already registered strategies.

## External services

Qtile, ActivityWatch, Ollama, GPG, and remote providers are treated as untrusted services behind adapters.

Adapters must apply:

- fixed endpoint or executable configuration;
- no shell interpolation;
- schema validation;
- output and request size limits;
- deadlines and bounded retries;
- sanitized error conversion;
- provenance and capability reporting;
- explicit network classification.

Localhost is not considered trusted input.

## Future script adapters

General script-based metadata adapters are deferred to issue #34 and require a threat-model update.

The minimum future design must include:

- explicit absolute-path allowlisting;
- owner and mode validation;
- symlink and replacement defense;
- optional content-hash pinning;
- fixed argument vectors with no shell;
- minimal environment allowlist;
- bounded stdout/stderr and timeout;
- strict versioned JSON output;
- no inherited secrets or general daemon file descriptors;
- conservative failure behavior.

Script adapters cannot become a generic command-runner feature.

## Future third-party plugins

Third-party in-process plugin loading is not planned for v0.1. If introduced later, it requires a new ADR choosing one of:

- fully trusted reviewed in-process code;
- a separately sandboxed helper process with a narrow protocol;
- WebAssembly or another capability sandbox.

The new design must cover raw-data transport, filesystem/network capabilities, key isolation, packaging, signature/update trust, and crash behavior.

## Contract tests

Every port has a reusable contract suite. An adapter is not registered unless it passes:

- successful operation behavior;
- malformed and oversized input/output behavior;
- timeout and cancellation behavior;
- capability denial tests;
- sanitized-error tests;
- no-plaintext-persistence scans where applicable;
- stage-type rejection tests;
- non-zero failure propagation meta-tests.

Security-critical adapters also require integration tests using synthetic services or desktop fixtures.

## Consequences

### Positive

- Strategy pattern remains useful without arbitrary code execution.
- Privacy decisions stay centralized and auditable.
- Adapters are easier to contract-test.
- Remote providers cannot silently obtain storage, key, or raw-frame capabilities.
- Future sandboxing can be added behind the same ports.

### Negative

- Users cannot install arbitrary third-party provider packages in v0.1.
- Adding an adapter requires a source change and release.
- Python process isolation between built-ins is not provided.
- Capability discipline requires careful dependency injection and negative tests.

## Alternatives considered

### Python entry points or arbitrary module paths

Rejected because imported code executes with daemon privileges and can bypass all ports.

### Pass the full application container to adapters

Rejected because it makes narrow interfaces meaningless and enables lateral access to keys, storage, policy, and network.

### Run every adapter in a subprocess

Deferred. It increases protocol, packaging, and raw-data transport complexity. Narrow subprocesses may be justified later for high-risk or unstable adapters.

### No strategy abstraction

Rejected because Xorg/Wayland, key providers, model providers, and storage implementations must remain replaceable without changing core policy/data flow.

## Verification

Issues #4, #5, #13–#16, #21–#23, and #34 must prove:

- only registered identifiers can be configured;
- arbitrary imports and shell commands are rejected;
- each adapter receives only its declared capabilities;
- storage cannot accept raw/redacted types;
- remote adapters cannot be reached without `AuthorizedEgressPayload`;
- local provider failure cannot instantiate a remote strategy automatically;
- adapter output is bounded and validated;
- malicious synthetic adapters cannot mutate lifecycle or read keys through the public port;
- contract-suite failures remain non-zero.