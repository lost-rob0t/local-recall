# ADR-0001: Use Python 3.13+ for the v0.1 daemon

- **Status:** Accepted
- **Date:** 2026-07-17
- **Decision owners:** Local Recall project
- **Related:** #3, `NFR-002`, `NFR-006`, `NFR-007`, `NFR-008`

## Context

Local Recall needs mature libraries for Linux desktop capture, image processing, OCR, local and remote model APIs, encryption bindings, Unix IPC, CLI development, testing, and Nix packaging. It also needs rapid test-driven implementation with strong runtime validation at untrusted boundaries.

The runtime handles sensitive in-memory data, but language memory safety alone cannot enforce the core privacy properties. Those properties depend primarily on lifecycle authority, stage-specific types, fail-closed validation, encrypted-only storage, bounded concurrency, and tests.

## Decision

The v0.1 daemon and CLI will use **Python 3.13 or newer within the Python 3.x line**.

The initial toolchain is:

- `uv` for environment creation, dependency locking, commands, and packaging workflow;
- AnyIO for structured concurrency, task groups, cancellation scopes, capacity limiters, and bounded memory streams;
- Pydantic v2 for external configuration, IPC, adapter, and provider boundary validation;
- frozen standard-library dataclasses or similarly immutable typed domain objects internally;
- Typer for the CLI;
- pytest and Hypothesis for TDD, contract, state-machine, property, and failure-injection tests;
- Ruff for formatting/linting and Pyright in strict mode for static type checking;
- Nix flakes for reproducible development, checks, and packaging.

The project will avoid untyped dictionaries at security boundaries. Native-library calls and blocking operations must be wrapped by narrow adapters, bounded with timeouts and capacity limits, and covered by negative tests.

## Dependency policy

- Dependencies are pinned in the lock file.
- Security-critical dependencies are kept minimal.
- A dependency cannot write capture data to temporary files unless the architecture and threat model are updated.
- Model SDKs are optional adapter dependencies where practical; OpenAI-compatible providers should prefer a small HTTP client over pulling multiple heavyweight SDKs.
- Runtime imports must not download models, binaries, or data.

## Consequences

### Positive

- Strong OCR, image, model, test, and Linux integration ecosystem.
- Fast implementation and broad contributor familiarity.
- Pydantic provides runtime checks where static typing is insufficient.
- AnyIO supports deterministic structured concurrency and test backends.
- Nix and `uv` can produce a reproducible developer and release workflow.

### Negative

- Python cannot guarantee complete memory zeroization of plaintext or keys.
- The GIL limits CPU-bound Python execution.
- Native OCR/image libraries may crash the daemon process.
- Static types do not prevent runtime misuse by themselves.

These limitations are addressed by minimizing plaintext lifetime, using native libraries behind narrow ports, bounding worker use, treating daemon crashes as fail-closed, restarting into `off`, and testing runtime boundary rejection.

## Alternatives considered

### Rust

Rust offers stronger memory safety and explicit ownership but would slow initial OCR/model integration and TDD iteration. Rust remains viable for future hardened helpers after profiling or threat analysis demonstrates a concrete need.

### Go

Go offers simple deployment and concurrency but has a weaker local AI/OCR ecosystem for this project and does not solve plaintext lifetime or provider-boundary policy by itself.

### Common Lisp

Common Lisp and actor libraries align with the owner’s broader systems work, but Python currently provides a more direct path to OCR, desktop, model, and security-testing dependencies for this standalone application. Local Recall should not depend on Star Intel or its RabbitMQ/CouchDB runtime.

### Multiple languages from the start

A split Python/Rust or Python/Common Lisp system would add IPC boundaries, packaging work, and more locations where sensitive data can exist. v0.1 remains one language unless a later ADR justifies a narrow helper process.

## Verification

Issue #4 must establish checks proving:

- the locked environment builds reproducibly;
- strict type checking and linting fail non-zero;
- zero collected tests fail;
- known failing tests propagate through the canonical command;
- no dependency or test fixture writes real capture data;
- the Nix development environment runs the same canonical checks.