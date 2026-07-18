# Local Recall

Local-first, encrypted desktop activity recall with explicit capture controls and optional remote AI providers.

## Design documents

- [v0.1 product requirements](docs/requirements.md)
- [Threat model and privacy invariants](docs/threat-model.md)
- [System architecture](docs/architecture.md)
- [Architecture decision records](docs/adr/README.md)
- [Domain models and strategy contracts](docs/domain-contracts.md)
- [Configuration and privacy profiles](docs/configuration.md)
- [Capture lifecycle and hard gate](docs/lifecycle.md)
- [Bounded in-memory capture pipeline](docs/pipeline.md)
- [Local OCR and deterministic redaction](docs/redaction.md)
- [Testing policy](docs/testing.md)

## Development

Requirements: CPython 3.14.x and `uv`, or Nix with flakes enabled.

```sh
./scripts/check
```

The canonical command syncs the exact `requirements.lock` environment and runs formatting, linting, shell linting, strict type checking, all populated test layers, direct failure-propagation checks, repository policy checks, secret scanning, and source security scanning.

```sh
nix develop -c ./scripts/check
```

Development follows red → green → refactor. Required tests may not be skipped or marked expected-failure.

Development is tracked through GitHub issues.
