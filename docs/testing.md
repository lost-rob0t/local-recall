# Testing policy

Local Recall uses test-driven development for all production behavior. All required development and CI checks target the standard CPython 3.14 series.

## Red → green → refactor

1. Add the smallest test that expresses the next required behavior.
2. Run the focused test and verify that it fails for the expected reason.
3. Implement only enough behavior to make the test pass.
4. Run the relevant layer and the canonical check command.
5. Refactor while keeping every required suite green.

Bug fixes start with a regression test that reproduces the defect. A production change without a prior observed failure is incomplete unless the change is pure documentation or repository plumbing.

## Canonical commands

```sh
./scripts/check
```

The command creates or synchronizes a Python 3.14 environment from `requirements.lock` and runs formatting, linting, shell linting, strict static typing, populated test layers, direct failure-propagation verification, repository-policy checks, secret scanning, and source security scanning.

Focused tests use the same failure-honest wrapper:

```sh
./scripts/run-pytest tests/unit/test_package.py
```

A NixOS development shell runs the same command:

```sh
nix develop -c ./scripts/check
```

## Runtime target

- Packaging requires `>=3.14,<3.15`.
- Bootstrap, CI, Ruff, Pyright, tests, and Nix must select Python 3.14.
- Python 3.13 and Python 3.15 are unsupported until a later ADR changes the target.
- The standard GIL-enabled CPython build is the v0.1 target; free-threaded builds require separate validation.

## Test layers

| Layer | Purpose |
|---|---|
| `tests/unit` | One class, function, or domain rule with no external service. |
| `tests/contract` | Shared strategy, Pykka actor, ZeroMQ framing, and port contracts. |
| `tests/integration` | Multiple real components with synthetic adapters and temporary encrypted storage. |
| `tests/security` | Privacy invariants, negative boundary tests, seeded leak scans, and abuse cases. |
| `tests/e2e` | User-visible acceptance scenarios over synthetic desktop activity. |
| `tests/failure_injection` | Crashes, timeouts, stale work, transport failure, and test-harness integrity. |

A behavior crossing a component or process boundary requires coverage at each materially different boundary. Unit coverage does not replace integration or end-to-end coverage.

An empty future layer is not invoked as a standalone required selection. Once a layer contains required tests, CI must execute it.

## Failure semantics

A required run fails when any of these occurs:

- an assertion fails;
- test collection or import fails;
- fixture setup or teardown fails;
- the test process crashes or receives a signal;
- a timeout expires;
- a required subprocess returns non-zero;
- no required tests are collected;
- a lint, format, type, policy, secret, or security scan fails.

The shell wrappers use strict error handling and pipeline failure propagation. Test output is intentionally piped through a neutral process inside `scripts/run-pytest`; the direct failure harness proves the original pytest status is preserved.

Required test and CI paths may not neutralize errors, return unconditional success, tolerate failed jobs, or treat an empty test selection as passing. The repository policy scanner checks the executable test and workflow paths for those constructs.

## Skips and quarantine

Required tests may not be skipped, disabled, filtered out, or marked expected-failure to obtain a green build.

A temporary quarantine requires all of the following:

1. a linked GitHub issue describing the defect and owner;
2. an explicit project-owner decision;
3. a separate CI-visible failing or quarantined job;
4. an expiry condition;
5. no effect on privacy/security release gates.

The default branch and release gate require zero skipped and zero expected-failure tests.

## Fixtures

- Fixtures are synthetic and deterministic.
- Tests never capture the developer or CI host screen.
- Tests never read personal Local Recall storage.
- Committed fixtures contain no real usernames, home paths, credentials, tokens, private keys, or machine-specific identifiers.
- Secret-redaction tests generate seeded synthetic values at runtime rather than committing values that resemble live credentials.
- Temporary files use pytest-provided temporary directories and are deleted after the test.
- Test output must not print captured payloads, secrets, absolute personal paths, or provider request bodies.

## Failure-injection verification

`scripts/verify-failure-modes` runs isolated known-failing fixtures and succeeds only when each nested run returns non-zero. The canonical check invokes it directly, and CI runs it as an independent required Python 3.14 job. It verifies:

- assertion failure;
- collection failure;
- process crash;
- signal termination;
- timeout;
- teardown failure;
- zero-test selection;
- piped-output status preservation.

The fixtures use a non-Python extension so normal pytest discovery can never execute them directly.

## Session-safety tests

Lock/idle coverage uses synthetic logind, ActivityWatch, Xorg-idle, lifecycle, and clocks only. Tests never inspect or manipulate the developer/CI desktop session. Lock races are validated through generation invalidation and policy authorization rather than real screenshots.
