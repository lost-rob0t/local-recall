# End-to-end acceptance, reliability, and performance

**Status:** v0.1 E2E layer for issue #39.
**Authority:** scenarios run against isolated synthetic desktops; they never inspect a real screen, never touch the developer session, and never use real credentials.

## Canonical command

```bash
./scripts/e2e                     # run every E2E scenario
./scripts/e2e tests/e2e/test_saturday_scenario.py   # one scenario
./scripts/verify-e2e-failure-modes  # self-test: injected failures must fail
```

`scripts/e2e` wraps the canonical runner (`set -Eeuo pipefail`, no `|| true`, no unconditional success). `scripts/verify-e2e-failure-modes` injects one failing scenario at a time (assertion, crash, timeout, teardown, zero `-k` selection, piped output) and succeeds only when every injected failure returns non-zero. It is part of the canonical gate (`./scripts/check`) and of the required CI failure-propagation job.

Zero selected, discovered, or executed scenarios fail the command (exit code 5 or collection error, both non-zero).

## Harness

`tests/e2e/harness.py` composes the real system over a deterministic synthetic desktop:

- synthetic capture backend and OCR provider (text lines keyed per frame; no pixels from any real display);
- the real redaction policy, envelope cipher with an in-memory keyring backend, SQLite encrypted storage, encrypted semantic index, retrieval, cited answering, lifecycle gate/actor, audit recorder, and the health subsystem with live ports;
- a deterministic scenario clock (capture timestamps, retention age, time-scoped questions) so scenarios never depend on wall-clock time.

Simplification: the synthetic embedding model is topical-permissive (a shared baseline component keeps cosine similarity above the retrieval floor) so scenarios exercise retrieval/citation plumbing rather than embedding-model semantics.

## Scenarios

| file | scenario |
| --- | --- |
| `test_lifecycle_scenario.py` | start → record → pause → resume → stop → restart → query; persistence halts within bounds after stop |
| `test_metadata_fallback_scenario.py` | Qtile probe preferred, generic Xorg fallback when the specialized source is unavailable, synthetic-desktop metadata recorded with provenance |
| `test_safety_failures_scenario.py` | session-lock pause, keyring lock (health `capture-blocking` + encryption fault, no record), low disk (`capture-blocking` + persistence refused), corrupted index (degraded → rebuild repair recovers), model outage (answering fails, capture continues) |
| `test_saturday_scenario.py` | "What was I doing Saturday?" over records from Saturday/Sunday/Monday; every citation resolves to a Saturday record; generation requests carry `redacted-content` |
| `test_soak_scenario.py` | 120-capture soak: latency budget, byte budget, index/storage agreement, retention sweep reclaims records |
| `test_offline_scenario.py` | local-only profile: local embeddings + local generation answer with citations; no remote provider configured; egress never authorized |

## Performance budgets

Budgets are enforced as scenario assertions; a violation fails the E2E command (and the canonical gate), it is never a warning. They are calibrated for CI runners and in-process synthetic workloads; release-time validation on reference hardware (8B-class local model) must re-measure them and record the results in the release report.

| budget | value (CI) | where asserted |
| --- | --- | --- |
| capture tick latency (synthetic backend) | < 0.5 s per capture | soak scenario |
| stop/persistence halt bound | < 2 s from stop to gate `off`, no records afterwards | lifecycle scenario |
| query latency (cited answer over the soak corpus) | < 2 s | soak scenario |
| storage growth | < 16 KiB per synthetic record (real envelope crypto) | soak scenario |
| in-flight work | bounded by construction (scenario steps drive ticks synchronously; no unbounded background queues) | harness design |
| idle CPU / peak memory / OCR throughput / model resource budgets | not measurable in CI; release-report items measured on reference hardware | release gate #41 |

Soak resource boundedness is asserted through record/index agreement and storage byte budgets; the scenario runner itself has no retry, no `continue-on-error`, and no swallowed exceptions.

## Failure semantics

- Every child process, subprocess, and piped stage propagates its exit status (the runner inherits `scripts/run-pytest` semantics; `scripts/verify-e2e-failure-modes` re-proves it per mode).
- Retries are not used anywhere in the E2E layer; transient classification is not required because scenarios are deterministic.
- A release report must record passed scenarios, exact failures, and known limitations without relabeling failures as passes.
