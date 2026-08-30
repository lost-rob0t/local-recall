# Local Recall — Autonomous Continuation Handoff

You are continuing an in-progress, multi-session autonomous implementation of the
`lost-rob0t/local-recall` repository. Prior sessions closed #2–#34 (all P0/P1) plus #60's
dependency #33. Work issue-by-issue in dependency order until the release gate (#41) is
satisfied. Do not stop after one issue. Do not re-scope, redesign, or invent epics.

## Immediate next action

1. `git checkout main && git pull origin main`
2. `gh issue list --state open` — remaining queue in dependency order:
   - **#35** Wayland portal capture (deps: #13,#17,#19,#29 ✓)
   - **#37** health checks/diagnostics/safe repair (deps: #12,#22,#27,#29,#31 ✓)
   - **#38** security regression/fuzz/test-integrity (deps ✓)
   - **#39** E2E/reliability/performance (deps ✓)
   - **#36** timeline UI (deps #28,#29,#30,#31 ✓)
   - **#40** Nix packaging (deps #27,#28,#29,#37,#39 — needs #37 and #39 first)
   - **#41** release gate (deps #38,#39,#40)
   - **#60** Zara visual-context IPC (deps satisfied via #33)
3. Start with **#35** (or #37 if #35 proves environment-blocked — portal capture may
   require a real Wayland session; if genuinely untestable in CI, implement everything
   testable and if acceptance criteria cannot be fully met, do NOT close it; document
   the human blocker in the RAGE file and move on without closing).
4. For each issue: create branch `agent/issue-NN-<slug>` from main.

## Per-issue loop (mandatory)

1. `gh issue view NN` — read completely, including acceptance criteria.
2. Check for existing branch/PR first; resume if present.
3. Strict RED→GREEN: write behavioral tests FIRST; create minimal module scaffolding so
   ruff/format/shellcheck pass while pyright fails exactly on the missing API; push and
   record the failing CI run as RED evidence; then implement; push GREEN.
4. Run gates locally before every push: `./scripts/check` (includes ruff format/check,
   shellcheck, strict pyright, full pytest, failure-propagation, bandit, detect-secrets,
   repo policy). All must pass. Fix lint/typing immediately — they are part of RED
   validity.
5. Write `rage/issue-NN-<slug>.org` (transaction, acceptance criteria, design decisions,
   RED/GREEN evidence with head SHAs + CI run IDs, verification mapping per criterion).
6. Write/update `docs/<topic>.md`.
7. `gh pr create` (CI triggers only on PRs, NOT plain branch pushes), wait for 4/4 green
   checks on the exact head, then `gh pr merge NN --squash --delete-branch=false`.
8. Confirm issue state CLOSED. Continue immediately to the next issue.

## Repository facts and gotchas (learned, cost real time — obey)

- Python 3.14 only. PEP 758 `except A, B:` (unparenthesized) is used in the codebase.
- Run tests via `uv run --no-sync pytest` or `.venv/bin/python -m pytest` (system python
  lacks deps). `timeout=120` pytest option exists.
- `scripts/check-policy` FORBIDS pytest skip markers, xfail, `|| true`, `continue-on-error`,
  etc. Never add `pytestmark`. Missing gpg/venv conditions must fail loudly, not skip.
- Bandit forbids `assert` in `src/` — use explicit `raise` fail-closed checks.
- ruff: line-length 100, isort order enforced by `ruff check --fix`; run
  `uv run --no-sync ruff format . && uv run --no-sync ruff check . --fix` before every
  commit. E501/SIM102/SIM103 will fire on long nested ifs — restructure cleanly.
- Baseline on current main: **930 tests pass** (unit 814, security 61, integration 49,
  contract 6). Anything less after your change = you broke something.
- Valid RED pattern used so far: new test file + module docstring-only scaffold →
  pyright fails "unknown import symbol", pytest fails at collection ImportError.
- GitHub CI (`on: pull_request`) has 4 jobs; merge requires all green on the exact head
  SHA. `gh pr view NN --json statusCheckRollup` to verify.
- Tests use uuid4-based records (storage rejects non-v4 UUIDs); see any
  `tests/unit/*/test_*.py` Harness/FakeStorage patterns for fakes (FakeStorage +
  FakeEncryption + MemoryKeyringBackend + Embeddings + EchoGenerator).
- `pytest.approx` triggers pyright unknown-type errors — use `== 0.2` for literals.
- Never commit HANDOFF.md; never commit unless it's your intended change.
- `gh pr merge --squash --delete-branch=false`; then `git checkout main && git pull`.

## Remaining issue requirements digest

### #35 Wayland capture through portals
PipeWire/portal screenshot or screen-stream flow; explicit user authorization through the
portal; capture backend stays behind the existing strategy interface (see
`src/local_recall/capture/` — XorgCaptureBackend, adaptive controller); compositor
metadata adapters only where stable; surface permission revocation (stop capture,
invalidate queued work), unsupported features, persistent-session behavior in status; no
automatic fallback to compositor internals/privileged helpers. Acceptance: works on one
wlroots + one DE subject to portal capability; revoked permission stops capture
immediately; Wayland limits visible in status/docs; Xorg tests unchanged. If CI cannot
run a real portal, use contract/fake portal implementations; close only if acceptance
criteria are met, else document blocker honestly (see RAGE format).

### #37 Health checks, diagnostics, safe repair
Read-only checks for: lifecycle state, capture backend, metadata sources, OCR,
encryption/key access, storage integrity, indexes, model providers, disk quota, daemon
IPC. Diagnostic bundle: versions, capability results, sanitized errors, opaque IDs only
(must pass secret scanning). Safe repair commands: index rebuild, orphan cleanup,
migration resume, provider re-probe — restartable, audited, never automatic, never
delete data or alter privacy policy. Capture faults/pauses when a critical privacy
dependency fails. Acceptance: `health` distinguishes degraded-optional from
capture-blocking; bundles pass content scanning; repairs restartable + audited; failing
encryption/redaction check prevents persistence. Suggested module `src/local_recall/health/`;
existing building blocks: `StorageIntegrityReport`/`recover()`, `KeyProvider.health()`,
`ProviderCapabilities.available`, `EncryptedSemanticIndex.manifest()`, audit recorder.
Reuse `tests/unit/retention/` fakes.

### #38 Security regression, fuzz, test-integrity
Meta-tests that inject failures into each required test path (assertion, crash, timeout,
zero-selection, piped) and prove non-zero exit — extend `scripts/verify-failure-modes`
coverage and `tests/failure_fixtures/`. Fuzz targets with deterministic seeds for config
parser, regex redaction detector, JSON/archive parsers, script-adapter output (use
hypothesis, seeded; document reproduction commands in docs/testing.md). Prove: seeded
secret cannot appear in persisted files/logs/bundles/exports/model requests; symlink/
permissions/race/traversal suites exist for new surfaces; IPC auth tests cover delete
capability; zero-test selection fails. Check what exists first: `tests/security/` has
15 files — extend, don't duplicate.

### #39 E2E acceptance/reliability/performance
Scenario runner scripts (no false-green constructs, pipefail, propagate child exit
codes) covering: start/record/pause/privacy/stop/restart/query; Qtile+Xorg synthetic;
lock/idle/model-outage/key-lock/low-disk/corrupt-index; "What was I doing Saturday?"
with citations on synthetic data; bounded soak with retention enabled; offline local-only.
Performance targets are in the issue body. E2E scenarios must fail before their feature
path is considered complete (TDD at E2E level). Self-tests: intentionally fail one
scenario at a time and prove the top-level command fails.

### #36 Timeline UI
Local-only, served via the existing authenticated IPC (extend
`src/local_recall/timeline/ipc.py` handler + `cli_contract.py` payloads); timeline/
search/answers/status/deletion workflows; previews decrypt-on-demand, never browser-
cached in plaintext; explicit egress confirmation UI for remote; emergency stop; no
third-party assets/CDNs/telemetry; static assets only. Acceptance includes browser-
cache inspection tests and closing-session credential clearing. This is the largest UI
task — keep it dependency-light (stdlib http.server over the unix socket is NOT allowed
to bypass auth; reuse `ZmqDaemonClient` patterns).

### #40 Nix packaging
`flake.nix` exists — extend: package, devShell, NixOS/Home-Manager module, hardened
systemd user unit (starts `off` by default; filesystem/network/capability restrictions),
qtile widget integration (see `indicator.py`), shell completions. `nix flake check` must
pass. VM test if feasible (`nixos-rebuild`/`nixos-vm` with synthetic Xorg capture);
document optional deps (OCR/tesseract, Ollama, ActivityWatch, GPG, portals). Uninstall
preserves/removes encrypted data only by explicit choice.

### #41 Release gate (final)
Requires #38, #39, #40 done. Documentation completeness per issue body; every completed
issue has automated acceptance tests + recorded RED evidence; published test report with
discovered/executed/passed/failed/skipped counts (skipped and expected-failure MUST be
0); signed/tagged `v0.1` with reproducible build instructions, exact test commands, test
counts, known limitations. Verify: `gh pr list`, `gh issue list --state open` (only
explicitly deferred issues may remain, each with rationale), full `./scripts/check`,
all security suites. Then produce the final report: release/tag, merged issues/PRs,
post-release leftovers, canonical commands, test counts, local/remote text model status,
local/remote vision status, known limitations, human blockers.

### #60 Zara visual context (any time after #33; deps satisfied)
Versioned typed request/response over the EXISTING owner-only ipc:// query boundary (no
TCP): `ExplainVisualContextRequest/Response` with current/recent/bounded_window
selectors, maximum_records, deadlines, remote_authorization absent|explicit. Refuse on
policy/lock/privacy-mode/missing-context. Minimum working set, memory-only pixels,
redaction before any provider, local default, remote only via EgressGate, sanitized
provenance, full audit trail, no capture-state changes. Extend `cli_contract.py`
commands + `timeline/ipc.py` handler or a sibling `vision/ipc.py`.

## Invariants that must never regress

- `capture -> deterministic redaction -> authorized provider`; raw frames never reach
  vision/remote surfaces (enforced at type boundary).
- Remote models stay fully supported (text/vision/embeddings) behind explicit
  authorization; local is default; NO silent local-to-remote fallback; no Ollama
  hardcoding; credentials never in persisted data/logs/bundles.
- Encrypted storage is the only record-existence authority; derived state reconciles
  from survivors; forward-only recovery.
- Sanitized audit events: counts/enums/digests only, never content.
- CLI imports only cli_contract/cli_service/ipcTransport — never daemon internals
  (enforced by tests/security/test_cli_architecture.py).
- Test policy: no skips, no xfail, no false-green constructs; zero-test selection fails.

## Final deliverable (when #41 closes)

Report: release/tag, merged issues/PRs list, remaining explicitly-post-release issues
with rationale, canonical verification commands, test counts/results per suite, local
text model status, remote text model status, local vision status, remote vision status,
known limitations, genuine human blockers. Otherwise, if context ends first, leave a
clean tree (all committed/pushed, no PR left unmerged), then output the same report with
"remaining queue" instead of release info.
