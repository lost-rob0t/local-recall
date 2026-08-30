# Installation and first run

**Status:** v0.1.

## From source (development)

Requirements: Python 3.14, `uv`, `git`, plus the optional system libraries used by tests and native backends (`libsodium`, `zeromq`, `tesseract4`, `xprintidle`).

```bash
git clone https://github.com/lost-rob0t/local-recall
cd local-recall
./scripts/bootstrap     # creates .venv from the lockfile
./scripts/check         # canonical gate: format, lint, types, tests, security scans
```

Run the CLI locally with `.venv/bin/local-recall --help`. The package entry point is `local_recall.cli:app` (`local-recall` after `uv sync`).

## Nix / NixOS

The flake provides the package, a development shell, an overlay, and a NixOS module with a hardened systemd user unit (see [Nix packaging](nix.md)):

```bash
nix build .#local-recall
nix run .# -- version
```

```nix
services.local-recall = {
  enable = true;
  package = local-recall.packages.${system}.local-recall;
  startMode = "off";            # hardened default
  networkAllowLoopback = true;  # required for the loopback IPC endpoint
};
```

The service starts in `off` state unless `startMode = "recording"` is explicitly configured. Uninstalling preserves the encrypted state directory; destruction is a deliberate manual oneshot (`local-recall-destroy-data`).

## First run

1. Write a configuration file (start from `docs/configuration.md`; validate with `local-recall config validate <path>`).
2. Configure the encryption key provider (OS keyring by default; GPG fallback available) — the daemon cannot persist records without key access.
3. Start the daemon session; the authenticated IPC credentials are created under the user runtime directory and the CLI picks them up automatically.
4. `local-recall status` shows the capture state, backend, and privacy mode. `local-recall start` / `pause` / `stop` control recording; `privacy-on` halts all capture immediately.

## Verification

```bash
./scripts/test            # full pytest suite
./scripts/check           # canonical gate (required for every change)
./scripts/e2e             # end-to-end scenarios (synthetic desktops only)
```

Test failure semantics, failure-injection self-tests, and the zero-test policy are documented in [testing](testing.md).
