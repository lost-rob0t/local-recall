# Nix packaging

**Status:** v0.1 for issue #40.
**Authority:** the flake builds the CLI/daemon package, the hardened systemd user unit, and a clean NixOS VM test; the daemon process mode itself is the pending release-gate item (see Known limitations).

## Flake outputs

```bash
nix build .#local-recall        # the CLI/daemon package (bash/zsh/fish completions included)
nix run .# -- version
nix develop                      # dev shell with python3.14, uv, tesseract, zeromq, libsodium, shellcheck
nix flake check                  # package + hardened-unit VM test (x86_64-linux runs the VM)
nix build .#checks.x86_64-linux.vm-test.driver
result/bin/nixos-test-driver     # run the VM test interactively
```

The overlay (`overlays.default`) exposes `local-recall` for other configurations:

```nix
{ nixpkgs.overlays = [ local-recall.overlays.default ]; }
```

## NixOS module

```nix
services.local-recall = {
  enable = true;
  package = local-recall.packages.${system}.local-recall;
  startMode = "off";                 # hardened default; "recording" is opt-in
  stateDirectory = "/var/lib/local-recall";
  user = "local-recall";
  networkAllowLoopback = false;      # deny-all network; loopback is opt-in
  extraSettings = { };               # merged into the generated TOML config
};
```

The module creates a dedicated `local-recall` system user (with linger) owning the encrypted state directory, installs the configuration at `/etc/local-recall/config.toml`, and installs a hardened **systemd user unit** (`systemd.user.services.local-recall`).

### Hardening

The unit runs with: `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `ProtectClock/Hostname/KernelLogs/KernelModules/KernelTunables/ControlGroups`, `ProtectProc=invisible`, `RestrictSUIDSGID/Realtime/Namespaces`, `LockPersonality`, `RemoveIPC`, `UMask=0077`, empty `CapabilityBoundingSet`, `SystemCallArchitectures=native` with `@system-service` minus privileged/obsolete/resources/mount syscall groups.

- **Home directories**: `ProtectHome=read-only` — the unit cannot write to `/home`, `/root`, or `/run/user`; all user state lives in the dedicated state directory (`ReadWritePaths`).
- **Network**: `IPAddressDeny=any` by default; `networkAllowLoopback = true` adds `IPAddressAllow=localhost` for the authenticated loopback IPC endpoint and local model providers. No external network access is granted.
- **Start state**: `startMode = "off"` (default) writes `capture.enabled = false` into the generated configuration, so the service starts in `off` unless explicitly configured otherwise.

## Optional dependencies

The package itself is dependency-light. Optional system components are documented here and included in the dev shell where relevant:

| capability | dependency | notes |
| --- | --- | --- |
| OCR (screenshot text) | `tesseract4` | enable via OCR settings; packaged in nixpkgs |
| Local generation/embeddings | Ollama (localhost) | remote-model authorization still applies; enable `networkAllowLoopback` |
| Activity metadata | ActivityWatch (localhost) | metadata probe; localhost only |
| GPG key fallback | `gnupg` | key-provider fallback for record encryption |
| Wayland capture | `xdg-desktop-portal-wlr` (wlroots) / `-gnome` / `-kde`, plus PipeWire for screen streams | the portal grants per-capture authorization |
| Xorg capture | `xorg.xwd`, `xorg.xrandr` (`xwd`/`xrandr`) | used by the Xorg capture backend |

## Qtile widget / tray integration

`local_recall.indicator` exposes `IndicatorController`, a daemon-authoritative, content-free recording-indicator model that renders state/privacy/backend strings from the authenticated status command. In a Qtile config (with the package importable in Qtile's Python):

```python
from local_recall.indicator import IndicatorController

indicator = IndicatorController(client_factory=my_authenticated_client_factory)
# render widget text from indicator.render() / refresh on interval
```

The controller never reads screen content and fails closed to `unavailable` when the daemon is unreachable.

## Uninstall semantics

- Removing `services.local-recall` (uninstalling the module) **preserves** the encrypted state directory and every record in it.
- Destroying data is an explicit, deliberate action: start the `local-recall-destroy-data` oneshot unit once. It is `wantedBy = []` — nothing enables or schedules it, and the daemon never deletes records during normal operation.

## Known limitations

- The daemon **process mode** (`local-recall daemon`) is a pending release-gate item: the hardened unit is installed and correctly configured, but until the long-running daemon command exists the unit exits at start and the CLI reports the sanitized `daemon-unavailable` failure (exit code 3) — fail-closed by design. The VM test asserts exactly this behavior.
- The VM test therefore verifies clean install, CLI behavior, unit hardening, state-directory ownership, config generation, and non-enabled destroy unit — not the full capture/query lifecycle, which requires the daemon process.
