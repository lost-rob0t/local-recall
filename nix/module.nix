# NixOS module for Local Recall: daemon lifecycle, storage paths, desktop integration.
#
# Sandboxing posture: no home-directory write access, no network by default,
# no capabilities, no kernel/namespace/realtime privileges. Encrypted state
# lives in a dedicated directory owned by a dedicated system user with linger
# so the hardened user unit runs at boot. Uninstalling the module preserves
# the encrypted state directory; destroying it requires deliberately starting
# the local-recall-destroy-data oneshot unit.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.local-recall;
  stateDir = cfg.stateDirectory;
  toTOMLValue =
    v:
    if builtins.isBool v then
      (if v then "true" else "false")
    else if builtins.isInt v then
      toString v
    else if builtins.isFloat v then
      toString v
    else if builtins.isString v then
      builtins.toJSON v
    else if builtins.isList v then
      "[ ${lib.concatStringsSep ", " (map toTOMLValue v)} ]"
    else
      throw "local-recall settings support scalars, lists, and one level of tables";
  renderTable =
    name: attrs:
    [ "[${name}]" ] ++ lib.mapAttrsToList (key: value: "${key} = ${toTOMLValue value}") attrs;
  settings = {
    capture = {
      enabled = cfg.startMode == "recording";
    };
    storage = {
      backend_id = "sqlite";
      root_directory = stateDir;
    };
  } // cfg.extraSettings;
  scalars = lib.filterAttrs (_: value: !(builtins.isAttrs value)) settings;
  tables = lib.filterAttrs (_: value: builtins.isAttrs value) settings;
  configFile = pkgs.writeText "local-recall.toml" (
    lib.concatStringsSep "\n" (
      lib.mapAttrsToList (key: value: "${key} = ${toTOMLValue value}") scalars
      ++ lib.flatten (lib.mapAttrsToList renderTable tables)
    )
  );
  networkAllow = if cfg.networkAllowLoopback then [ "localhost" ] else [ ];
in
{
  options.services.local-recall = {
    enable = lib.mkEnableOption "Local Recall daemon lifecycle management";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The Local Recall package to run (use the flake overlay or set it explicitly).";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "local-recall";
      description = "User account owning the daemon session and encrypted state.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "local-recall";
      description = "Group for the daemon session.";
    };

    stateDirectory = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/local-recall";
      description = ''
        Directory holding the encrypted storage and daemon credentials.
        Uninstalling the module preserves this directory; removing it is an
        explicit, manual choice (or start the local-recall-destroy-data
        oneshot unit once, deliberately).
      '';
    };

    startMode = lib.mkOption {
      type = lib.types.enum [
        "off"
        "recording"
      ];
      default = "off";
      description = ''
        Capture state the daemon starts in. The hardened default is "off";
        recording must be explicitly configured or started through the
        authenticated control surface afterwards.
      '';
    };

    networkAllowLoopback = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Allow loopback network access (authenticated IPC on 127.0.0.1, local
        model providers such as Ollama). The hardened default denies all
        network addresses.
      '';
    };

    extraSettings = lib.mkOption {
      type = lib.types.attrs;
      default = { };
      description = "Extra settings merged into the generated TOML configuration.";
    };

    command = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        (lib.getExe cfg.package)
        "daemon"
      ];
      defaultText = lib.literalExpression "[ (lib.getExe cfg.package) \"daemon\" ]";
      description = ''
        Long-running command executed by the hardened systemd user unit. The
        daemon process mode is a pending release-gate item; until it exists
        the installed unit exits at start, which keeps the machine
        fail-closed (the CLI reports daemon-unavailable).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    users.groups.${cfg.group} = { };
    users.users.${cfg.user} = {
      isSystemUser = true;
      inherit (cfg) group;
      home = stateDir;
      createHome = true;
      linger = true;
    };

    systemd.services.local-recall-destroy-data = {
      description = "Local Recall explicit encrypted-data destruction (manual oneshot)";
      wantedBy = lib.mkForce [ ];
      serviceConfig = {
        Type = "oneshot";
        User = cfg.user;
        ExecStart = "${pkgs.runtimeShell} -c 'rm -rf ${stateDir}/*'";
      };
    };

    systemd.user.services.local-recall = {
      description = "Local Recall daemon";
      after = [ "default.target" ];
      wantedBy = [ "default.target" ];
      environment = {
        LOCAL_RECALL_CONFIG = configFile;
      };
      serviceConfig = {
        Type = "simple";
        ExecStart = lib.escapeShellArgs cfg.command;
        Restart = "on-failure";
        RestartSec = 5;

        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        ProtectProc = "invisible";
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        RemoveIPC = true;
        UMask = "0077";
        CapabilityBoundingSet = [ "" ];
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged @obsolete @resources @mount"
        ];

        ProtectHome = "read-only";
        ReadWritePaths = [ stateDir ];

        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
        IPAddressDeny = [ "any" ];
        IPAddressAllow = networkAllow;
      };
    };

    environment = {
      etc."local-recall/config.toml".source = configFile;
      systemPackages = [ cfg.package ];
    };
  };
}
