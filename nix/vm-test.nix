# NixOS VM test: clean install, hardened unit properties, fail-closed CLI.
{
  nixpkgs,
  self,
  system,
}:
let
  pkgs = import nixpkgs {
    inherit system;
    overlays = [ self.overlays.default ];
  };
  testing = import (nixpkgs + "/nixos/lib/testing-python.nix") {
    inherit pkgs system;
  };
in
{
  vmTest = testing.makeTest {
    name = "local-recall-vm";

    nodes.machine =
      { lib, ... }:
      {
        imports = [ self.nixosModules.local-recall ];
        virtualisation.memorySize = 1024;
        services.local-recall = {
          enable = true;
          package = self.packages.${system}.local-recall;
          startMode = "off";
          networkAllowLoopback = true;
        };
        users.users.alice = {
          isNormalUser = true;
        };
        environment.systemPackages = with pkgs; [
          jq
        ];
      };

    testScript = ''
      machine.wait_for_unit("default.target")

      machine.succeed("local-recall version | grep -q 0.1.0.dev0")

      machine.fail("local-recall status")
      machine.succeed("local-recall status > /tmp/status.out 2>&1 || test $? -eq 3")
      machine.succeed("grep -q daemon-unavailable /tmp/status.out")

      machine.succeed("cat /etc/systemd/user/local-recall.service > /tmp/unit.out")
      machine.succeed("cat /tmp/unit.out >&2")
      machine.succeed("grep -qi 'NoNewPrivileges' /tmp/unit.out")
      machine.succeed("grep -qi 'ProtectHome' /tmp/unit.out")
      machine.succeed("grep -qi 'IPAddressDeny' /tmp/unit.out")
      machine.succeed("grep -qi 'IPAddressAllow' /tmp/unit.out")
      machine.succeed("grep -qi 'CapabilityBoundingSet' /tmp/unit.out")
      machine.succeed("grep -qi 'UMask' /tmp/unit.out")
      machine.succeed("grep -qi 'Restart' /tmp/unit.out")

      machine.succeed("test -d /var/lib/local-recall")
      machine.succeed("stat -c '%U' /var/lib/local-recall | grep -q local-recall")

      machine.fail("systemctl cat local-recall-destroy-data.service | grep -q 'WantedBy='")

      machine.succeed("grep -q 'enabled = false' /etc/local-recall/config.toml")
    '';
  };
}
