{ config, lib, pkgs, ... }:

let
  cfg = config.services.keysharp-input;
in {
  options.services.keysharp-input = {
    enable = lib.mkEnableOption "the keysharp-input privileged input broker";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = "keysharp-input package to run.";
    };
  };

  config = lib.mkIf cfg.enable {
    security.polkit.enable = true;
    boot.kernelModules = [ "uinput" ];
    services.udev.packages = [ cfg.package ];
    environment.systemPackages = [ cfg.package ];
    systemd.tmpfiles.rules = [
      "d /var/lib/keysharp-permissions 0700 root root - -"
      "d /var/lib/keysharp-permissions/v1 0700 root root - -"
      "d /run/keysharp-permissions 0755 root root - -"
    ];

    systemd.sockets.keysharp-inputd = {
      description = "Privileged Linux input broker socket";
      socketConfig = {
        ListenStream = "/run/keysharp-inputd/keysharp-inputd.sock";
        SocketMode = "0666";
        DirectoryMode = "0755";
        Accept = false;
      };
    };

    systemd.services.keysharp-inputd = {
      description = "Privileged Linux input broker";
      wantedBy = [ "multi-user.target" ];
      requires = [ "keysharp-inputd.socket" ];
      after = [ "keysharp-inputd.socket" "systemd-udevd.service" "keyd.service" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/keysharp-inputd --system-service";
        Restart = "on-failure";
        RestartSec = 1;
        OOMScoreAdjust = -900;
        LimitMEMLOCK = "infinity";
        NoNewPrivileges = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        ReadWritePaths = [
          "/var/lib/keysharp-permissions"
          "/run/keysharp-permissions"
        ];
        UMask = "0077";
        DevicePolicy = "closed";
        DeviceAllow = [ "char-input r" "/dev/uinput rw" ];
      };
    };
  };
}
