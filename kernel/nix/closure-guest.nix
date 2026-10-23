# SPDX-License-Identifier: GPL-2.0-only
{ pkgs, nixpkgsPath, system, kernel, module, category, configuration }:
let
  inherit (pkgs) lib;
  witness = pkgs.writeText "voidport-closure-readonly" "closure bytes remain unchanged\n";
  reference = "firewall-reference";
  storeOptions = [ "ro" "nosuid" "nodev" ];
  output = import ./guest-output.nix;
  fixture = import (nixpkgsPath + "/nixos/lib/eval-config.nix") {
    inherit system;
    modules = [ ({ config, ... }: {
      imports = [ (nixpkgsPath + "/nixos/modules/profiles/minimal.nix") ];
      system.stateVersion = "26.05";
      networking.hostName = "closure-boot";
      networking.useDHCP = false;
      boot.kernelPackages = pkgs.linuxPackagesFor kernel;
      system.extraDependencies = [ module ];
      boot.loader.grub.enable = false;
      boot.initrd.enable = false;
      boot.kernelParams = [ "console=ttyS0" ];
      # NixOS otherwise lowers the console level to 4 through the kernel.printk
      # sysctl, which keeps kernel log records off the console.
      boot.consoleLogLevel = 7;
      fileSystems."/" = { device = "tmpfs"; fsType = "tmpfs"; };
      fileSystems."/nix/store" = {
        device = "closure";
        fsType = "voidport";
        options = storeOptions;
      };
      # Stage 2 stacks a bind mount on the store unless it has these options. The
      # default adds x-initrd.mount, which findmnt never shows for a mount made
      # before stage 2.
      boot.nixStoreMountOpts = storeOptions;
      nix.enable = false;
      documentation.enable = false;
      systemd.services.closure-proof = {
        wantedBy = [ "multi-user.target" ];
        # The target does not wait for the firewall to succeed, so the observer
        # checks the outcome itself.
        after = [ "multi-user.target" "firewall.service" ];
        # The target must not be ordered after this observer.
        unitConfig.DefaultDependencies = false;
        serviceConfig = {
          Type = "oneshot";
          TimeoutStartSec = "infinity";
          StandardOutput = "file:${output.device}";
          StandardError = "file:${output.device}";
        };
        path = [ pkgs.util-linux pkgs.systemd pkgs.coreutils pkgs.iproute2
          config.networking.firewall.package ];
        script = ''
          ${pkgs.python3}/bin/python3 ${../tests/closure-guest.py} \
            ${../tests/guest-events.py} ${../tests/closure-firewall.py} \
            ${reference} ${witness}
          systemctl --no-block poweroff
        '';
      };
      # The firewall start command, run in the empty network namespace that the
      # observer creates before it starts this service.
      systemd.services.${reference} = {
        inherit (config.systemd.services.firewall) path;
        serviceConfig = {
          inherit (config.systemd.services.firewall.serviceConfig)
            Type RemainAfterExit ExecStart;
          NetworkNamespacePath = "/run/netns/${reference}";
        };
      };
      systemd.defaultUnit = "multi-user.target";
      systemd.settings.Manager = {
        DefaultTimeoutStartSec = "infinity";
        DefaultTimeoutStopSec = "infinity";
      };
    }) ];
  };
  toplevel = fixture.config.system.build.toplevel;
  closure = pkgs.closureInfo { rootPaths = [ toplevel ]; };
  excluded = pkgs.writeText "voidport-excluded-store-path" "not exported\n";
  manifest = pkgs.runCommand "voidport-system-closure-manifest" {
    nativeBuildInputs = [ pkgs.python3 ];
  } ''
    python3 ${../tests/closure-manifest.py} ${closure}/store-paths \
      ${toplevel} ${witness} ${excluded} "$out"
  '';
  init = pkgs.writeText "voidport-closure-init" ''
    #!/bin/sh
    set -eu
    export PATH=/bin
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev
    ${output.toKernelLog}
    # The links NixOS stage 1 makes. Stage 2 writes its log through a process
    # substitution, which bash opens as a path under /dev/fd.
    ln -sfn /proc/self/fd /dev/fd
    ln -sfn /proc/self/fd/0 /dev/stdin
    ln -sfn /proc/self/fd/1 /dev/stdout
    ln -sfn /proc/self/fd/2 /dev/stderr
    test "$(uname -r)" = '${kernel.modDirVersion}'
    # Loaded before the store connection opens.
    . /load-modules
    ${output.toConsole}
    insmod /voidport.ko
    ${builtins.readFile ./guest-network.sh}
    mount -t tmpfs tmpfs /sysroot
    mkdir -p /sysroot/nix/store /sysroot/run /sysroot/proc /sysroot/sys /sysroot/dev
    mount -t tmpfs tmpfs /sysroot/run
    test -z "$(ls -A /nix/store)"
    test -z "$(ls -A /sysroot/nix/store)"
    printf 'empty\n' > /sysroot/run/closure-store-before
    cp /manifest.json /sysroot/run/closure-manifest.json
    mount -t voidport closure /sysroot/nix/store \
      -o "${lib.concatStringsSep "," storeOptions},$VOIDPORT_ENDPOINT"
    mount --move /proc /sysroot/proc
    mount --move /sys /sysroot/sys
    mount --move /dev /sysroot/dev
    exec switch_root /sysroot ${toplevel}/init
  '';
in
assert fixture.config.boot.kernelPackages.kernel.drvPath == kernel.drvPath;
pkgs.runCommand "voidport-closure-guest-${category}-${configuration}" {
  nativeBuildInputs = [ pkgs.python3 pkgs.kmod pkgs.cpio ];
  passthru = { inherit kernel module toplevel closure manifest fixture; };
} ''
  mkdir -p root/{bin,proc,sys,dev,sysroot,nix/store} "$out"
  cp ${pkgs.pkgsStatic.busybox}/bin/busybox root/bin/
  for applet in sh mount insmod ip uname mkdir ln ls printf cp switch_root; do
    ln -s busybox "root/bin/$applet"
  done
  python3 ${../tests/closure-bootstrap.py} ${kernel.modules} \
    ${kernel.modDirVersion} root
  ${pkgs.pkgsStatic.busybox}/bin/busybox sh -n ${init}
  install -m 555 ${init} root/init
  install -m 444 ${module}/voidport/voidport.ko root/voidport.ko
  cp ${manifest} root/manifest.json
  ${import ./guest-image.nix { inherit kernel category configuration system; }}
  cp ${manifest} "$out/manifest.json"
  cp ${closure}/store-paths "$out/store-paths"
  cp root/load-modules "$out/load-modules"
  ln -s ${toplevel} "$out/toplevel"
  ln -s ${module} "$out/module"
  ln -s ${closure} "$out/closure"
  ln -s ${excluded} "$out/excluded"
''
