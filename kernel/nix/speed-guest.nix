{
  lib,
  runCommand,
  writeText,
  pkgsStatic,
  python3Minimal,
  closureInfo,
  callPackage,
  cpio,
  kmod,
  xz,
  stdenv,
  kernel,
  module,
  category ? "stable",
  configuration ? "production",
}:
let
  programs = callPackage ../../nix/workspace-programs.nix { } {
    pname = "voidport-speed-programs";
    inherit ((lib.importTOML ../../Cargo.toml).workspace.package) version;
    src = lib.fileset.toSource {
      root = ../..;
      fileset = lib.fileset.unions [
        ../../Cargo.toml
        ../../Cargo.lock
        ../../crates
      ];
    };
    packages = [
      "voidportd"
      "voidport-ctl"
      "voidport"
      "voidport-bench"
      "voidport-wire-census"
    ];
  };
  guestPrograms = runCommand "voidport-speed-guest-programs" { } ''
    install -Dm555 -t "$out/bin" ${programs}/bin/voidport ${programs}/bin/voidport-bench \
      ${programs}/bin/voidport-wire-census
  '';
  scripts = lib.fileset.toSource {
    root = ../tests;
    fileset = lib.fileset.unions [
      ../tests/speed-guest.py
      ../tests/speed-records.py
      ../tests/guest-events.py
    ];
  };
  copyModules = import ./guest-modules.nix { inherit lib kernel; };
  output = import ./guest-output.nix;
  packImage = import ./guest-image.nix {
    inherit kernel category configuration;
    inherit (stdenv.hostPlatform) system;
  };

  init = writeText "voidport-speed-guest-init" ''
    #!/bin/sh
    export PATH=/bin
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev
    ${output.toKernelLog}
    # A module that does not load ends the run. The module of the filesystem is
    # loaded by the program below, after the userspace client ran.
    for object in /modules/*.ko; do
      insmod "$object" || {
        printf 'voidport harness: %s did not load\n' "$object"
        poweroff -f
      }
    done
    ${output.toConsole}
    ip link set lo up
    ${builtins.readFile ./guest-network.sh}
    ${python3Minimal}/bin/python3 ${scripts}/speed-guest.py \
      --voidport ${guestPrograms}/bin/voidport \
      --module /voidport.ko \
      --bench ${guestPrograms}/bin/voidport-bench \
      --census ${guestPrograms}/bin/voidport-wire-census
    poweroff -f
  '';
  closure = closureInfo { rootPaths = [ init ]; };
in
runCommand "voidport-speed-guest-${kernel.modDirVersion}"
  {
    nativeBuildInputs = [
      cpio
      kmod
      xz
    ];
    passthru = { inherit kernel module programs init; };
  }
  ''
    mkdir -p root/bin root/proc root/sys root/dev root/modules root/nix/store "$out"
    cp ${pkgsStatic.busybox}/bin/busybox root/bin/busybox
    for applet in sh mount umount insmod poweroff printf ip; do
      ln -s busybox "root/bin/$applet"
    done
    while read -r dependency; do
      cp -a "$dependency" root/nix/store/
    done < ${closure}/store-paths
    install -m 555 ${init} root/init
    install -m 444 ${module}/voidport/voidport.ko root/voidport.ko
    ${copyModules {
      load = [
        "virtio_pci"
        "virtio_net"
        "virtio_console"
        "fuse"
      ];
    }}
    ${packImage}
    ln -s ${programs} "$out/programs"
  ''
