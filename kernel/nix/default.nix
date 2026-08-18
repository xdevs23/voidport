# The nix side of the voidport kernel client, phase one.
#
# Everything the ladder needs is an attribute here. The build rungs are
# derivations; the guest rung is not, because it needs the host's KVM and vsock
# devices, which a build sandbox exposes neither of. That split is the spec's,
# and it is why the harness is a script the devshell runs.
#
# This expression pins no nixpkgs of its own. A caller that has one already
# passes it as `nixpkgsPath` — the repository flake does, from its own input —
# and the default resolves the same revision from the flake's lockfile, so a
# direct `nix-build` of this directory and the flake output build the module
# against the nixpkgs the workspace is built against either way.
{
  nixpkgsPath ? import ./nixpkgs.nix,
  system ? builtins.currentSystem,
}:
let
  pkgs = import nixpkgsPath { inherit system; };

  # The stable member of the supported kernel set.
  kernel = pkgs.linuxPackages_latest.kernel;

  module = pkgs.callPackage ./module.nix { inherit kernel; };
in
{
  inherit pkgs kernel module;

  # The ladder's first rung: the workspace's wire crate compiled under kbuild's
  # own flags, before anything larger is asked for.
  wireCrate = module.wireCrate;

  # The module under the kernel tree's clippy configuration.
  linted = module.linted;

  # What the module was built from, for the rung that holds those inputs
  # against the workspace's own files.
  crateInputs = module.crateInputs;

  guest = pkgs.callPackage ./guest.nix { inherit kernel module; };

  # The kernel tree's own style configuration, which the ladder checks against.
  # Both files live in the kernel source and neither survives into the packaged
  # development output, so they are lifted out of the source here.
  style = pkgs.runCommand "voidport-kernel-style" { } ''
    mkdir -p "$out/scripts"
    tar -xf ${kernel.src} --strip-components=1 -C "$out" \
      linux-${kernel.version}/.rustfmt.toml \
      linux-${kernel.version}/scripts/checkpatch.pl \
      linux-${kernel.version}/scripts/spelling.txt \
      linux-${kernel.version}/scripts/const_structs.checkpatch
    chmod +x "$out/scripts/checkpatch.pl"
  '';

  # What the ladder reaches for by store path, because an ordinary PATH either
  # does not carry it or does not carry the version the check is against: the
  # style checkers, the file lister they are pointed at, and the reader that
  # answers what a built module says it was built for.
  tools = pkgs.buildEnv {
    name = "voidport-kernel-ladder-tools";
    paths = [
      pkgs.rustfmt
      pkgs.perl
      pkgs.kmod
      pkgs.findutils
    ];
  };

  # The same for the harness: the guest needs a machine to run on, and the
  # server's answer is JSON, which is read by a reader and never by hand.
  harnessTools = pkgs.buildEnv {
    name = "voidport-kernel-harness-tools";
    paths = [
      pkgs.qemu_kvm
      pkgs.jq
    ];
  };
}
