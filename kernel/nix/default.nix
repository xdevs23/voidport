{
  nixpkgsPath ? import ./nixpkgs.nix,
  system ? builtins.currentSystem,
  ccacheDir ? null,
  cacheKernel ? false,
}:
assert (!cacheKernel || ccacheDir != null)
  || throw "cacheKernel=true requires ccacheDir";
assert (ccacheDir == null || (builtins.isString ccacheDir
  && builtins.substring 0 1 ccacheDir == "/" && ccacheDir != "/"))
  || throw "ccacheDir must be null or a non-root absolute string";
let
  pkgs = import nixpkgsPath { inherit system; };
  cacheConfig = ''
    export CCACHE_DIR=${pkgs.lib.escapeShellArg ccacheDir}
    export CCACHE_COMPILERCHECK=content CCACHE_COMPRESS=1
    export CCACHE_MAXSIZE=20G CCACHE_UMASK=007
    export CCACHE_TEMPDIR="$TMPDIR/ccache"
    mkdir -p "$CCACHE_TEMPDIR"
  '';
  cachedStdenv = stdenv: pkgs.ccacheStdenv.override {
    inherit stdenv;
    extraConfig = cacheConfig;
  };
  hostCompiler = pkgs.buildPackages.ccacheWrapper.override {
    cc = pkgs.buildPackages.stdenv.cc;
    extraConfig = cacheConfig;
  };
  # Changing a kernel compiler changes its development output, so module-only
  # caching must keep the built kernel.
  selectedKernel = kernel: stdenv:
    if cacheKernel then kernel.override (old: {
      stdenv = cachedStdenv stdenv;
      extraMakeFlags = (old.extraMakeFlags or [ ]) ++ [
        "HOSTCC=${hostCompiler}/bin/cc"
        "HOSTCXX=${hostCompiler}/bin/c++"
      ];
    }) else kernel;

  kernels = {
    longterm = pkgs.linuxPackages_6_18.kernel;
    stable = pkgs.linuxPackages_latest.kernel;
    mainline = pkgs.linuxPackages_testing.kernel;
  };
  styleOf = kernel: pkgs.runCommand "voidport-kernel-style" { } ''
    mkdir -p "$out/scripts"
    if [ -d ${kernel.src} ]; then
      cp ${kernel.src}/.rustfmt.toml "$out/"
      cp ${kernel.src}/scripts/{checkpatch.pl,spelling.txt,const_structs.checkpatch} "$out/scripts/"
    else
      tar -xf ${kernel.src} --strip-components=1 -C "$out" \
        linux-${kernel.version}/.rustfmt.toml \
        linux-${kernel.version}/scripts/checkpatch.pl \
        linux-${kernel.version}/scripts/spelling.txt \
        linux-${kernel.version}/scripts/const_structs.checkpatch
    fi
    chmod +x "$out/scripts/checkpatch.pl"
  '';
  member = category: configuration: baseKernel:
    let
      stdenv = if configuration == "debug" then pkgs.llvmPackages.stdenv else pkgs.stdenv;
      kernel = selectedKernel baseKernel stdenv;
      module = pkgs.callPackage ./module.nix ({
        inherit kernel stdenv;
      } // pkgs.lib.optionalAttrs (ccacheDir != null) {
        kbuildStdenv = cachedStdenv stdenv;
      });
    in {
      inherit category configuration kernel module;
      style = styleOf kernel;
      inherit (module) wireCrate sessionCrate linted crateInputs;
      closureGuest = import ./closure-guest.nix {
        inherit pkgs nixpkgsPath system kernel module category configuration;
      };
      mountGuest = pkgs.callPackage ./mount-guest.nix {
        inherit category configuration kernel module;
      };
      speedGuest = pkgs.callPackage ./speed-guest.nix {
        inherit category configuration kernel module;
      };
    };
  production = pkgs.lib.mapAttrs (category: member category "production") kernels;
  # A debug kernel compiles every source file with the sanitizers, so
  # localmodconfig reduces it to the modules a guest loads, listed per member
  # under debug-modules because module names differ between kernel versions.
  # A name without a kernel option fails the build, so a renamed module cannot
  # drop out unnoticed.
  debugKernel = category: kernel:
    let
      # Rust plus KASAN requires Clang in the selected kernels' Kconfig.
      stdenv = pkgs.llvmPackages.stdenv;
      full = kernel.override {
        inherit stdenv;
        structuredExtraConfig = with pkgs.lib.kernel; {
          KASAN = yes;
          KASAN_GENERIC = yes;
          UBSAN = yes;
          PROVE_LOCKING = yes;
          DEBUG_ATOMIC_SLEEP = yes;
          DEBUG_KMEMLEAK = yes;
          # Fails allocations from outside the module. The stack filter limits
          # the failures to allocations made from module code.
          FAULT_INJECTION = yes;
          FAULT_INJECTION_DEBUG_FS = yes;
          FAULT_INJECTION_STACKTRACE_FILTER = yes;
          FAILSLAB = yes;
          FAIL_PAGE_ALLOC = yes;
        };
      };
      configfile = full.configfile.overrideAttrs (old: {
        pname = "linux-config-trimmed";
        buildPhase = old.buildPhase + ''
          set +o pipefail
          yes "" | make $makeFlags -C . O="$buildRoot" ARCH=$kernelArch \
            CROSS_COMPILE=${stdenv.cc.targetPrefix} \
            LSMOD=${./debug-modules + "/${category}.lsmod"} localmodconfig 2> localmodconfig.err
          set -o pipefail
          cat localmodconfig.err >&2
          if grep -F 'config not found' localmodconfig.err; then
            echo "debug-modules/${category}.lsmod names a module this kernel has no option for" >&2
            exit 1
          fi
        '';
      });
    in (pkgs.linuxManualConfig {
      inherit (full) src version modDirVersion;
      kernelPatches = full.kernelPatches or [ ];
      inherit configfile stdenv;
      inherit (full) features;
      config = { CONFIG_MODULES = "y"; CONFIG_FW_LOADER = "y"; CONFIG_RUST = "y"; };
    });
  debug = pkgs.lib.mapAttrs (category: kernel:
    member category "debug" (debugKernel category kernel)) kernels;
  kernel = production.stable.kernel;
  module = production.stable.module;
in
{
  inherit pkgs kernel module debug;
  inherit (production) longterm stable mainline;

  closureChecks = pkgs.runCommand "voidport-closure-harness-checks" {
    nativeBuildInputs = [ (pkgs.python3.withPackages (p: [ p.tomli-w ])) ];
  } ''
    export PYTHONDONTWRITEBYTECODE=1
    python3 ${../tests}/closure-test.py
    VOIDPORT_GUEST_PYTHON=${pkgs.python3Minimal}/bin/python3 \
      python3 ${../tests}/guest-events-test.py
    python3 ${../tests}/speed-records-test.py
    python3 ${../tests}/mount-verdicts-test.py
    python3 ${../tests}/console-diagnostics.py --self-test
    python3 - <<'PY'
    from pathlib import Path
    source = Path('${../tests}')
    for name in ('closure-guest.py', 'closure-bootstrap.py', 'closure-firewall.py',
                 'closure-manifest.py', 'closure-host.py', 'guest-events.py', 'mount-verdicts.py',
                 'run-guest.py', 'speed-guest.py', 'speed-records.py'):
        compile((source / name).read_bytes(), name, 'exec')
    PY
    mkdir -p "$out"
    touch "$out/passed"
  '';

  wireCrate = module.wireCrate;
  sessionCrate = module.sessionCrate;

  linted = module.linted;

  crateInputs = module.crateInputs;

  mountGuest = production.stable.mountGuest;

  # Neither file survives into the packaged development output of the kernel.
  style = styleOf kernel;

  tools = pkgs.buildEnv {
    name = "voidport-kernel-ladder-tools";
    paths = [
      pkgs.rustfmt
      pkgs.perl
      pkgs.kmod
      pkgs.findutils
      pkgs.jq
    ];
  };

  harnessTools = pkgs.buildEnv {
    name = "voidport-kernel-harness-tools";
    paths = [
      pkgs.qemu_kvm
      pkgs.jq
      (pkgs.python3.withPackages (p: [ p.tomli-w ]))
    ];
  };
}
