# The probe module, built out of tree against the kernel's own build tree.
#
# The crate chain is stated whole, and none of it is vendored into this
# repository: the wire crate is the workspace's own directory, consumed by
# path, and its dependency and that dependency's host-side chain are
# materialized from the workspace's lockfile. The module therefore cannot be
# built against a wire crate the workspace does not have, which is the
# mechanical form of one wire truth.
{
  lib,
  stdenv,
  rustPlatform,
  rustc,
  cargo,
  clippy,
  writeText,
  kernel,
}:
let
  lockFile = ../../Cargo.lock;
  protoSrc = ../../crates/voidport-proto;

  vendor = rustPlatform.importCargoLock { inherit lockFile; };

  lock = builtins.fromTOML (builtins.readFile lockFile);
  versionOf =
    name:
    (lib.findFirst (
      package: package.name == name
    ) (throw "${name} is not in the workspace lockfile") lock.package).version;

  zerocopySrc = "${vendor}/zerocopy-${versionOf "zerocopy"}";
  zerocopyDeriveSrc = "${vendor}/zerocopy-derive-${versionOf "zerocopy-derive"}";

  # `zerocopy-derive` is a proc macro: a shared object for the *build* machine,
  # compiled with the ordinary sysroot, exactly as kbuild compiles its own
  # `rust/libmacros.so`. rustc requires only that the compiler which built a
  # proc macro is the compiler that consumes it, so cargo is the cheapest way to
  # get it and its dependency chain built. Nothing cargo produces here reaches
  # the kernel module: every target-side crate is built by kbuild's rules.
  #
  # The derive is built as a *dependency* of a package that asks for it, never
  # as the root package: cargo resolves a root package's development
  # dependencies too, and the derive's are outside the workspace's dependency
  # graph and so outside the vendored directory. Asking for it the way the
  # workspace asks for it is what keeps the resolution the workspace's.
  procMacro = stdenv.mkDerivation {
    name = "voidport-zerocopy-derive";
    nativeBuildInputs = [
      rustc
      cargo
    ];
    dontUnpack = true;
    buildPhase = ''
      mkdir -p holder/src .cargo
      : > holder/src/lib.rs
      cat > holder/Cargo.toml <<EOF
      [package]
      name = "voidport-kernel-procmacro-holder"
      version = "0.0.0"
      edition = "2021"

      [dependencies]
      zerocopy-derive = "=${versionOf "zerocopy-derive"}"
      EOF
      cat > .cargo/config.toml <<EOF
      [source.crates-io]
      replace-with = "vendored"
      [source.vendored]
      directory = "${vendor}"
      EOF
      CARGO_HOME=$PWD/.cargo-home CARGO_TARGET_DIR=$PWD/target \
        cargo build --release --offline --manifest-path holder/Cargo.toml \
          --package zerocopy-derive
    '';
    installPhase = ''
      mkdir -p "$out/deps"
      cp target/release/libzerocopy_derive.so "$out/"
      cp target/release/deps/*.so "$out/deps/"
    '';
  };
  # The two build rungs of the ladder differ only in what they ask kbuild for,
  # so they are one recipe with two goals: the crate rung cannot pass under
  # different flags from the ones the module rung uses.
  kbuild =
    {
      goal,
      product,
      suffix,
      lint ? false,
    }:
    stdenv.mkDerivation {
      name = "voidport-probe-${suffix}-${kernel.modDirVersion}";
      src = ../probe;

      nativeBuildInputs = [ rustc ] ++ lib.optional lint clippy ++ kernel.moduleBuildDependencies;

      KDIR = "${kernel.dev}/lib/modules/${kernel.modDirVersion}/build";
      # A warning that survives a build is a warning nobody reads, and the bar
      # this module is held to is the kernel tree's own. Per-crate allowances
      # live in Kbuild, beside the rule they belong to.
      KRUSTFLAGS = "-Dwarnings";
      VOIDPORT_PROTO_SRC = protoSrc;
      VOIDPORT_ZEROCOPY_SRC = zerocopySrc;
      VOIDPORT_PROCMACRO_DIR = procMacro;

      # The kernel object carries no interpreter and no runtime path, and the
      # fixup pass has nothing to say about it but noise.
      dontFixup = true;

      # kbuild reads `CLIPPY` only from a command line, so the flag is spelled
      # there and make carries it into the kernel tree's own invocation.
      buildPhase = ''
        runHook preBuild
        make ${lib.optionalString lint "CLIPPY=1 "}${goal}
        runHook postBuild
      '';

      installPhase = ''
        runHook preInstall
        install -Dm444 ${product} "$out/${product}"
        runHook postInstall
      '';
    };

  # The wire crate alone, riding kbuild's own flags. It is a rung of its own
  # because a crate that stops riding kbuild is a different failure from a
  # module that stops building, and the cheaper answer comes first.
  wireCrate = kbuild {
    goal = "crates";
    product = "voidport_proto.o";
    suffix = "wire-crate";
  };

  # The same module under the kernel tree's clippy configuration, which the
  # tree carries beside its rustfmt one and holds its own Rust to. It is a
  # build of its own because clippy-driver replaces the compiler, and a rung
  # that changes the compiler may not be the rung that produces what is loaded.
  linted = kbuild {
    goal = "all";
    product = "voidport_probe.ko";
    suffix = "clippy";
    lint = true;
  };

  # What the module was built from, named so a rung can hold it against the
  # workspace's own files. Both entries are store paths, so comparing them is
  # comparing content: a vendored copy, a stale lockfile or a second wire crate
  # cannot answer with the workspace's hash.
  crateInputs = writeText "voidport-probe-crate-inputs" ''
    voidport-proto ${protoSrc}
    lockfile ${lockFile}
    zerocopy ${versionOf "zerocopy"}
    zerocopy-derive ${versionOf "zerocopy-derive"}
  '';
in
(kbuild {
  goal = "all";
  product = "voidport_probe.ko";
  suffix = "module";
}).overrideAttrs
  (previous: {
    passthru = (previous.passthru or { }) // {
      inherit wireCrate linted crateInputs;
    };
  })
