{
  lib,
  stdenv,
  rustPlatform,
  rustc,
  cargo,
  clippy,
  python3,
  writeText,
  kernel,
  kbuildStdenv ? stdenv,
}:
let
  legacyKernel = lib.versionOlder kernel.version "7.0";
  exclusiveCreate = lib.versionAtLeast kernel.version "7.3";
  lockFile = ../../Cargo.lock;
  protoSrc = ../../crates/voidport-proto;
  sessionSrc = ../../crates/voidport-session;

  vendor = rustPlatform.importCargoLock { inherit lockFile; };

  lock = builtins.fromTOML (builtins.readFile lockFile);
  versionOf =
    name:
    (lib.findFirst (
      package: package.name == name
    ) (throw "${name} is not in the workspace lockfile") lock.package).version;

  optionsLockFile = ../options/Cargo.lock;
  optionsLock = builtins.fromTOML (builtins.readFile optionsLockFile);
  optionsVendor = rustPlatform.importCargoLock { lockFile = optionsLockFile; };
  optionVersion = name: (lib.findFirst (package: package.name == name)
    (throw "${name} is not in the kernel options lockfile") optionsLock.package).version;
  optionSource = name: "${optionsVendor}/${name}-${optionVersion name}";

  # The fixed-point parser references the types of half but executes none of its
  # operations. Under no_fp_fmt_parse half omits FromStr and all formatting
  # trait implementations, so its object is not linked.
  halfMetadataSource = stdenv.mkDerivation {
    name = "voidport-half-metadata-source";
    src = optionSource "half";
    unpackPhase = ''cp -rL "$src" source; chmod -R u+w source; sourceRoot=source'';
    dontBuild = true;
    postPatch = ''
      substituteInPlace src/binary16.rs src/bfloat.rs \
        --replace-fail '#[cfg(not(target_arch = "spirv"))]' \
        '#[cfg(all(not(target_arch = "spirv"), not(no_fp_fmt_parse)))]'
    '';
    installPhase = ''cp -r . "$out"'';
  };

  # The overflow diagnostics of unused float conversions still type-check under
  # no_fp_fmt_parse. Keep the assertion without formatting a float value.
  fixedSource = stdenv.mkDerivation {
    name = "voidport-fixed-source";
    src = optionSource "fixed";
    unpackPhase = ''cp -rL "$src" source; chmod -R u+w source; sourceRoot=source'';
    dontBuild = true;
    postPatch = ''
      substituteInPlace src/prim_traits.rs \
        --replace-fail 'debug_assert!(!overflow, $overflows_fmt, $overflows_filt(self));' \
        'debug_assert!(!overflow, "floating-point value overflows");'
    '';
    installPhase = ''cp -r . "$out"'';
  };

  zerocopySrc = assert optionVersion "zerocopy" == versionOf "zerocopy";
    "${vendor}/zerocopy-${versionOf "zerocopy"}";
  zerocopyDeriveSrc = "${vendor}/zerocopy-derive-${versionOf "zerocopy-derive"}";

  # `zerocopy-derive` is a proc macro for the build machine, compiled with the
  # ordinary sysroot like `rust/libmacros.so` of the kernel. cargo builds it as a
  # dependency of a holder package, never as the root package, because cargo
  # resolves the development dependencies of a root package, and those are
  # outside the vendored directory.
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
  # Module files whose logic reads no kernel object. Each is compiled on the
  # host into the test of the same name, which includes it by path.
  hostTested = [ "division" "parts" "splice" ];
  hostTests = stdenv.mkDerivation {
    name = "voidport-kernel-host-tests";
    src = ../options;
    nativeBuildInputs = [ rustc cargo ];
    buildPhase = ''
      mkdir -p .cargo
      cat > .cargo/config.toml <<EOF
      [source.crates-io]
      replace-with = "vendored"
      [source.vendored]
      directory = "${optionsVendor}"
      EOF
      CARGO_HOME=$PWD/.cargo-home CARGO_TARGET_DIR=$PWD/target \
        cargo test --locked --offline
      mkdir -p host/tests host/voidport
      ${lib.concatMapStrings (name: ''
        cp ${../tests + "/${name}.rs"} host/tests/${name}.rs
        cp ${../voidport + "/${name}.rs"} host/voidport/${name}.rs
        rustc --edition=2021 --test host/tests/${name}.rs -o ${name}-tests
        ./${name}-tests
      '') hostTested}
    '';
    installPhase = ''mkdir -p "$out"; touch "$out/passed"'';
  };

  # The module is linked by the linker of the kernel it targets. The compiler
  # cache replaces only the compilers, and make takes the last of two
  # assignments.
  cachedCompiler = kbuildStdenv.cc.cc.isCcache or false;
  compilerFlags = lib.escapeShellArgs (kernel.commonMakeFlags
    ++ lib.optionals cachedCompiler [
      (if stdenv.cc.isClang then "CC=${kbuildStdenv.cc.cc}/bin/clang" else "CC=${kbuildStdenv.cc}/bin/gcc")
      "HOSTCC=${kbuildStdenv.cc}/bin/cc"
      "HOSTCXX=${kbuildStdenv.cc}/bin/c++"
    ]) + " ";

  kbuild =
    {
      goal,
      products,
      suffix,
      lint ? false,
    }:
    kbuildStdenv.mkDerivation ({
      name = "voidport-kernel-${suffix}-${kernel.modDirVersion}";
      src = ../.;

      nativeBuildInputs = [ rustc ] ++ lib.optional lint clippy
        ++ kernel.moduleBuildDependencies;

      KDIR = "${kernel.dev}/lib/modules/${kernel.modDirVersion}/build";
      KRUSTFLAGS = "-Dwarnings"
        + lib.optionalString legacyKernel " --cfg voidport_legacy_kernel"
        + lib.optionalString exclusiveCreate " --cfg voidport_exclusive_create";
      KCFLAGS = lib.optionalString legacyKernel "-DVOIDPORT_LEGACY_KERNEL";
      VOIDPORT_PROTO_SRC = protoSrc;
      VOIDPORT_SESSION_SRC = sessionSrc;
      VOIDPORT_ZEROCOPY_SRC = zerocopySrc;
      VOIDPORT_PROCMACRO_DIR = procMacro;
      VOIDPORT_OPTIONS_SRC = ../options;
      VOIDPORT_FIXED_SRC = fixedSource;
      VOIDPORT_HALF_SRC = halfMetadataSource;
      VOIDPORT_AZ_SRC = optionSource "az";
      VOIDPORT_BYTEMUCK_SRC = optionSource "bytemuck";
      VOIDPORT_TYPENUM_SRC = optionSource "typenum";
      VOIDPORT_CFG_IF_SRC = optionSource "cfg-if";

      dontFixup = true;

      # kbuild reads `CLIPPY` only from a command line.
      buildPhase = ''
        runHook preBuild
        make ${compilerFlags}${lib.optionalString lint "CLIPPY=1 "}${goal}
        ${lib.optionalString (goal == "all" || goal == "c-object") ''
          ${python3}/bin/python3 tests/helpers transport/voidport_helpers.o
        ''}
        runHook postBuild
      '';

      installPhase = ''
        runHook preInstall
        ${lib.concatMapStringsSep "\n" (p: ''install -Dm444 ${p} "$out/${p}"'') products}
        runHook postInstall
      '';
    } // lib.optionalAttrs cachedCompiler {
      # The wrapper seed flag must not depend on the output store path.
      NIX_OUTPATH_USED_AS_RANDOM_SEED = "vp-kbuild";
    });

  cObject = kbuild {
    goal = "c-object";
    products = [ "transport/voidport_helpers.o" ];
    suffix = "c-object";
  };

  wireCrate = kbuild {
    goal = "wire-crate";
    products = [ "voidport/voidport_proto.o" ];
    suffix = "wire-crate";
  };

  sessionCrate = kbuild {
    goal = "session-crate";
    products = [ "voidport/voidport_session.o" ];
    suffix = "session-crate";
  };

  # clippy-driver replaces the compiler, so this is a build of its own.
  linted = kbuild {
    goal = "all";
    products = [ "voidport/voidport.ko" ];
    suffix = "clippy";
    lint = true;
  };

  crateInputs = writeText "voidport-kernel-crate-inputs.json" (
    builtins.toJSON {
      voidport-proto = "${protoSrc}";
      voidport-session = "${sessionSrc}";
      lockfile = "${lockFile}";
      kernel-options = "${../options}";
      zerocopy = versionOf "zerocopy";
      zerocopy-derive = versionOf "zerocopy-derive";
    }
  );
in
(kbuild {
  goal = "all";
  products = [ "voidport/voidport.ko" ];
  suffix = "module";
}).overrideAttrs
  (previous: {
    postInstall = ''
      install -Dm444 udev/60-voidport.rules "$out/lib/udev/rules.d/60-voidport.rules"
    '';
    passthru = (previous.passthru or { }) // {
      inherit wireCrate sessionCrate linted crateInputs hostTests cObject;
    };
  })
