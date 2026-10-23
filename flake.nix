{
  description = "voidport — policy-composed network filesystem for host-to-VM file sharing";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      kernelFor =
        system:
        import ./kernel/nix {
          inherit system;
          nixpkgsPath = nixpkgs;
        };

      noStdTarget = "x86_64-unknown-none";

      # A sysroot with `core` and `compiler_builtins` built for the target
      # without a standard library, from the library source of the compiler of
      # the shell, and with the sysroot crates of the host linked in beside them.
      noStdSysroot =
        pkgs:
        pkgs.runCommand "rust-std-${noStdTarget}"
          {
            nativeBuildInputs = [
              pkgs.rustc
              pkgs.cargo
              # The build script of `compiler_builtins` is a host program and
              # needs a host linker.
              pkgs.stdenv.cc
            ];
            libSrc = pkgs.rustPlatform.rustLibSrc;
          }
          ''
            export HOME="$TMPDIR"
            export CARGO_HOME="$TMPDIR/cargo"
            # The sysroot crates use unstable features of the compiler.
            export RUSTC_BOOTSTRAP=1

            libdir="$out/lib/rustlib/${noStdTarget}/lib"
            mkdir -p "$libdir"
            rustc --edition 2024 -O --crate-type rlib --crate-name core \
              --target ${noStdTarget} --out-dir "$libdir" "$libSrc/core/src/lib.rs"

            # Built as a cargo package, because its build script checks what
            # the target supports. The shim and the vendored dependencies come
            # with the library source.
            cp -r "$libSrc/compiler-builtins/builtins-shim" \
                  "$libSrc/compiler-builtins/compiler-builtins" \
                  "$libSrc/compiler-builtins/libm" "$TMPDIR"
            chmod -R u+w "$TMPDIR/builtins-shim" "$TMPDIR/compiler-builtins" "$TMPDIR/libm"
            printf '\n[workspace]\n' >> "$TMPDIR/builtins-shim/Cargo.toml"
            mkdir -p "$TMPDIR/builtins-shim/.cargo"
            cat > "$TMPDIR/builtins-shim/.cargo/config.toml" <<EOF
            [source.crates-io]
            replace-with = "vendored"
            [source.vendored]
            directory = "$libSrc/vendor"
            EOF
            (
              cd "$TMPDIR/builtins-shim"
              RUSTFLAGS="--sysroot=$out" cargo build --offline --release \
                --target ${noStdTarget} --features compiler-builtins,mem \
                --target-dir "$TMPDIR/target"
            )
            cp "$TMPDIR/target/${noStdTarget}/release/libcompiler_builtins.rlib" "$libdir"

            host="$(rustc --print sysroot)/lib/rustlib"
            ln -s "$host/${pkgs.stdenv.hostPlatform.rust.rustcTargetSpec}" "$out/lib/rustlib/"
            ln -s "$host/etc" "$out/lib/rustlib/"
          '';
    in
    {
      packages = forAllSystems (pkgs: {
        kernel-module = (kernelFor pkgs.stdenv.hostPlatform.system).module;

        default = pkgs.callPackage ./nix/workspace-programs.nix { } {
          pname = "voidport";
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
          src = self;
          nativeBuildInputs = [ pkgs.makeWrapper ];
          nativeCheckInputs = [ pkgs.python3 ];

          postInstall = ''
            # Called by this name, the binary runs as the mount helper.
            ln -s voidport "$out/bin/mount.voidport"
            wrapProgram "$out/bin/voidport-lkml" \
              --set VOIDPORT_LKML_LEI "${pkgs.public-inbox}/bin/lei" \
              --set VOIDPORT_LKML_LEI_VERSION "${pkgs.public-inbox.version}"
            for binary in voidportd voidport voidport-ctl voidport-keeper voidport-lkml voidport-lkml-collect voidport-lkml-status voidport-lkml-verify; do
              found=$(find target -type f -path '*/out/*' -name "$binary.1")
              if [ -z "$found" ]; then
                echo "no manual page was generated for $binary" >&2
                exit 1
              fi
            done
            find target -type f -path '*/out/*' -name '*.1' -print0 |
              while IFS= read -r -d "" page; do
                install -Dm644 "$page" "$out/share/man/man1/$(basename "$page")"
              done
          '';
        };

        tests = self.packages.${pkgs.stdenv.hostPlatform.system}.default.overrideAttrs (_: {
          pname = "voidport-tests";
          doCheck = true;
        });
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            pkg-config
            public-inbox
            python3
            fuse3
            btrfs-progs
            util-linux
            e2fsprogs
            mold
          ];
          # A `RUSTFLAGS` set in the environment replaces these flags, as in
          # the check without a standard library.
          "CARGO_TARGET_${pkgs.stdenv.hostPlatform.rust.cargoEnvVarTarget}_RUSTFLAGS" =
            "-C link-arg=-fuse-ld=mold";
          VOIDPORT_NO_STD_SYSROOT = noStdSysroot pkgs;
          VOIDPORT_NO_STD_TARGET = noStdTarget;
          VOIDPORT_LKML_LEI = "${pkgs.public-inbox}/bin/lei";
          VOIDPORT_LKML_LEI_VERSION = pkgs.public-inbox.version;
          # A `path:.` flake reference copies the whole tree, gitignored files
          # included, into the nix store. Build artifacts stay outside it.
          shellHook = ''
            # Keyed by checkout path: two checkouts that build different
            # revisions into one target directory corrupt each other's rlibs.
            export CARGO_TARGET_DIR="''${CARGO_TARGET_DIR:-$HOME/.cache/voidport-target/$(pwd -P | md5sum | cut -c1-12)}"
            # Several builds may run at once, and unbounded job counts multiply
            # into memory spikes.
            export CARGO_BUILD_JOBS="''${CARGO_BUILD_JOBS:-8}"
            if [ -d .githooks ]; then
              git config core.hooksPath .githooks 2>/dev/null || true
            fi
          '';
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt-rfc-style);
    };
}
