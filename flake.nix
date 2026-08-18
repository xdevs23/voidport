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

      # The kernel client is built by kbuild, outside the cargo workspace, from
      # its own directory. It is reachable here so the module is a flake output
      # like everything else this repository builds, and it is reachable
      # directly (`nix-build kernel/nix`) so the ladder can ask for one rung
      # without the whole tree being copied into the store for each.
      kernelFor =
        system:
        import ./kernel/nix {
          inherit system;
          nixpkgsPath = nixpkgs;
        };

      # The bare-metal target the session core is proven std-free against.
      noStdTarget = "x86_64-unknown-none";

      # A sysroot that carries that target beside this machine's own.
      #
      # The rust toolchain nixpkgs builds ships the standard library for the
      # host and for wasm and bpf, and none of those proves what the session
      # core's contract asks for: a 64-bit target with no standard library and
      # no allocator behind it. So the two crates such a target needs — `core`
      # and `compiler_builtins` — are built here, from the very library source
      # the shell's own compiler was built from, and the host's own are linked
      # in beside them so one sysroot answers for both. A `cargo check` against
      # it therefore builds the core for a target that has no `std` to fall
      # back on, which is the proof, and builds the proc macros it needs for
      # the host as usual.
      noStdSysroot =
        pkgs:
        pkgs.runCommand "rust-std-${noStdTarget}"
          {
            nativeBuildInputs = [
              pkgs.rustc
              pkgs.cargo
              # `compiler_builtins` runs a build script, which is an ordinary
              # host program and wants an ordinary host linker.
              pkgs.stdenv.cc
            ];
            libSrc = pkgs.rustPlatform.rustLibSrc;
          }
          ''
            export HOME="$TMPDIR"
            export CARGO_HOME="$TMPDIR/cargo"
            # The sysroot crates are the compiler's own, and they use the
            # compiler's own unstable features; every sysroot build enables
            # them the same way.
            export RUSTC_BOOTSTRAP=1

            libdir="$out/lib/rustlib/${noStdTarget}/lib"
            mkdir -p "$libdir"
            rustc --edition 2024 -O --crate-type rlib --crate-name core \
              --target ${noStdTarget} --out-dir "$libdir" "$libSrc/core/src/lib.rs"

            # `compiler_builtins` is a cargo package with a build script that
            # decides what its target supports, so it is built as one — from
            # the in-tree shim the compiler's own sysroot build uses, against
            # the vendored dependencies the library source ships.
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
        kernel-guest = (kernelFor pkgs.stdenv.hostPlatform.system).guest;

        default = pkgs.rustPlatform.buildRustPackage {
          pname = "voidport";
          version = "1.0.0";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.fuse3 ];

          # Each binary's build script renders its own manual page from its clap
          # definition into that crate's OUT_DIR, subcommand pages included.
          # They are collected here, not written by hand, so an option
          # that changes changes the page with it; a missing page is a build
          # failure, because a silently unshipped manual is worse than none.
          postInstall = ''
            for binary in voidportd voidport voidport-ctl; do
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
            fuse3
            # The loop-image smoke test builds a real filesystem inside a file
            # that lives on a voidport mount, and then fscks it: `mkfs.btrfs` and
            # `btrfs check` are the test's oracle, and `losetup` is how the
            # kernel is pointed at the file. They are test tools, not build
            # inputs, so they belong to the shell the suite runs in.
            btrfs-progs
            util-linux
            # `mkfs.ext4`, for the node-identity criterion: ext4 hands the same
            # (dev, ino) straight back on the first recreate, which is what makes
            # the birth-time half of a node's recorded identity load-bearing. The
            # guarantee has to be proven on the filesystem that breaks the naive
            # check, not only on the ones that happen to be kind.
            e2fsprogs
          ];
          # Where the checks find the std-free target the session core is
          # proven against; `cargo check --target` reaches it through this.
          VOIDPORT_NO_STD_SYSROOT = noStdSysroot pkgs;
          VOIDPORT_NO_STD_TARGET = noStdTarget;
          # Keep build artifacts out of the source tree: the tree may live on a
          # slow network mount, and a `path:.` flake reference copies the whole
          # tree (gitignore does not filter it) into the nix store.
          shellHook = ''
            # Keyed by checkout path: two checkouts (a worktree beside the main
            # tree, above all) building different revisions into one target dir
            # poison each other's rlibs, and the failures surface as phantom
            # compile errors in files neither tree touched.
            export CARGO_TARGET_DIR="''${CARGO_TARGET_DIR:-$HOME/.cache/voidport-target/$(pwd -P | md5sum | cut -c1-12)}"
            # Bound compile parallelism: several builds may run concurrently,
            # and unbounded rustc job counts multiply into memory spikes.
            export CARGO_BUILD_JOBS="''${CARGO_BUILD_JOBS:-8}"
            # Tree hygiene at commit time: external files (kernel sources,
            # other projects) never enter this history.
            if [ -d .githooks ]; then
              git config core.hooksPath .githooks 2>/dev/null || true
            fi
          '';
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt-rfc-style);
    };
}
