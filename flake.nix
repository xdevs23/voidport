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
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "voidport";
          version = "1.0.5";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.fuse3 ];

          # Building the programs does not run the test suite: someone who
          # wants the binaries should not wait for it or be stopped by it.
          # The `tests` package is the same build with the suite switched on.
          doCheck = false;

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

        # The test suite, for whoever asks for it: `nix build .#tests`.
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
