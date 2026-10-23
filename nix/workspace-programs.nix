# `packages` lists the workspace packages to build, and every package is built
# when it is empty. Every other argument goes to buildRustPackage as it is.
{
  lib,
  rustPlatform,
  pkg-config,
  fuse3,
}:
{
  packages ? [ ],
  nativeBuildInputs ? [ ],
  ...
}@arguments:
rustPlatform.buildRustPackage (
  removeAttrs arguments [ "packages" ]
  // {
    cargoLock.lockFile = ../Cargo.lock;
    nativeBuildInputs = [ pkg-config ] ++ nativeBuildInputs;
    buildInputs = [ fuse3 ];

    doCheck = false;
  }
  // lib.optionalAttrs (packages != [ ]) {
    cargoBuildFlags = map (name: "--package=${name}") packages;
  }
)
