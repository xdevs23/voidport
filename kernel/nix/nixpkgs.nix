# Reads the lockfile directly instead of evaluating the flake, so that a direct
# build of this directory does not copy the repository into the store.
let
  lock = builtins.fromJSON (builtins.readFile ../../flake.lock);
  node = lock.nodes.${lock.nodes.${lock.root}.inputs.nixpkgs}.locked;
in
builtins.fetchTarball {
  url = "https://github.com/${node.owner}/${node.repo}/archive/${node.rev}.tar.gz";
  sha256 = node.narHash;
}
