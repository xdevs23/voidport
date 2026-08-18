# The nixpkgs the repository's flake locks, resolved without the flake.
#
# Reading the lockfile directly, instead of evaluating the flake, keeps a
# direct build of this directory from copying the repository into the store.
# The module's inputs are two files and one crate directory, and a copy of
# everything else would make every unrelated edit in the tree a new store path
# to build against. What this reads is the same revision the workspace builds
# against, so the module and the workspace never disagree about their nixpkgs.
#
# The flake output passes its own input instead and never reaches this file.
let
  lock = builtins.fromJSON (builtins.readFile ../../flake.lock);
  node = lock.nodes.${lock.nodes.${lock.root}.inputs.nixpkgs}.locked;
in
builtins.fetchTarball {
  url = "https://github.com/${node.owner}/${node.repo}/archive/${node.rev}.tar.gz";
  sha256 = node.narHash;
}
