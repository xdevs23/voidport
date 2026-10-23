# The modules in `load` are numbered in load order. The modules in `installed`
# go under lib/modules, where udev finds them through the depmod index. Nothing
# loads those at boot.
{ lib, kernel }:
{
  load,
  installed ? [ ],
}:
''
  dependencies() {
    for chain in "$@"; do
      modprobe -d ${kernel.modules} -S ${kernel.modDirVersion} \
        --show-depends --ignore-install "$chain"
    done | awk '{ print $2 }' | awk '!seen[$0]++'
  }
  unpack() {
    case "$1" in
      *.xz) xz -dc "$1" > "$2" ;;
      *) cp "$1" "$2" ;;
    esac
  }
  module_name() {
    basename "$(basename "$1" .ko.xz)" .ko
  }

  dependencies ${lib.concatStringsSep " " load} > order
  index=0
  while read -r object; do
    index=$((index + 1))
    unpack "$object" "$(printf 'root/modules/%02d-%s.ko' "$index" "$(module_name "$object")")"
  done < order
  ${lib.optionalString (installed != [ ]) ''
    kernel_tree=root/lib/modules/${kernel.modDirVersion}/kernel
    mkdir -p "$kernel_tree"
    dependencies ${lib.concatStringsSep " " installed} > installed
    while read -r object; do
      unpack "$object" "$kernel_tree/$(module_name "$object").ko"
    done < installed
  ''}
''
