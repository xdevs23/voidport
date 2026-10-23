{
  kernel,
  category,
  configuration,
  system,
}:
''
  (cd root && find . -print0 | cpio --null --create --format=newc --quiet) > "$out/initramfs.cpio"
  cp ${kernel}/bzImage "$out/bzImage"
  cp ${kernel.configfile} "$out/kernel-config"
  printf '%s\n' '${kernel.modDirVersion}' > "$out/kernel-release"
  printf '%s\n' '${category} ${configuration} ${system}' > "$out/kernel-member"
''
