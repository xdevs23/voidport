# The minimal guest the probe runs in.
#
# The rule that makes loading sound is that a module is only ever loaded on the
# kernel it was built against. The development machine boots a different
# kernel, so the probe's kernel is booted here instead: this image is that
# kernel, an initramfs holding nothing but a shell, the vsock transport chain
# and the module, and an init that loads them in order and says what happened.
#
# The image carries no server, no network and no disk. Everything it needs is
# on the other side of one vsock connection.
{
  lib,
  runCommand,
  writeText,
  pkgsStatic,
  cpio,
  kmod,
  xz,
  kernel,
  module,
}:
let
  busybox = pkgsStatic.busybox;

  # The applets init uses. Listing them beats installing every applet busybox
  # has: what the guest can do is then readable here.
  applets = [
    "sh"
    "mount"
    "insmod"
    "poweroff"
    "printf"
    "sleep"
  ];

  # The vsock transport is a module in this kernel, and its family must be
  # registered before the probe can ask for an AF_VSOCK socket at all. The
  # transport rides virtio-pci, which is a module too.
  transportChain = [
    "virtio_pci"
    "vmw_vsock_virtio_transport"
  ];

  # How long the guest holds an opened session before it powers itself off.
  # The harness ends the guest as soon as it has read the session, so this is
  # only ever reached by a run whose harness is gone: nothing else would be
  # there to end it, and a guest that outlives its run is a guest the next run
  # collides with.
  sessionSeconds = 900;

  init = writeText "voidport-guest-init" ''
    #!/bin/sh
    # The probe's report is the console, so nothing may be held back from it.
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev
    printf 8 > /proc/sys/kernel/printk

    for object in /modules/*.ko; do
      insmod "$object" || printf 'voidport harness: %s did not load\n' "$object"
    done

    # The port is a kernel command line assignment, which the kernel hands to
    # init as an environment variable: no command line is parsed here. The cid
    # is the module's own default, which is the host.
    if insmod /voidport_probe.ko port="$VOIDPORT_PORT"; then
      printf 'voidport harness: the module loaded\n'
      printf 'voidport harness: complete\n'
      # The module holds the session it opened, so this guest holds it too.
      # The host's own proof that it accepted the session is on its control
      # plane, and a session closed in the same instant it opened could not be
      # read there; the harness ends this guest as soon as it has read it.
      #
      # The wait is bounded all the same. A harness that is killed outright
      # takes no guest down with it, and a guest that outlives its run is a
      # guest the next run collides with.
      held=0
      while [ "$held" -lt ${toString sessionSeconds} ]; do
        held=$((held + 1))
        sleep 1
      done
      printf 'voidport harness: the session outlasted the run\n'
    else
      printf 'voidport harness: the module refused to load\n'
      printf 'voidport harness: complete\n'
    fi
    poweroff -f
    sleep 30
  '';
in
runCommand "voidport-probe-guest-${kernel.modDirVersion}"
  {
    nativeBuildInputs = [
      cpio
      kmod
      xz
    ];
    passthru = { inherit kernel module; };
  }
  ''
    mkdir -p root/bin root/proc root/sys root/dev root/modules "$out"

    cp ${busybox}/bin/busybox root/bin/busybox
    ${lib.concatMapStringsSep "\n" (applet: "ln -s busybox root/bin/${applet}") applets}

    install -m 555 ${init} root/init
    install -m 444 ${module}/voidport_probe.ko root/voidport_probe.ko

    # modprobe answers the load order, so the order is not restated by hand and
    # cannot drift when the kernel's own dependencies change. Each chain is
    # asked for separately and the union keeps the first occurrence, because
    # the chains share their lower members.
    for chain in ${lib.concatStringsSep " " transportChain}; do
      modprobe -d ${kernel.modules} -S ${kernel.modDirVersion} \
        --show-depends --ignore-install "$chain"
    done | awk '{ print $2 }' | awk '!seen[$0]++' > order

    index=0
    while read -r object; do
      index=$((index + 1))
      name=$(basename "$object" .ko.xz)
      name=$(basename "$name" .ko)
      target=$(printf 'root/modules/%02d-%s.ko' "$index" "$name")
      case "$object" in
        *.xz) xz -dc "$object" > "$target" ;;
        *) cp "$object" "$target" ;;
      esac
    done < order

    (cd root && find . -print0 | cpio --null --create --format=newc --quiet) > "$out/initramfs.cpio"
    cp ${kernel}/bzImage "$out/bzImage"
    cp order "$out/transport-order"
    # What this image boots, stated so the ladder can check the module against
    # it instead of assuming the two agree.
    printf '%s\n' "${kernel.modDirVersion}" > "$out/kernel-release"
  ''
