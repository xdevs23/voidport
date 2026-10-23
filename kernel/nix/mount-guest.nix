{
  lib,
  runCommand,
  writeText,
  pkgsStatic,
  stdenv,
  rustPlatform,
  rustc,
  cargo,
  closureInfo,
  callPackage,
  systemdMinimal,
  cpio,
  kmod,
  xz,
  kernel,
  module,
  category ? "stable",
  configuration ? "production",
}:
let
  busybox = pkgsStatic.busybox;
  testVendor = rustPlatform.importCargoLock { lockFile = ../tests/transport/Cargo.lock; };
  mappingVendor = rustPlatform.importCargoLock { lockFile = ../tests/mapping/Cargo.lock; };
  mappingTest = stdenv.mkDerivation {
    name = "voidport-mapping-test";
    nativeBuildInputs = [ rustc cargo ];
    dontUnpack = true;
    buildPhase = ''
      mkdir -p mapping .cargo
      cp ${../tests/mapping.rs} mapping.rs
      cp ${../tests/namespace.rs} namespace.rs
      cp ${../tests/ownership.rs} ownership.rs
      cp ${../tests/record_locks.rs} record_locks.rs
      cp ${../tests/transports.rs} transports.rs
      cp ${../tests/xattr.rs} xattr.rs
      cp ${../tests/mapping/Cargo.toml} mapping/Cargo.toml
      cp ${../tests/mapping/Cargo.lock} mapping/Cargo.lock
      cat > .cargo/config.toml <<EOF
      [source.crates-io]
      replace-with = "vendored"
      [source.vendored]
      directory = "${mappingVendor}"
      EOF
      CARGO_HOME=$PWD/.cargo-home CARGO_TARGET_DIR=$PWD/target \
        cargo build --manifest-path mapping/Cargo.toml --offline --locked --release
    '';
    installPhase = ''
      install -Dm555 target/release/mapping-test "$out/bin/mapping-test"
    '';
  };
  forever = "18446744073709551615";
  transportTest = stdenv.mkDerivation {
    name = "voidport-transport-test";
    # Panic source paths are diagnostics. Without remapping, one inlined
    # dependency can retain the whole vendor tree.
    RUSTFLAGS = "--remap-path-prefix=${testVendor}=vendor";
    VOIDPORT_FOREVER = forever;
    nativeBuildInputs = [ rustc cargo ];
    dontUnpack = true;
    buildPhase = ''
      mkdir -p proto session .cargo
      cat > Cargo.toml <<'EOF'
      [package]
      name = "transport-test"
      version = "0.0.0"
      edition = "2024"
      [workspace]
      [[bin]]
      name = "transport-test"
      path = "${../tests}/transport_peer.rs"
      [dependencies]
      libc = "=0.2.189"
      zerocopy = { version = "=0.8.56", features = ["derive"] }
      netlink-packet-core = "=0.9.0"
      netlink-packet-route = "=0.33.0"
      netlink-sys = "=0.9.0"
      voidport-proto = { path = "proto" }
      voidport-session = { path = "session" }
      EOF
      cat > proto/Cargo.toml <<'EOF'
      [package]
      name = "voidport-proto"
      version = "0.0.0"
      edition = "2024"
      [lib]
      path = "${../../crates/voidport-proto}/src/lib.rs"
      [dependencies]
      zerocopy = { version = "=0.8.56", features = ["derive"] }
      [features]
      userspace = []
      EOF
      cat > session/Cargo.toml <<'EOF'
      [package]
      name = "voidport-session"
      version = "0.0.0"
      edition = "2024"
      [lib]
      path = "${../../crates/voidport-session}/src/lib.rs"
      [dependencies]
      voidport-proto = { path = "../proto" }
      EOF
      cp ${../tests/transport/Cargo.lock} Cargo.lock
      cat > .cargo/config.toml <<EOF
      [source.crates-io]
      replace-with = "vendored"
      [source.vendored]
      directory = "${testVendor}"
      EOF
      CARGO_HOME=$PWD/.cargo-home CARGO_TARGET_DIR=$PWD/target cargo build --offline --locked --release
    '';
    installPhase = ''
      install -Dm555 target/release/transport-test "$out/bin/transport-test"
    '';
  };
  guestEvents = callPackage ./guest-events.nix { };
  # Built here because kernel/nix builds on its own with nix-build, without
  # the flake package.
  client = callPackage ../../nix/workspace-programs.nix { } {
    pname = "voidport";
    version = "0";
    src = lib.fileset.toSource {
      root = ../..;
      fileset = lib.fileset.unions [ ../../Cargo.toml ../../Cargo.lock ../../crates ];
    };
    packages = [ "voidport" ];
  };
  testClosure = closureInfo {
    rootPaths = [ mappingTest transportTest guestEvents client systemdMinimal ];
  };

  applets = [
    "sh"
    "mount"
    "umount"
    "insmod"
    "rmmod"
    "poweroff"
    "printf"
    "sleep"
    "mkdir"
    "ls"
    "cat"
    "stat"
    "readlink"
    "head"
    "dd"
    "grep"
    "chmod"
    "sync"
    "cmp"
    "wc"
    "kill"
    "id"
    "setuidgid"
    "env"
    "test"
    "true"
    "seq"
    "expr"
    "uname"
    "dmesg"
    "ip"
  ];

  fixtureNote = "served over the kernel mount";

  # Each line contains its line number, so data written to the wrong place
  # reads differently, and its size is no multiple of a page.
  fixturePattern = runCommand "voidport-fixture-pattern" { } "seq -w 0 399999 > $out";

  transportChain = [
    "virtio_pci"
    "virtio_net"
  ];
  outputChain = [ "virtio_console" ];
  copyModules = import ./guest-modules.nix { inherit lib kernel; };
  output = import ./guest-output.nix;
  packImage = import ./guest-image.nix {
    inherit kernel category configuration;
    inherit (stdenv.hostPlatform) system;
  };

  # Installed for udev to load. Nothing loads it at boot.
  deviceChain = [ "virtiofs" ];

  # The endpoint options, the address of the server and the address of the
  # guest are kernel command line assignments that the kernel hands init as
  # environment variables.
  init = writeText "voidport-mount-guest-init" ''
    #!/bin/sh
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev
    ${output.toKernelLog}
    mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null
    printf 8 > /proc/sys/kernel/printk

    for object in /modules/*.ko; do
      insmod "$object" || printf 'voidport harness: %s did not load\n' "$object"
    done
    ${output.toConsole}

    ip link set lo up
    ${builtins.readFile ./guest-network.sh}

    endpoint="$VOIDPORT_ENDPOINT"
    addr="$VOIDPORT_ADDR"
    port="$VOIDPORT_PORT"

    mkdir -p /etc
    printf '%s voidport-host.test\n' "$addr" > /etc/hosts
    printf 'hosts: files\n' > /etc/nsswitch.conf
    stats=/sys/kernel/debug/voidport

    report() { guest-verdict "$1" "$2" || exit 1; }
    ok() { report "$1" ok; }
    no() { report "$1" FAILED; }
    done_now() {
      ${lib.optionalString (configuration == "debug") ''
        if [ -r /sys/kernel/debug/kmemleak ]; then
          # A scan reports only objects at least this many seconds old.
          kmemleak_min_age=5
          sleep $((kmemleak_min_age + 1))
          # A detector that disabled itself rejects the scan and lists
          # nothing, so the rejection or the notice in the log fails the case.
          if ! printf scan >/sys/kernel/debug/kmemleak ||
             dmesg | grep -q 'Kernel memory leak detector disabled'; then
            printf 'voidport debug: kmemleak is disabled\n'
            no debug-lifetime
          elif [ -n "$(cat /sys/kernel/debug/kmemleak)" ]; then
            cat /sys/kernel/debug/kmemleak
            no debug-lifetime
          else
            ok debug-lifetime
          fi
        else
          printf 'voidport debug: kmemleak runtime interface unavailable\n'
          no debug-lifetime
        fi
      ''}
      guest-event complete || exit 1
      poweroff -f
      # A failed shutdown must never resume assertions after completion.
      exit 1
    }

    printf 'voidport identity: category=${category} configuration=${configuration} expected=${kernel.modDirVersion} target=${stdenv.hostPlatform.system}\n'
    printf 'voidport identity: running=%s architecture=%s\n' "$(uname -r)" "$(uname -m)"
    if [ "$(uname -r)" != '${kernel.modDirVersion}' ]; then
      no kernel-identity
      done_now
    fi
    for facility in RUST KASAN KASAN_GENERIC UBSAN PROVE_LOCKING DEBUG_ATOMIC_SLEEP DEBUG_KMEMLEAK; do
      grep -E "^(CONFIG_$facility=|# CONFIG_$facility is not set)" /kernel-config
    done
    ${lib.optionalString (configuration == "debug") ''
      for facility in RUST KASAN KASAN_GENERIC UBSAN PROVE_LOCKING DEBUG_ATOMIC_SLEEP DEBUG_KMEMLEAK; do
        if ! grep -q "^CONFIG_$facility=y$" /kernel-config; then
          printf 'voidport debug: required CONFIG_%s unavailable\n' "$facility"
          no debug-configuration
          done_now
        fi
      done
      printf 'voidport debug: KASAN covers compiled memory accesses; UBSAN instruments C, not Rust; lockdep and atomic-sleep check kernel synchronization; kmemleak scans allocations\n'
      ok debug-configuration
    ''}

    load() {
      if ! insmod /voidport.ko; then
        printf 'voidport harness: the module refused to load\n'
        done_now
      fi
    }

    # An unreadable counter prints `unreadable:` and its name, which equals no
    # number and no other output, so every comparison fails.
    counter() {
      printf '%s' "$(cat "$stats/$1" 2>/dev/null || printf 'unreadable:%s' "$1")"
    }

    ${builtins.readFile ../tests/fault-teardown.sh}

    peer_case() {
      if transport-test "$2"; then
        ok "$1"
      else
        no "$1"
        done_now
      fi
    }

    # The kernel reads ipv6.disable only at boot.
    if [ "$VOIDPORT_FOCUS" = ipv6-disabled ]; then
      peer_case address-family-unavailable --address-family
      done_now
    fi

    if [ "$VOIDPORT_FOCUS" = virtio ]; then
      mapping_case() {
        name=$1
        shift
        if mapping-test "$@"; then
          ok "$name"
        else
          no "$name"
          done_now
        fi
      }

      mount -t tmpfs tmpfs /run
      if ! systemd-udevd --daemon --resolve-names=never; then
        printf 'voidport harness: udev did not start\n'
        done_now
      fi
      mapping_case virtio-handover --handover
      mapping_case virtio-absent-tag --absent-tag

      # Nothing the mount caches outlives a request, so every case sends its
      # requests to the server, and a request that finds the server gone waits
      # until it is back.
      virtio="tag=$VOIDPORT_TAG,attr_timeout=0,entry_timeout=0,reconnect_stall=${forever}"
      mkdir -p /virtio
      if mount -t voidport share /virtio -o "$virtio"; then
        ok virtio-mount
      else
        no virtio-mount
        done_now
      fi
      mapping_case virtio-read-write --read-write /virtio "$virtio"
      mapping_case virtio-mapping --mapping /virtio "$virtio"
      mapping_case virtio-restart --restart /virtio "$virtio"

      if umount /virtio && rmmod voidport; then
        ok module-unload
      else
        no module-unload
      fi
      done_now
    fi

    peer_case transport-transitions --transitions

    peer_case read-concurrency --concurrency

    signal_cases() {
      for case in signal-queued signal-partial kill-partial signal-transmitted \
        signal-answered ownership-signal-node ownership-signal-open ownership-signal-dir; do
        peer_case "$case" "--$case"
      done
    }

    if [ "$VOIDPORT_FOCUS" = lifetime ]; then
      if sh -c 'for iteration in 1 2 3; do transport-test --lifecycle || exit; done'; then
        ok active-io-lifecycle
      else
        no active-io-lifecycle
        done_now
      fi
    fi

    load
    mkdir -p /mnt
    verdict=ok
    opens=0
    reaped=0
    open_path=/mnt/tree/note.txt
    if [ "$VOIDPORT_BAD_CHILD_OPEN" = 1 ]; then
      open_path=/mnt/tree/missing-child-open
    fi
    if mount -t voidport share /mnt -o ro,"$endpoint",entry_timeout=0,attr_timeout=0; then
      for iteration in $(seq 1 32); do
        # The wait builtin of the shell hangs with SIGCHLD blocked, so a helper
        # opens the file while a child of the helper exits.
        if mapping-test --child-open "$open_path"; then
          opens=$((opens + 1))
          reaped=$((reaped + 1))
        else
          result=$?
          [ "$result" = 1 ] && reaped=$((reaped + 1))
          verdict=FAILED
        fi
      done
      [ "$opens" = 32 ] && [ "$reaped" = 32 ] || verdict=FAILED
      printf 'voidport benign children: opens=%s reaped=%s\n' "$opens" "$reaped"
      umount /mnt || verdict=FAILED
    else
      verdict=FAILED
    fi
    rmmod voidport || verdict=FAILED
    report benign-child-exit "$verdict"

    if [ "$VOIDPORT_FOCUS" = lifetime ]; then
      signal_cases
      done_now
    fi

    peer_case vfs-options --vfs
    peer_case mount-diagnostics --diagnostics
    peer_case active-io-lifecycle --lifecycle
    peer_case revalidate-retry --retry
    peer_case negative-lifetime --negative-lifetime

    peer_case unix-mount --unix
    peer_case unix-chroot-mount --unix-chroot

    peer_case netns-mount --netns

    peer_case netns-reference --netns-reference

    peer_case peer-failure --peer-failure

    peer_case decoy-failure --decoy-failure

    peer_case unmount-wait --unmount-wait

    peer_case frame-in-parts --frame-in-parts
    peer_case close-frame --close-frame

    peer_case stall-expiry --stall-expiry

    peer_case connection-flaps --flaps

    peer_case sessions-share-node --sessions-share-node

    peer_case connection-threads --connection-threads

    peer_case connections-parallel --connections-parallel

    for case in settle-not-started settle-applied-forget settle-departed-lookup \
      settle-signalled-outcome settle-signalled-mkdir; do
      peer_case "$case" "--$case"
    done

    for case in join-silent join-teardown join-refused; do
      peer_case "$case" "--$case"
    done

    for case in ownership-cleanup-forget ownership-cleanup-release; do
      peer_case "$case" "--$case"
    done

    peer_case write-through --write

    peer_case namespace-orphan --namespace

    peer_case setattr --setattr

    peer_case writable-mapping --mapped-writes

    peer_case direct-io --direct

    peer_case lock-wait --record-locks

    ${lib.optionalString (configuration == "debug") ''
      peer_case allocation-faults --allocation-faults
    ''}

    load
    printf 'voidport harness: the module loaded\n'

    if [ ! -d "$stats" ]; then
      printf 'voidport harness: the statistics directory is absent\n'
      done_now
    fi

    mkdir -p /mnt

    logged_since() {
      [ "$(dmesg | grep -cF -- "$1")" -gt "$2" ]
    }

    # mount(2) alone: busybox runs the mount.voidport helper once mount(2)
    # fails.
    kernel_refuses() {
      before=$(dmesg | grep -cF -- "$1")
      if mount -i -t voidport share /mnt -o "$2" 2>/dev/null; then
        umount /mnt 2>/dev/null
        return 1
      fi
      logged_since "$1" "$before"
    }

    if kernel_refuses 'port must be 1 to 65535' "ro,addr=$addr,port=0"; then
      ok invalid-port
    else
      no invalid-port
    fi
    if kernel_refuses 'addr given twice' "ro,$endpoint,addr=$addr"; then
      ok duplicate-addr
    else
      no duplicate-addr
    fi
    if kernel_refuses "Unknown parameter 'bogus'" "ro,$endpoint,bogus=1"; then
      ok unknown-option
    else
      no unknown-option
    fi
    if kernel_refuses 'path must be an absolute path inside the namespace' \
      "ro,$endpoint,path=tree"; then
      ok relative-path
    else
      no relative-path
    fi

    url="voidport://voidport-host.test:$port/@share/tree"
    mkdir -p /url
    shows_path() {
      [ "$(cat /url/note.txt)" = '${fixtureNote}' ] && [ ! -e /url/tree ]
    }
    changes="filesystem option changes require a new mount"

    verdict=ok
    if mount.voidport "$url" /url -n -o ro,nosuid,attr_timeout=0; then
      shows_path || verdict=FAILED
      grep -qF "$url /url voidport ro,nosuid," /proc/mounts || verdict=FAILED
      mount -i -o remount,ro,path=/tree /url || verdict=FAILED
      before=$(dmesg | grep -cF -- "$changes")
      if mount -i -o remount,ro,path=/tree/sub /url 2>/dev/null; then
        verdict=FAILED
      fi
      logged_since "$changes" "$before" || verdict=FAILED
      mount.voidport "$url" /url -o remount,rw,nosuid,attr_timeout=0 || verdict=FAILED
      grep -qF "$url /url voidport rw,nosuid," /proc/mounts || verdict=FAILED
      if message=$(mount.voidport "$url" /url -o remount,path=/tree/sub 2>&1); then
        verdict=FAILED
      fi
      case $message in
        *"$changes"*) ;;
        *) verdict=FAILED ;;
      esac
      umount /url || verdict=FAILED
    else
      verdict=FAILED
    fi
    report url-helper "$verdict"

    verdict=ok
    if mount -t voidport "$url" /url; then
      shows_path || verdict=FAILED
      umount /url || verdict=FAILED
    else
      verdict=FAILED
    fi
    report url-type "$verdict"

    verdict=ok
    if message=$(voidport mount --dispatch-threads 2 "$url" /url 2>&1); then
      verdict=FAILED
      umount /url
    fi
    case $message in
      *"--dispatch-threads shapes only the FUSE client"*) ;;
      *) verdict=FAILED ;;
    esac
    if voidport mount --attr-timeout 0 "$url" /url; then
      shows_path || verdict=FAILED
      grep -qF "$url /url voidport rw," /proc/mounts || verdict=FAILED
      voidport umount /url || verdict=FAILED
    else
      verdict=FAILED
    fi
    report url-client "$verdict"

    forever=${forever}
    if mount -t voidport share /mnt -o ro,"$endpoint",attr_timeout=$forever,entry_timeout=$forever; then
      ok mount
    else
      no mount
      done_now
    fi

    if mount -o remount,rw /mnt && mount -o remount,ro /mnt; then
      ok remount
    else
      no remount
    fi

    if [ "$(cat /mnt/tree/note.txt)" = '${fixtureNote}' ]; then
      ok read-file
    else
      no read-file
    fi
    if [ -f /mnt/tree/empty ] && [ "$(wc -c </mnt/tree/empty)" = "0" ]; then
      ok read-empty
    else
      no read-empty
    fi
    if ls /mnt | grep -q tree && ls /mnt/tree | grep -q note.txt && ls /mnt/tree | grep -q sub; then
      ok readdir
    else
      no readdir
    fi
    longest=
    for _ in $(seq 255); do longest="n$longest"; done
    if [ "$(cat "/mnt/tree/long/$longest")" = "the longest name" ] &&
       ls /mnt/tree/long | grep -qx "$longest"; then
      ok name-max
    else
      no name-max
    fi
    if [ "$(cat /mnt/tree/sub/inner.txt)" = "nested" ]; then
      ok read-nested
    else
      no read-nested
    fi
    if stat /mnt/tree/note.txt >/dev/null 2>&1 && stat -f /mnt >/dev/null 2>&1; then
      ok getattr
    else
      no getattr
    fi
    if [ "$(readlink /mnt/tree/link)" = "note.txt" ]; then
      ok readlink
    else
      no readlink
    fi
    if [ "$(wc -c </mnt/tree/big.bin)" = "1048576" ] &&
       [ "$(dd if=/mnt/tree/big.bin bs=1 skip=1048575 count=1 2>/dev/null | wc -c)" = "1" ]; then
      ok read-large
    else
      no read-large
    fi

    if [ -p /mnt/tree/fifo ]; then
      ok special-inode
    else
      no special-inode
    fi

    before="$(cat /mnt/tree/note.txt)"
    if printf x >> /mnt/tree/note.txt 2>/dev/null; then
      no write-refused
    else
      [ "$(cat /mnt/tree/note.txt)" = "$before" ] && ok write-refused || no write-refused
    fi

    if mapping-test /mnt/tree/note.txt; then
      ok mapping-modes
    else
      no mapping-modes
    fi

    if /mnt/tree/hello.sh 2>/dev/null | grep -q "hello from the mount"; then
      ok exec-from-mount
    else
      no exec-from-mount
    fi

    if cat /mnt/tree/secret.txt >/dev/null 2>&1 &&
       mapping-test --local-denial; then
      ok credentials
    else
      no credentials
    fi

    mkdir -p /rw
    verdict=ok
    if mount -t voidport share /rw -o "$endpoint",attr_timeout=0; then
      mapping-test --xattr /rw/tree/artifact.jar /rw/tree/sub || verdict=FAILED
      umount /rw || verdict=FAILED
    else
      verdict=FAILED
    fi
    report xattr-acl "$verdict"

    mkdir /fresh
    if ! mount -t voidport share /fresh -o ro,"$endpoint",entry_timeout=0,attr_timeout=0; then
      no negative-zero
      done_now
    fi
    old_size="$(wc -c </fresh/tree/grow.txt)"
    old_mtime_bytes="$(cat /fresh/tree/mtime.txt)"
    was_file=no
    [ ! -f /fresh/tree/swap ] || was_file=yes
    negative=ok
    mapping-test --negative-zero || negative=FAILED
    new_size="$(wc -c </fresh/tree/grow.txt)"
    [ "$new_size" -gt "$old_size" ] && ok revalidate-size || no revalidate-size
    if [ "$old_mtime_bytes" = before ] &&
       [ "$(cat /fresh/tree/mtime.txt)" = 'after!' ] &&
       [ "$(wc -c </fresh/tree/mtime.txt)" = 6 ]; then
      ok revalidate-mtime
    else
      no revalidate-mtime
    fi
    [ "$was_file" = yes ] && [ -d /fresh/tree/swap ] && ok revalidate-replace || no revalidate-replace
    umount /fresh || negative=FAILED
    report negative-fixture "$negative"

    # Only the helper can exit on a special-builtin redirection failure.
    # Its callback runs only after the descriptor has actually opened.
    with_open_file() (
      exec 7<"$1"
      shift
      "$@"
      result=$?
      exec 7<&-
      exit "$result"
    )
    refuse_unmount() { ! umount /mnt 2>/dev/null; }
    detach_retained() {
      umount -l /mnt &&
        ! grep -q ' /mnt ' /proc/mounts &&
        ! rmmod voidport 2>/dev/null &&
        [ "$(cat <&7)" = '${fixtureNote}' ]
    }

    if with_open_file /mnt/tree/note.txt refuse_unmount; then
      ok busy-unmount
    else
      no busy-unmount
    fi
    if umount /mnt; then
      ok unmount
    else
      no unmount
    fi

    verdict=ok
    if mount -t voidport share /mnt -o "$endpoint",entry_timeout=$forever,attr_timeout=$forever; then
      if mount -t voidport share /fresh -o ro,"$endpoint",entry_timeout=0,attr_timeout=0; then
        mapping-test --namespace || verdict=FAILED
        umount /fresh || verdict=FAILED
      else
        verdict=FAILED
      fi
      umount /mnt || verdict=FAILED
    else
      verdict=FAILED
    fi
    report namespace-operations "$verdict"

    admitted="$(counter nodes_admitted)"
    forgotten="$(counter nodes_forgotten)"
    opened="$(counter handles_opened)"
    released="$(counter handles_released)"
    live="$(counter replies_live)"
    inflight="$(counter requests_in_flight)"
    if [ "$admitted" = "$forgotten" ] && [ "$opened" = "$released" ] &&
       [ "$live" = 0 ] && [ "$inflight" = 0 ]; then
      ok node-balance
    else
      printf 'voidport harness: admitted=%s forgotten=%s opened=%s released=%s live=%s inflight=%s\n' \
        "$admitted" "$forgotten" "$opened" "$released" "$live" "$inflight"
      no node-balance
    fi

    verdict=ok
    if mount -t voidport share /mnt -o ro,"$endpoint"; then
      with_open_file /mnt/tree/note.txt detach_retained || verdict=FAILED
      if grep -q ' /mnt ' /proc/mounts; then
        umount /mnt || verdict=FAILED
      fi
    else
      verdict=FAILED
    fi
    report lazy-detach "$verdict"

    verdict=ok
    if mount -t voidport share /mnt -o "$endpoint"; then
      mapping-test --record-locks /mnt/tree/lock || verdict=FAILED
      umount /mnt || verdict=FAILED
    else
      verdict=FAILED
    fi
    report record-locks "$verdict"

    if rmmod voidport; then
      ok module-unload
    else
      no module-unload
    fi

    load
    verdict=ok
    if mount -t voidport share /mnt -o ro,"$endpoint",entry_timeout=0,attr_timeout=0; then
      mapping-test --ownership || verdict=FAILED
      umount /mnt || verdict=FAILED
      [ "$(counter requests_in_flight)" = 0 ] && [ "$(counter replies_live)" = 0 ] &&
        [ "$(counter handles_opened)" = "$(counter handles_released)" ] || verdict=FAILED
    else
      verdict=FAILED
    fi
    rmmod voidport || verdict=FAILED
    report ownership-reclaim "$verdict"

    signal_cases

    # This is last, because it drops the server every earlier mount needed.
    load
    verdict=ok
    if mount -t voidport share /mnt -o ro,"$endpoint",reconnect_stall=0,attr_timeout=0,entry_timeout=0; then
      before_loss="$(counter connections_lost)"
      guest-event kill-server || { no host-acknowledgement; done_now; }
      cat /mnt/tree/note.txt >/dev/null 2>&1
      [ "$?" = 1 ] || verdict=FAILED
      [ "$(counter connections_lost)" -gt "$before_loss" ] || verdict=FAILED
    else
      verdict=FAILED
    fi
    fault_teardown
    report connection-fault "$verdict"

    done_now
  '';
in
runCommand "voidport-mount-guest-${kernel.modDirVersion}"
  {
    nativeBuildInputs = [
      cpio
      kmod
      xz
    ];
    passthru = { inherit kernel module mappingTest transportTest init guestEvents client; };
  }
  ''
    mkdir -p root/bin root/proc root/sys root/dev root/run root/modules root/sys/kernel/debug "$out"

    cp ${busybox}/bin/busybox root/bin/busybox
    ${lib.concatMapStringsSep "\n" (applet: "ln -s busybox root/bin/${applet}") applets}

    mkdir -p root/nix/store
    while read -r dependency; do
      cp -a "$dependency" root/nix/store/
    done < ${testClosure}/store-paths
    ln -s ${guestEvents}/bin/guest-event root/bin/guest-event
    ln -s ${guestEvents}/bin/guest-verdict root/bin/guest-verdict
    ln -s ${mappingTest}/bin/mapping-test root/bin/mapping-test
    ln -s ${transportTest}/bin/transport-test root/bin/transport-test
    ln -s ${client}/bin/voidport root/bin/voidport
    ln -s ${client}/bin/voidport root/bin/mount.voidport
    install -m 555 ${init} root/mount-init
    install -m 555 ${writeText "voidport-guest-init-launcher" ''
      #!/bin/sh
      exec /bin/mapping-test --guest-init
    ''} root/init

    ${copyModules {
      load = transportChain ++ outputChain;
      installed = transportChain ++ deviceChain;
    }}

    # depmod writes the index in which udev's kmod finds the module.
    release=${kernel.modDirVersion}
    tree=root/lib/modules/$release
    install -Dm444 ${module}/voidport/voidport.ko "$tree/extra/voidport.ko"
    ln -s "lib/modules/$release/extra/voidport.ko" root/voidport.ko

    cp ${kernel.modules}/lib/modules/$release/modules.builtin \
      ${kernel.modules}/lib/modules/$release/modules.builtin.modinfo "$tree/"
    (cd "$tree" && find kernel extra -name '*.ko' | sort > modules.order)
    depmod -b root "$release"

    ln -s ${systemdMinimal}/lib/systemd/systemd-udevd root/bin/systemd-udevd
    ln -s ${systemdMinimal}/bin/udevadm root/bin/udevadm
    install -Dm444 ${module}/lib/udev/rules.d/60-voidport.rules \
      root/etc/udev/rules.d/60-voidport.rules

    cp ${fixturePattern} root/fixture-pattern
    cp ${kernel.configfile} root/kernel-config
    ${packImage}
    printf '%s' '${fixtureNote}' > "$out/fixture-note"
    cp ${fixturePattern} "$out/fixture-pattern"
  ''
