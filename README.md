# voidport

A network filesystem for sharing host directories with virtual machines. A
namespace starts empty, and rules attach host paths to it, each one `rw`, `ro`
or `hidden`. The server checks every operation against the rules. Rules can
change while guests have the namespace mounted.

| Program | What it does |
|---|---|
| `voidportd` | The server. It reads its configuration from a TOML state file and runs the listeners for guests and the control socket. |
| `voidport` | The guest client: `voidport mount`, `voidport umount`, `voidport subscribe`, and the `mount.voidport` helper of mount(8). |
| `voidport-ctl` | Changes the configuration of a running server through its control socket. |
| `voidport-keeper` | Connects the `vhost-user-fs-pci` device of a virtual machine to `voidportd`, and makes the device available while `voidportd` restarts. |

Every program has a manual page (`man voidportd`, `man voidport`, and one per
subcommand) and `--help`.

## Build

```console
$ nix develop -c cargo build --release
```

`nix build` builds the programs with their manual pages and the
`mount.voidport` link. `nix build .#kernel-module` builds the kernel module.

## Quickstart

Share a directory. Name at least one listener: `--addr HOST:PORT`, `--unix
PATH` or `--vsock PORT`, each repeatable.

```console
$ voidportd share /srv/shared/project --addr 0.0.0.0:9000
namespace "share" is being served.

Mount it from the guest:
    voidport mount voidport://0.0.0.0:9000/@share /mnt/share

Reconfigure it from this machine:
    voidport-ctl --socket /home/you/.local/state/voidport/control.sock info

auth is "none": anything that can connect to the tcp listener can mount this namespace. See the Security section of README.md.
```

Run the printed line in the guest, with an address of the host that the guest
can connect to:

```console
$ voidport mount voidport://10.0.2.2:9000/@share /mnt/share
$ ls /mnt/share/srv/shared/project
README.md  src/
```

The directory appears below the mountpoint under the path it has on the host.
`share` writes the share into `$XDG_STATE_HOME/voidport/state.toml` (or
`--state PATH`) and then starts the server on that file, so the share survives
a restart. Other options: `--ro`, `--name NAME` (default `share`) and
`--control-socket PATH`. With `--vsock 0` or a tcp port 0, the server picks a
free port at every start.

## Configure

The state file contains the whole configuration. `examples/state.toml` shows
every key with a comment. Start the server on a state file:

```console
$ voidportd --state state.toml
```

A missing state file is created empty. A file that does not parse stops the
start. The server writes every change made through `voidport-ctl` back to
the file. Started with `NOTIFY_SOCKET` set, the server sends `READY=1` once
the control socket and every listener accept connections.

Change a running server with `voidport-ctl`:

```console
$ voidport-ctl namespace list
$ voidport-ctl rule add project /docs --mode ro --target /srv/shared/docs
$ voidport-ctl rule add project /work --match 'project-*' --mode rw
$ voidport-ctl rule add project /secrets --mode hidden
$ voidport-ctl rule remove project /docs
$ voidport-ctl xattr add project 'user.*' --write deny
$ voidport-ctl listener add --addr 0.0.0.0:9000
$ voidport-ctl session list
$ voidport-ctl resolve project /docs/index.md
```

A rule change applies to new lookups and opens. Open handles still have the
access they were opened with.

Without `--socket`, `voidport-ctl` and `voidportd --tui` use
`$XDG_STATE_HOME/voidport/control.sock` and then `/run/voidport/control.sock`.

## Mount

A mount URL contains the namespace name after `@`. It may add a path inside
the namespace:

* `voidport://HOST:PORT/@project/src` over tcp
* `voidport+unix://%2Frun%2Fvoidport%2Fdata.sock/@project` over a unix socket,
  with the socket path percent-encoded
* `voidport+vsock://2:1024/@project` over vsock, where 2 is the cid of the host

`voidport umount DIR` unmounts either kind of mount.

A file changed through one mount shows in another mount after the attribute
timeout. `fcntl` record locks work across mounts. `flock` locks work only
within one mount.

### FUSE client

`voidport mount URL DIR` mounts over FUSE when the kernel module is not
loaded or the process may not mount through it, and always for a vsock URL.
It needs `/dev/fuse` and runs in the foreground until the mount ends.
`SIGINT` and `SIGTERM` unmount. Options: `--read-only`, `--allow-other`,
`--attr-timeout` and `--entry-timeout` (seconds, default 1),
`--dispatch-threads`, `--reconnect-stall` (seconds, default 5),
`--no-auto-unmount`, `--no-privileged-bits` and `--direct-io`. Started with
`NOTIFY_SOCKET` set, it sends `READY=1` once the mount is up.

### Kernel module

`nix build .#kernel-module` builds `voidport.ko` for the kernel of
`linuxPackages_latest` in the nixpkgs revision locked by the flake. Load it
only on that kernel:

```console
# insmod result/voidport/voidport.ko
```

With the module loaded, `voidport mount` of a tcp or unix URL mounts through
the module and returns at once. A kernel mount needs `CAP_SYS_ADMIN`. mount(8)
and fstab use the same URL through the `mount.voidport` helper:

```console
# mount -t voidport voidport://build-host:9000/@project/src /mnt/src
$ grep voidport /etc/fstab
voidport://build-host:9000/@project/src /mnt/src voidport _netdev 0 0
```

The generic mount options work, and the module takes `attr_timeout`,
`entry_timeout`, `reconnect_stall`, `no_privileged_bits` and `direct_io`.
Busybox mount does not pass the generic options, such as `ro`, to the helper.

A virtual machine can also connect to the server through a virtio device.
Add a vhost-user listener, start the keeper before QEMU, and give QEMU the
device with a tag that starts with `voidport-`:

```console
$ voidport-ctl listener add --vhost-user /run/voidport/vhost-user.sock
$ voidport-keeper --vm /run/vm/voidport.sock --server /run/voidport/vhost-user.sock
$ qemu-system-x86_64 ... -m 4G \
    -object memory-backend-memfd,id=mem,size=4G,share=on \
    -machine q35,memory-backend=mem \
    -chardev socket,id=voidport,path=/run/vm/voidport.sock \
    -device vhost-user-fs-pci,chardev=voidport,tag=voidport-0
```

Install `result/lib/udev/rules.d/60-voidport.rules` from the module build in
the guest. The rule hands the device to the module. Then mount the namespace
by the tag, without the helper:

```console
# mount -i -t voidport project /mnt/project -o tag=voidport-0
```

## Follow a namespace

`voidport subscribe URL` prints one JSON object per line: a `snapshot` of
every share first, then `added`, `changed`, `removed`, `lapsed`,
`disconnected`, `resumed` and `ended`. After `lapsed` and `resumed`, a new
snapshot replaces all earlier state.

```console
$ voidport subscribe voidport://10.0.2.2:9000/@project
{"entries":[{"kind":"directory","mode":"rw","path":"/src"}],"event":"snapshot","v":1}
{"event":"added","kind":"directory","mode":"ro","path":"/docs","v":1}
{"event":"removed","path":"/docs","v":1}
```

`examples/mount-manager.sh` mounts every share under a directory and unmounts
the shares that go away:

```console
$ examples/mount-manager.sh voidport://10.0.2.2:9000/@project /mnt/project
```

## Security

Every namespace uses `auth = "none"`. Any process that can connect to a data
listener can mount every namespace of the server, and read and write what the
rules allow. The traffic is neither encrypted nor authenticated.

* Every network that can route to the address of a tcp listener can connect
  to it. Bind it to an interface that only the virtual machines can connect
  to, and never use it across an untrusted network. A server with a tcp
  listener prints a note about this at start.
* Every virtual machine on the host can connect to a vsock listener, and the
  host itself can where the vsock loopback module is loaded. Set `cid` to
  accept one machine only.
* Unix and vhost-user listeners and the control socket are created with mode
  0600. A process that can connect to the control socket can change every
  namespace.

## Develop

```console
$ ./check
```

`./check` runs `cargo fmt --check`, `cargo clippy -D warnings` and the test
suite of the workspace in the development shell. Run the tests of one crate
with `nix develop -c cargo test -p voidportd`. The end-to-end tests mount over
FUSE and need `/dev/fuse`. `kernel/ladder` builds and checks the kernel module
and runs its tests in KVM guests.

## License

The full texts are in `LICENSES/`.

| Component | License |
|---|---|
| `voidportd` | AGPL-3.0-only |
| `voidport-proto`, `voidport-session` | MIT |
| `kernel/` | GPL-2.0-only |
| every other crate | GPL-3.0-only |
