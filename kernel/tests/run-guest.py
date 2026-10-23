#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run one kernel guest with durable evidence and acknowledged host actions."""

import argparse
import asyncio
import dataclasses
import errno
import fcntl
from fractions import Fraction
import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import signal
import socket
import tempfile
import typing
from urllib.parse import urlsplit

import tomli_w

def helper(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


events = helper("guest-events")
diagnostics = helper("console-diagnostics")
speed_records = helper("speed-records")
mount_verdicts = helper("mount-verdicts")

# QEMU's user networking: the guest's network, the address that leads to this
# machine's loopback, and the static address the guest's early init assigns.
NETWORK = "10.0.2.0/24"
HOST_ADDRESS = "10.0.2.2"
GUEST_ADDRESS = "10.0.2.15/24"


@dataclasses.dataclass(frozen=True)
class Listener:
    transport: str
    host: str
    port: int

    def state(self):
        return {"transport": self.transport, "addr": f"{self.host}:{self.port}"}

    @classmethod
    def reported(cls, transport, endpoint):
        address = urlsplit("//" + endpoint)
        return cls(transport, address.hostname, address.port)


@dataclasses.dataclass(frozen=True)
class VhostUserListener:
    transport: typing.ClassVar[str] = "vhost-user"
    path: str

    def state(self):
        return {"transport": self.transport, "path": self.path}


def reported(transport, endpoint):
    if transport == VhostUserListener.transport:
        return VhostUserListener(endpoint)
    return Listener.reported(transport, endpoint)


# The TCP listener of every guest's server, on this machine's loopback, which
# the guest connects to through QEMU's user networking at the host address.
# Port 0 lets the kernel choose a free port, which the server reports once it
# is bound.
LISTENER = Listener("tcp", "127.0.0.1", 0)
CONTROL_SOCKET = "control.sock"

# The focus whose guest boots with a virtio filesystem device of voidport.
# The device is connected to the server through the keeper. The sockets
# between them are named relative to the directory each process runs in, so
# they fit a unix socket address however deep the evidence directory lies.
VIRTIO_FOCUS = "virtio"
VHOST_USER_LISTENER = VhostUserListener("vhost-user.sock")
KEEPER_SOCKET = "vm.sock"
TAG = "voidport-0"
# The file to which the virtio console of every guest is written. Init sends
# its standard output and standard error and those of every program it runs
# there, so the serial console contains the records of the kernel log only. The
# virtio console has an interrupt of its own: a third ISA serial port would
# share one with the serial console.
PROGRAMS_LOG = "programs.log"
# The processors of every guest. The virtio filesystem device has one request
# queue for each, so the requests of both processors go on queues of their own.
PROCESSORS = 2


class Child:
    def __init__(self, process, log, receipt):
        self.process = process
        self.log = log
        self.receipt = receipt
        self.lines = []
        self.failure = asyncio.get_running_loop().create_future()
        self.changed = asyncio.Condition()
        self.reader = asyncio.create_task(self.capture())
        self.exit = asyncio.create_task(self.reap())

    @classmethod
    async def start(cls, command, directory, name, **kwargs):
        directory.joinpath(name + ".argv.json").write_bytes(events.encode({
            "argv": command, "cwd": str(kwargs.get("cwd", Path.cwd())),
        }))
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT, **kwargs
        )
        return cls(process, directory / (name + ".log"), directory / (name + ".exit.json"))

    async def capture(self):
        with self.log.open("wb") as output:
            while line := await self.process.stdout.readline():
                output.write(line)
                output.flush()
                if self.log.name == "guest.log" and diagnostics.fatal(line.decode(errors="replace")):
                    if not self.failure.done():
                        self.failure.set_result("fatal kernel diagnostic")
                async with self.changed:
                    self.lines.append(line.decode(errors="replace"))
                    self.changed.notify_all()
            async with self.changed:
                self.lines.append(None)
                self.changed.notify_all()

    async def reap(self):
        status = await self.process.wait()
        self.receipt.write_bytes(events.encode({"exit": status}))
        return status

    async def contains(self, text):
        index = 0
        async with self.changed:
            while True:
                for line in self.lines[index:]:
                    if line is None:
                        raise RuntimeError(f"{self.log.name} ended before {text!r}")
                    if text in line:
                        return
                index = len(self.lines)
                await self.changed.wait()

    async def finished(self):
        done, _ = await asyncio.wait([self.exit, self.failure], return_when=asyncio.FIRST_COMPLETED)
        if self.failure in done:
            raise RuntimeError(self.failure.result())
        return self.exit.result()

    async def stop(self):
        if self.process.returncode is None:
            self.process.terminate()
        await self.exit
        await self.reader


async def observed(awaitable, *children):
    operation = asyncio.ensure_future(awaitable)
    try:
        done, _ = await asyncio.wait(
            [operation, *(child.exit for child in children), *(child.failure for child in children)],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for child in children:
            if child.failure in done:
                raise RuntimeError(f"{child.log.name}: {child.failure.result()}")
            if child.exit in done:
                raise RuntimeError(f"{child.log.name} exited with {child.exit.result()}")
        return await operation
    finally:
        if not operation.done():
            operation.cancel()
        await asyncio.gather(operation, return_exceptions=True)


def lay_tree(tree, note, pattern):
    tree.mkdir()
    (tree / "sub").mkdir()
    (tree / "long").mkdir()
    (tree / "long" / ("n" * 255)).write_bytes(b"the longest name")
    for name, data in {
        "note.txt": note, "pattern.bin": pattern,
        "empty": b"", "sub/inner.txt": b"nested", "big.bin": bytes(1048576),
        "hello.sh": b"#!/bin/sh\nprintf 'hello from the mount\\n'\n",
        "secret.txt": b"restricted", "grow.txt": b"small",
        "mtime.txt": b"before", "swap": b"a file for now", "artifact.jar": b"jar",
        "lock": b"",
    }.items():
        (tree / name).write_bytes(data)
    (tree / "hello.sh").chmod(0o755)
    (tree / "secret.txt").chmod(0o600)
    (tree / "link").symlink_to("note.txt")
    os.mkfifo(tree / "fifo")


def lock_free(path):
    with path.open("r+b") as probe:
        try:
            fcntl.lockf(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EAGAIN, errno.EACCES):
                return False
            raise
    return True


def mutate(tree):
    with (tree / "grow.txt").open("ab") as output:
        output.write(b" and more bytes than before")
    path = tree / "mtime.txt"
    before = path.stat().st_mtime_ns
    path.write_bytes(b"after!")
    # The fixture requires a distinct mtime even on a coarse host filesystem.
    os.utime(path, ns=(before + 2_000_000_000, before + 2_000_000_000))
    (tree / "appeared").write_bytes(b"now here")
    (tree / "swap").unlink()
    (tree / "swap").mkdir()

BASE_GUEST_MIB = 1024
MIB = 1 << 20


def guest_memory_mib(archive_size, generic_kasan):
    """Guest memory in MiB: the base size plus two copies of the archive, rounded up.

    Early boot holds the initramfs archive and the root filesystem unpacked from
    it at once. The generic address sanitizer spends an eighth of all memory on
    its shadow memory, so for a kernel built with it the copies count eight
    sevenths of their size.
    """
    copies = Fraction(2 * archive_size, MIB)
    if generic_kasan:
        copies *= Fraction(8, 7)
    return BASE_GUEST_MIB + math.ceil(copies)


async def bound_port(ctl, directory):
    query = await Child.start([ctl, "--socket", CONTROL_SOCKET, "--json", "info"],
                              directory, "info", cwd=directory)
    status = await query.exit
    await query.reader
    if status != 0:
        raise RuntimeError(f"the server information query exited with {status}")
    match json.loads(query.log.read_bytes()):
        case {"status": "ok", "result": {"listeners": list(records)}}:
            listeners = [reported(**record) for record in records]
        case response:
            raise ValueError(f"the server information query failed: {response}")
    # A vhost-user listener beside it has a socket path and no port.
    match [listener for listener in listeners if isinstance(listener, Listener)]:
        case [Listener(transport=LISTENER.transport, host=LISTENER.host, port=port)] if port:
            return port
    raise ValueError(f"the server reports listeners {listeners!r}, not the one configured")


def state_of(listeners, namespace):
    return tomli_w.dumps({"server": {"listeners": [listener.state() for listener in listeners]},
                          "namespaces": [namespace]})


async def start_server(args, directory, name, state, children):
    state_path = directory / (name + ".toml")
    state_path.write_text(state)
    server = await Child.start(
        [args.server, "--state", str(state_path), "--control-socket", CONTROL_SOCKET],
        directory, name, cwd=directory, env={**os.environ, "RUST_LOG": "info"},
    )
    children.append(server)
    await observed(server.contains("serving a data listener"), server)
    return server


async def run(args, work):
    guest = Path(args.guest)
    tree = work / "tree"
    closure = speed = verdicts = None
    if args.mode == "mount":
        verdicts = mount_verdicts.Verdicts()
        note = (guest / "fixture-note").read_bytes()
        lay_tree(tree, note, (guest / "fixture-pattern").read_bytes())
    elif args.mode == "speed":
        speed = speed_records.Comparison(work)
        speed.prepare(tree)
    for name in ("kernel-config", "kernel-release", "kernel-member"):
        if (guest / name).exists():
            shutil.copyfile(guest / name, work / name)
    children = []
    server = vm = None
    writer = None
    outcome = {"verdict": "incomplete"}
    (work / "verdict.json").write_bytes(events.encode(outcome))
    try:
        if args.mode == "closure":
            closure = helper("closure-host").Closure(guest, work, helper("closure-firewall"))
            namespace = closure.namespace(args.namespace)
        else:
            namespace = {"name": args.namespace, "rules": [
                {"path": "/tree", "mode": "rw", "target": str(tree)}
            ]}
        virtio = args.focus == VIRTIO_FOCUS
        device_listeners = [VHOST_USER_LISTENER] if virtio else []
        state = state_of([LISTENER, *device_listeners], namespace)
        if closure:
            closure.verify(state)
        server_directory = work / "server"
        server_directory.mkdir()
        server = await start_server(args, server_directory, "server", state, children)
        port = await observed(bound_port(args.ctl, server_directory), server)
        keepers = []
        if virtio:
            keeper_directory = work / "keeper"
            keeper_directory.mkdir()
            keeper = await Child.start(
                [args.keeper, "--vm", KEEPER_SOCKET, "--server",
                 os.path.relpath(server_directory / VHOST_USER_LISTENER.path, keeper_directory)],
                keeper_directory, "keeper", cwd=keeper_directory,
            )
            children.append(keeper)
            keepers.append(keeper)
            await observed(keeper.contains("waiting for QEMU"), keeper, server)
        attempt = work / "guest"
        attempt.mkdir()
        local, remote = socket.socketpair()
        reader, writer = await asyncio.open_connection(sock=local)
        archive = guest / "initramfs.cpio"
        config = (guest / "kernel-config").read_text().splitlines()
        memory = guest_memory_mib(archive.stat().st_size,
                                  generic_kasan="CONFIG_KASAN_GENERIC=y" in config)
        machine = "q35,accel=kvm"
        device = []
        if virtio:
            # The backend of a vhost-user device maps guest memory, so the
            # memory is a file the keeper can hand on.
            machine += ",memory-backend=guest-memory"
            device = [
                "-object", f"memory-backend-memfd,id=guest-memory,size={memory}M,share=on",
                "-chardev", "socket,id=voidport,path="
                + os.path.relpath(keeper_directory / KEEPER_SOCKET, attempt),
                "-device", f"vhost-user-fs-pci,chardev=voidport,tag={TAG},"
                f"num-request-queues={PROCESSORS}",
            ]
        command = [
            args.qemu, "-machine", machine, "-cpu", "host",
            "-smp", str(PROCESSORS), "-m", f"{memory}M",
            "-nographic", "-no-reboot",
            "-nic", f"user,model=virtio-net-pci,net={NETWORK},host={HOST_ADDRESS}",
            *device,
            "-kernel", str(guest / "bzImage"), "-initrd", str(archive),
            "-append", " ".join([
                "console=ttyS0",
                f"VOIDPORT_ADDR={HOST_ADDRESS}", f"VOIDPORT_PORT={port}",
                f"VOIDPORT_ENDPOINT=addr={HOST_ADDRESS},port={port}",
                f"VOIDPORT_NAMESPACE={args.namespace}",
                f"VOIDPORT_GUEST_ADDRESS={GUEST_ADDRESS}", f"VOIDPORT_FOCUS={args.focus}",
                f"VOIDPORT_BAD_CHILD_OPEN={args.bad_child_open}",
                *([f"VOIDPORT_TAG={TAG}"] if virtio else []),
                *args.boot_parameter,
            ]),
            "-chardev", f"socket,id=events,fd={remote.fileno()}",
            "-chardev", f"file,id=programs,path={PROGRAMS_LOG}",
            # With one port, the device is a single console, which the guest
            # driver sets up while it loads.
            "-device", "virtio-serial-pci,max_ports=1",
            "-device", "virtconsole,chardev=programs",
            "-serial", "mon:stdio", "-serial", "chardev:events",
        ]
        try:
            vm = await Child.start(command, attempt, "guest", pass_fds=(remote.fileno(),),
                                   stdin=asyncio.subprocess.DEVNULL, cwd=attempt)
        finally:
            remote.close()
        children.append(vm)
        await observed(vm.contains("Run /init as init process"), vm, server, *keepers)
        seen = {}
        performed = set()
        holder = None
        server_stopped = False
        complete = False
        with (work / "events.jsonl").open("ab", buffering=0) as history:
            while not complete:
                required = [vm, *keepers] + ([] if server_stopped else [server])
                message = events.decode(await observed(reader.readline(), *required))
                history.write(events.encode({"request": message}))
                identity = message.get("id")
                if not isinstance(identity, str):
                    raise ValueError("test request needs a string id")
                operation = events.Operation(message.get("operation"))
                if identity in seen:
                    if seen[identity][0] != operation:
                        raise ValueError("test request identity was reused for another operation")
                    reply = seen[identity][1]
                else:
                    request = (operation, events.encode(message.get("evidence")))
                    if request in performed:
                        raise ValueError("guest repeated a request with a new identity")
                    performed.add(request)
                    acknowledged = True
                    if operation is events.Operation.CLOSURE_FAILED and closure:
                        raise AssertionError(f"guest closure check failed: {message.get('evidence')}")
                    elif operation is events.Operation.SPEED_FAILED and speed:
                        raise AssertionError(f"guest speed comparison failed: {message.get('evidence')}")
                    elif operation is events.Operation.RECORD and speed:
                        speed.record(message.get("evidence"))
                    elif operation is events.Operation.VERDICT and verdicts:
                        verdicts.record(message.get("evidence"))
                    elif operation is events.Operation.BOOT_COMPLETE and closure:
                        closure.boot(message.get("evidence", {}))
                    elif operation is events.Operation.MUTATE and args.mode == "mount":
                        mutate(tree)
                    elif operation is events.Operation.KILL_SERVER and args.mode == "mount":
                        if server.process.returncode is not None:
                            raise RuntimeError("server exited before the requested fault")
                        await server.stop()
                        server_stopped = True
                    elif operation is events.Operation.RESTART_SERVER and args.mode == "mount":
                        if server.process.returncode is not None:
                            raise RuntimeError("server exited before the requested restart")
                        await server.stop()
                        # The restarted server binds the same vhost-user
                        # socket, to which the keeper connects again.
                        server = await start_server(
                            args, server_directory, "restarted", state, children,
                        )
                    elif operation is events.Operation.LOCK_HOLD and args.mode == "mount":
                        holder = (tree / "lock").open("r+b")
                        fcntl.lockf(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    elif operation is events.Operation.LOCK_RELEASE and holder:
                        holder.close()
                    elif operation is events.Operation.LOCK_FREE and args.mode == "mount":
                        acknowledged = lock_free(tree / "lock")
                    elif operation is events.Operation.COMPLETE:
                        if closure:
                            closure.complete(message.get("evidence"))
                        elif speed:
                            speed.complete()
                        complete = True
                    else:
                        raise ValueError(f"unexpected guest operation {operation.value!r}")
                    reply = {"id": identity, "ok": acknowledged}
                    seen[identity] = (operation, reply)
                writer.write(events.encode(reply))
                if complete:
                    # Receiving this acknowledgement permits immediate shutdown.
                    # A successful exit after this acknowledgement is expected.
                    await writer.drain()
                else:
                    await observed(writer.drain(), vm)
                history.write(events.encode({"reply": reply}))
        status = await observed(vm.finished(), *([] if server_stopped else [server]))
        await vm.reader
        shutil.copyfile(vm.log, work / "guest.log")
        shutil.copyfile(attempt / PROGRAMS_LOG, work / PROGRAMS_LOG)
        if status != 0:
            raise RuntimeError(f"guest exited with {status}")
        if "Power down" not in vm.log.read_text():
            raise AssertionError("guest did not report orderly poweroff")
        for keeper in keepers:
            if (status := await keeper.exit) != 0:
                raise AssertionError(f"the keeper exited with {status}")
        root = Path(__file__).resolve().parents[2]
        check = await Child.start(
            [args.python, str(root / "kernel/tests/console-diagnostics.py"), str(vm.log)],
            work, "console-diagnostics")
        children.append(check)
        if await check.exit != 0:
            raise AssertionError("the guest console contains a fatal kernel diagnostic")
        await check.reader
        if verdicts:
            verdicts.complete(args.expected)
        if closure:
            closure.unchanged()
            if "systemd-shutdown" not in vm.log.read_text():
                raise AssertionError("NixOS did not enter normal systemd shutdown")
        elif args.mode == "mount" and (tree / "note.txt").read_bytes() != note:
            raise AssertionError("read-only assertions changed server bytes")
        outcome = {"verdict": "pass"}
    except asyncio.CancelledError:
        outcome = {"verdict": "incomplete", "reason": "external interruption"}
        raise
    except Exception as error:
        outcome = {"verdict": "fail", "reason": str(error)}
        raise
    finally:
        cleanup_errors = []
        for child in reversed(children):
            try:
                await child.stop()
            except Exception as error:
                cleanup_errors.append(f"{child.log.name}: {error}")
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                # Child exit and the operation outcome are already recorded.
                pass
        if cleanup_errors:
            outcome["cleanup_errors"] = cleanup_errors
            if outcome["verdict"] == "pass":
                outcome["verdict"] = "fail"
        (work / "verdict.json").write_bytes(events.encode(outcome))
        if cleanup_errors:
            raise RuntimeError("child cleanup failed: " + "; ".join(cleanup_errors))


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("mount", "closure", "speed"), required=True)
    for name in ("guest", "server", "ctl", "qemu", "directory", "source"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--keeper", help="the keeper, which the virtio focus needs")
    parser.add_argument("--python", default="python3")
    parser.add_argument("--focus", default="full")
    parser.add_argument("--bad-child-open", default="0")
    parser.add_argument("--boot-parameter", action="append", default=[],
                        help="a parameter to add to the kernel command line, repeatable")
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("expected", nargs="*")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("runs must be positive")
    if args.focus == VIRTIO_FOCUS and args.keeper is None:
        parser.error(f"the {VIRTIO_FOCUS} focus needs --keeper")
    directory = Path(args.directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    task = asyncio.current_task()
    loop = asyncio.get_running_loop()
    for number in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(number, task.cancel)
    for _ in range(args.runs):
        work = Path(tempfile.mkdtemp(prefix="run-", dir=directory))
        (work / "verdict.json").write_bytes(events.encode({"verdict": "incomplete"}))
        (work / "inputs.json").write_bytes(events.encode(vars(args)))
        print(f"kernel guest evidence: {work}", flush=True)
        await run(args, work)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except asyncio.CancelledError:
        raise SystemExit(130)
