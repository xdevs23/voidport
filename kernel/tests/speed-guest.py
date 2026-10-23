#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the speed comparison of the two clients inside the guest."""

import argparse
import contextlib
import dataclasses
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import termios
import tty


def helper(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


events = helper("guest-events")
records = helper("speed-records")

SCENARIOS = [
    ["seq-write", "--size-mib", "40", "--chunk-kib", "40960"],
    ["build-tree"],
]
COUNTED = ["--warmup", "0", "--reps", "1"]
SHARED = "tree"
NOTIFY_SOCKET = "/run/voidport-notify"
# Longer than the one notification sent by the userspace client, READY=1.
NOTIFICATION_BYTES = 4096


@dataclasses.dataclass(frozen=True)
class Endpoint:
    host: str
    port: int


@dataclasses.dataclass(frozen=True)
class Setup:
    bench: str
    census: str
    server: Endpoint


def run(*command):
    subprocess.run(command, check=True)


class Kernel:
    kind = records.Client.KERNEL

    def __init__(self, namespace, module):
        self.namespace = namespace
        self.module = module
        self.mountpoint = Path("/mnt", self.kind.value)

    def prepare(self):
        self.mountpoint.mkdir(parents=True)
        run("insmod", self.module)

    @contextlib.contextmanager
    def mounted(self, server):
        run("mount", "-t", "voidport", self.namespace, str(self.mountpoint),
            "-o", f"addr={server.host},port={server.port}")
        try:
            yield
        finally:
            run("umount", str(self.mountpoint))


class Userspace:
    kind = records.Client.USERSPACE

    def __init__(self, namespace, program):
        self.namespace = namespace
        self.program = program
        self.mountpoint = Path("/mnt", self.kind.value)

    def prepare(self):
        self.mountpoint.mkdir(parents=True)
        Path(NOTIFY_SOCKET).parent.mkdir(parents=True, exist_ok=True)

    @contextlib.contextmanager
    def mounted(self, server):
        """Mounts the namespace from `server` once the client reports the mount
        ready. When the block ends, it unmounts the namespace and waits for the
        client to exit, and it stops a client that is still running then."""
        url = f"voidport://{server.host}:{server.port}/@{self.namespace}"
        with contextlib.ExitStack() as cleanup:
            readiness = cleanup.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM))
            readiness.bind(NOTIFY_SOCKET)
            cleanup.callback(os.unlink, NOTIFY_SOCKET)
            client = cleanup.enter_context(subprocess.Popen(
                [self.program, "mount", url, str(self.mountpoint), "--no-auto-unmount"],
                env={**os.environ, "NOTIFY_SOCKET": NOTIFY_SOCKET}))
            cleanup.callback(stop, client)
            await_readiness(readiness, client)
            try:
                yield
            finally:
                run("umount", str(self.mountpoint))
            if (status := client.wait()) != 0:
                raise RuntimeError(f"the userspace client exited with {status} after the unmount")


def stop(process):
    if process.poll() is None:
        process.terminate()


def await_readiness(readiness, client):
    exited = os.pidfd_open(client.pid)
    try:
        while True:
            ready, _, _ = select.select([readiness, exited], [], [])
            if exited in ready:
                raise RuntimeError(f"the userspace client exited with {client.wait()} "
                                   "before the mount was ready")
            if b"READY=1" in readiness.recv(NOTIFICATION_BYTES).splitlines():
                return
    finally:
        os.close(exited)


class Census:
    def __init__(self, process, endpoint):
        self.process = process
        self.endpoint = endpoint

    def totals(self):
        self.process.stdin.close()
        counted = self.process.stdout.readline()
        if (status := self.process.wait()) != 0:
            raise RuntimeError(f"voidport-wire-census exited with {status}")
        return records.Totals(**json.loads(counted))


@contextlib.contextmanager
def census(program, server):
    with subprocess.Popen([program, "127.0.0.1:0", f"{server.host}:{server.port}"],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE) as process:
        try:
            listening = process.stdout.readline()
            if not listening:
                raise RuntimeError(
                    f"voidport-wire-census exited with {process.wait()} before it listened")
            yield Census(process, Endpoint(**json.loads(listening)))
        finally:
            stop(process)


def bench(setup, client, arguments, options):
    output = subprocess.run(
        [setup.bench, "--dir", str(client.mountpoint / SHARED),
         "--label", client.kind.value, "--drop-caches", *options, *arguments],
        check=True, stdout=subprocess.PIPE).stdout
    return records.Run.read(json.loads(output))


def timed(setup, client, arguments):
    with client.mounted(setup.server):
        measured = bench(setup, client, arguments, [])
    return records.Record(records.Pass.TIMED, measured)


def counted(setup, client, arguments):
    with census(setup.census, setup.server) as counter:
        with client.mounted(counter.endpoint):
            measured = bench(setup, client, arguments, COUNTED)
        totals = counter.totals()
    return records.Record(records.Pass.COUNTED, measured, totals)


def compare(setup, clients):
    for client in clients:
        client.prepare()
        for arguments in SCENARIOS:
            yield timed(setup, client, arguments)
            yield counted(setup, client, arguments)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--voidport", required=True, help="the userspace client")
    parser.add_argument("--module", required=True, help="the kernel module of the filesystem")
    parser.add_argument("--bench", required=True, help="voidport-bench")
    parser.add_argument("--census", required=True, help="voidport-wire-census")
    args = parser.parse_args()
    namespace = os.environ["VOIDPORT_NAMESPACE"]
    server = Endpoint(os.environ["VOIDPORT_ADDR"], int(os.environ["VOIDPORT_PORT"]))
    setup = Setup(args.bench, args.census, server)
    clients = [Userspace(namespace, args.voidport), Kernel(namespace, args.module)]
    with open("/dev/ttyS1", "r+b", buffering=0) as channel:
        tty.setraw(channel.fileno(), termios.TCSANOW)
        try:
            for record in compare(setup, clients):
                events.request(channel, events.Operation.RECORD, record.as_json())
        except Exception as error:
            events.request(channel, events.Operation.SPEED_FAILED, {"reason": str(error)})
            raise
        events.request(channel, events.Operation.COMPLETE)


if __name__ == "__main__":
    main()
