#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Runs a heavy command once memory allows one more job, beside other heavy commands.

Usage: slots/slots.py COMMAND [ARGUMENT...]

VOIDPORT_SLOTS_DIR is the directory of the slot files shared by every command
run this way, by default ~/.cache/voidport-slots. There is one slot for each core.
This tool is the jobserver of the cargo, rustc and GNU make processes below
COMMAND. A process below COMMAND that is not a jobserver client, such as a test
binary or a guest boot, runs on the job of COMMAND. A command started below another
command run this way runs on the jobs of the outer one. A job that runs is never
stopped.

A byte goes into the jobserver fifo only once memory allows one more job and a slot
is free. A byte still unread after a PERIOD is taken back, so its slot is free for
other commands. Once per PERIOD, the tool measures the resident memory of COMMAND
and of every process below it. The most memory per job measured so far is the size
of one job. Each command sets aside its jobs times that size, less the memory they
use. One more job starts when the memory available, less what every command sets
aside, is at least the size of one job. One byte goes into the fifo at first, and
twice as many in each PERIOD after one in which every byte was read. Nothing starts
while the kernel reports memory pressure.

While several commands run, a command takes a slot beyond its share, the number of
cores divided by the number of commands, only while no other command below its share
reads every byte it got.

VOIDPORT_HOST_MEMORY is a file to which the host appends the output of
`free -m -s 15`. While it is unset, no host is watched. The memory available is the
smaller of what this machine and the host report. When the last sample is missing
or older than HOST_SAMPLE_LIFETIME, a command starts only while no other command
runs.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import termios
import time
from typing import TextIO

PERIOD = 1.0
# The host appends a sample every 15 seconds. A sample older than four of those
# intervals means that the stream of samples stopped.
HOST_SAMPLE_LIFETIME = 60.0
HOST_TAIL_BYTES = 4096
# Set for the command, so that a command started below it runs on its jobs.
RUN_VARIABLE = "VOIDPORT_SLOTS_RUN"
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
MIB = 1 << 20


class HostUnknown(Exception):
    """The host memory file has no recent complete sample."""


@dataclass(frozen=True)
class Memory:
    """Sizes in bytes."""

    vm_available: int
    pressure: bool
    # None when no host is watched or the host is unknown.
    host_available: int | None
    host_unknown: str | None

    @property
    def available(self) -> int:
        if self.host_available is None:
            return self.vm_available
        return min(self.vm_available, self.host_available)


def vm_available(meminfo: Path) -> int:
    for line in meminfo.read_text().splitlines():
        name, value = line.split(":", 1)
        if name == "MemAvailable":
            amount, unit = value.split()
            assert unit == "kB", f"MemAvailable is given in {unit}"
            return int(amount) * 1024
    raise RuntimeError(f"{meminfo} does not report MemAvailable")


def under_pressure(pressure: Path) -> bool:
    """Whether some task waited for memory within the last ten seconds."""
    for line in pressure.read_text().splitlines():
        kind, *fields = line.split()
        if kind == "some":
            averages = dict(field.split("=", 1) for field in fields)
            return float(averages["avg10"]) > 0
    raise RuntimeError(f"{pressure} does not report the stall of some tasks")


def host_available(log: Path, now: float) -> int:
    """The memory available on the host in bytes, from the last sample in `log`."""
    try:
        status = log.stat()
    except OSError as error:
        raise HostUnknown(f"{log} cannot be read: {error.strerror}") from None
    if now - status.st_mtime > HOST_SAMPLE_LIFETIME:
        raise HostUnknown(f"the last sample in {log} is older than "
                          f"{HOST_SAMPLE_LIFETIME:.0f} seconds")
    start = max(0, status.st_size - HOST_TAIL_BYTES)
    with log.open("rb") as stream:
        stream.seek(start)
        lines = stream.read().decode(errors="replace").split("\n")
    # The first line read can start in the middle of a line, and the last one is
    # complete only once its newline is written.
    complete = lines[1 if start else 0 : -1]
    header = None
    available = None
    for line in complete:
        words = line.split()
        if words[:1] == ["Mem:"] and header and len(words) == len(header) + 1:
            available = int(dict(zip(header, words[1:]))["available"])
        elif "available" in words:
            header = words
    if available is None:
        raise HostUnknown(f"{log} contains no complete sample")
    return available * MIB


@dataclass(frozen=True)
class Signals:
    host: Path | None
    meminfo: Path = Path("/proc/meminfo")
    pressure: Path = Path("/proc/pressure/memory")

    def read(self) -> Memory:
        host, unknown = None, None
        if self.host is not None:
            try:
                host = host_available(self.host, time.time())
            except HostUnknown as error:
                unknown = str(error)
        return Memory(
            vm_available=vm_available(self.meminfo),
            pressure=under_pressure(self.pressure),
            host_available=host,
            host_unknown=unknown,
        )


@dataclass(frozen=True)
class Published:
    """What a command writes into its first slot, sizes in bytes."""

    job_size: int
    set_aside: int
    jobs: int
    # Whether the command read every byte it got, so that it may use one more.
    wants: bool


class Pool:
    def __init__(self, directory: Path, cores: int):
        directory.mkdir(parents=True, exist_ok=True)
        self.directory = directory
        self.cores = cores
        self.paths = [directory / f"slot.{index}" for index in range(cores)]

    @contextmanager
    def decision(self):
        """Lets one command at a time read and write slot files and take slots."""
        with open(self.directory / "lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def survey(self, taken: list[TextIO]) -> tuple[list[TextIO], list[Published]]:
        """Slots in `taken` are left out. The caller closes the free slots it does not take."""
        mine = {slot.name for slot in taken}
        free, others = [], []
        for path in self.paths:
            if str(path) in mine:
                continue
            slot = open(path, "a+")
            try:
                fcntl.flock(slot, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                slot.seek(0)
                text = slot.read()
                slot.close()
                if text:
                    others.append(Published(**json.loads(text)))
                continue
            free.append(slot)
        return free, others


class Jobserver:
    """A fifo from which a jobserver client reads one byte for each job beyond its first."""

    def __init__(self, path: Path):
        path.unlink(missing_ok=True)
        os.mkfifo(path, 0o600)
        self.path = path
        self.fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
        self.handed_out = 0

    @property
    def flags(self) -> str:
        return f"-j --jobserver-auth=fifo:{self.path}"

    def hand_out(self, count: int):
        os.write(self.fd, b"+" * count)
        self.handed_out += count

    def take_back(self) -> int:
        """Reads back every byte nobody took, and returns how many there were."""
        unread = bytearray(4)
        fcntl.ioctl(self.fd, termios.FIONREAD, unread)
        count = min(int.from_bytes(unread, sys.byteorder), self.handed_out)
        if count == 0:
            return 0
        try:
            count = len(os.read(self.fd, count))
        except BlockingIOError:
            return 0
        self.handed_out -= count
        return count

    def close(self):
        os.close(self.fd)
        self.path.unlink(missing_ok=True)


def resident_size(root: int) -> int:
    children: dict[int, list[int]] = {}
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            stat = Path(entry.path, "stat").read_text()
        except OSError:
            continue
        # The name of the program comes in parentheses and can contain anything,
        # so the fields are counted from the last parenthesis on.
        parent = int(stat.rsplit(")", 1)[1].split()[1])
        children.setdefault(parent, []).append(int(entry.name))
    total = 0
    pending = [root]
    while pending:
        pid = pending.pop()
        pending.extend(children.get(pid, []))
        try:
            total += int(Path(f"/proc/{pid}/statm").read_text().split()[1]) * PAGE_SIZE
        except OSError:
            continue
    return total


class Run:
    def __init__(self, pool: Pool, signals: Signals):
        self.pool = pool
        self.signals = signals
        self.slots: list[TextIO] = []
        self.job_size = 0
        self.resident = 0
        self.grant = 1
        self.wants = False
        self.jobserver: Jobserver | None = None
        self.child: subprocess.Popen | None = None
        self.told: set[str] = set()

    def tell(self, message: str):
        if message not in self.told:
            self.told.add(message)
            print(f"slots: {message}", file=sys.stderr, flush=True)

    def set_aside(self, jobs: int) -> int:
        """The memory that `jobs` jobs of this command may still grow into."""
        return max(0, jobs * self.job_size - self.resident)

    def admit(self, wanted: int) -> int:
        with self.pool.decision():
            free, others = self.pool.survey(self.slots)
            try:
                memory = self.signals.read()
                if not self.slots:
                    self.job_size = max((other.job_size for other in others), default=0)
                taken = 0
                if memory.host_unknown:
                    self.tell(f"the host memory is unknown, because {memory.host_unknown}. "
                              "A command starts only while no other command runs.")
                    if not self.slots and len(free) < self.pool.cores:
                        wanted = 0
                share = -(-self.pool.cores // (len(others) + 1))
                short = any(other.wants and other.jobs < share for other in others)
                if not memory.pressure:
                    room = memory.available - sum(other.set_aside for other in others)
                    while (taken < wanted and free
                           and (len(self.slots) < share or not short)
                           and room - self.set_aside(len(self.slots)) >= self.job_size):
                        slot = free.pop()
                        slot.truncate(0)
                        self.slots.append(slot)
                        taken += 1
                if self.slots:
                    self.publish()
                return taken
            finally:
                for slot in free:
                    slot.close()

    def publish(self):
        first = self.slots[0]
        first.truncate(0)
        first.write(json.dumps({"job_size": self.job_size,
                                "set_aside": self.set_aside(len(self.slots)),
                                "jobs": len(self.slots), "wants": self.wants}))
        first.flush()

    def start(self, command: list[str]):
        assert len(self.slots) == 1, "the command starts on its first slot"
        # The fifo goes beside the slots, outside the source tree: a `path:` flake
        # reference copies the tree with its ignored files and fails on a fifo.
        self.jobserver = Jobserver(self.pool.directory / f"jobserver.{os.getpid()}")
        flags = self.jobserver.flags
        self.child = subprocess.Popen(command, env={
            **os.environ, "MAKEFLAGS": flags, "CARGO_MAKEFLAGS": flags,
            RUN_VARIABLE: str(os.getpid()),
        })

    def tick(self):
        returned = self.jobserver.take_back()
        for _ in range(returned):
            self.slots.pop().close()
        self.resident = resident_size(self.child.pid)
        self.job_size = max(self.job_size, self.resident // len(self.slots))
        self.wants = not returned and self.jobserver.handed_out > 0
        wanted = 0 if returned else self.grant
        taken = self.admit(wanted)
        self.jobserver.hand_out(taken)
        if returned:
            self.grant = 1
        elif taken == wanted:
            self.grant = min(2 * self.grant, self.pool.cores)

    def finish(self):
        if self.jobserver:
            self.jobserver.close()
            self.jobserver = None
        for slot in self.slots:
            slot.close()
        self.slots.clear()

    def execute(self, command: list[str]) -> int:
        try:
            while not self.admit(1):
                self.tell("waiting until memory allows one more job and a slot is free.")
                time.sleep(PERIOD)
            self.start(command)
            for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                signal.signal(number, lambda received, _: self.child.send_signal(received))
            while True:
                try:
                    return self.child.wait(timeout=PERIOD)
                except subprocess.TimeoutExpired:
                    self.tick()
        finally:
            self.finish()


def main(arguments: list[str]) -> int:
    if not arguments:
        print(__doc__, file=sys.stderr)
        return 2
    if RUN_VARIABLE in os.environ:
        os.execvp(arguments[0], arguments)
    directory = os.environ.get("VOIDPORT_SLOTS_DIR") or Path.home() / ".cache/voidport-slots"
    host = os.environ.get("VOIDPORT_HOST_MEMORY")
    run = Run(Pool(Path(directory), os.cpu_count()), Signals(host=Path(host) if host else None))
    status = run.execute(arguments)
    # A shell reports a command ended by a signal as 128 and the signal number.
    return status if status >= 0 else 128 - status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
