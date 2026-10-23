#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Checks of the admission rule, the jobserver and the release of slots, on a pool of
their own and with memory signals read from files the checks write."""

from contextlib import redirect_stderr
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

import slots

GIB = 1 << 30
HERE = Path(__file__).resolve().parent

# A job below the command: reads one byte from the jobserver, reports it on the
# fifo named first, waits for a line on the fifo named second and gives the byte back.
JOB = """
import os, sys
fifo = os.environ["CARGO_MAKEFLAGS"].rsplit("fifo:", 1)[1]
jobserver = os.open(fifo, os.O_RDWR)
token = os.read(jobserver, 1)
with open(sys.argv[1], "w") as report:
    report.write("job\\n")
with open(sys.argv[2]) as release:
    release.readline()
os.write(jobserver, token)
"""

KILLED_JOB = """
import os, signal
fifo = os.environ["CARGO_MAKEFLAGS"].rsplit("fifo:", 1)[1]
os.read(os.open(fifo, os.O_RDWR), 1)
os.kill(os.getpid(), signal.SIGKILL)
"""

HOLDER = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import slots
directory = Path(sys.argv[2])
run = slots.Run(slots.Pool(directory / "pool", 4),
                slots.Signals(host=None, meminfo=directory / "meminfo",
                              pressure=directory / "pressure"))
assert run.admit(3) == 3
print("ready", flush=True)
sys.stdin.read()
"""


def free_sample(available_mib: int, header: str = "total used free shared buff/cache available") -> str:
    values = {"total": 128000, "available": available_mib}
    columns = header.split()
    line = "Mem: " + " ".join(str(values.get(column, 1000)) for column in columns)
    return f"{header}\n{line}\nSwap: 0 0 0\n\n"


class Machine:
    def __init__(self, test: unittest.TestCase):
        temporary = tempfile.TemporaryDirectory()
        test.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.meminfo = self.directory / "meminfo"
        self.pressure = self.directory / "pressure"
        self.host = self.directory / "free.log"
        self.pool = slots.Pool(self.directory / "pool", 4)
        self.memory(64 * GIB)
        self.stall(0)

    def memory(self, available: int):
        self.meminfo.write_text(f"MemTotal: {128 * GIB // 1024} kB\n"
                                f"MemAvailable: {available // 1024} kB\n")

    def stall(self, average: float):
        self.pressure.write_text(f"some avg10={average:.2f} avg60=0.00 avg300=0.00 total=0\n"
                                 "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")

    def host_sample(self, available: int):
        with self.host.open("a") as log:
            log.write(free_sample(available // slots.MIB))

    def run(self, watch_host: bool = False) -> slots.Run:
        return slots.Run(self.pool, slots.Signals(host=self.host if watch_host else None,
                                                  meminfo=self.meminfo, pressure=self.pressure))

    def free_slots(self) -> int:
        with self.pool.decision():
            free, _ = self.pool.survey([])
        for slot in free:
            slot.close()
        return len(free)

    def fifo(self, name: str) -> Path:
        path = self.directory / name
        os.mkfifo(path)
        return path


def measured(run: slots.Run, job_size: int, resident: int = 0):
    """Makes `run` publish a measured job size and resident memory."""
    run.job_size = job_size
    run.resident = resident
    run.admit(0)


class Admission(unittest.TestCase):
    def setUp(self):
        self.machine = Machine(self)

    def test_a_command_waits_until_memory_allows_one_more_job(self):
        running = self.machine.run()
        self.assertEqual(running.admit(1), 1)
        # The job of the running command measures 2 GiB but uses nothing yet, so
        # its 2 GiB are set aside, and a new command expects a job of 2 GiB too.
        measured(running, job_size=2 * GIB)
        waiting = self.machine.run()
        self.machine.memory(3 * GIB)
        self.assertEqual(waiting.admit(1), 0)
        self.machine.memory(4 * GIB)
        self.assertEqual(waiting.admit(1), 1)
        self.assertEqual(waiting.job_size, 2 * GIB)

    def test_a_job_that_has_grown_sets_nothing_aside(self):
        running = self.machine.run()
        running.admit(1)
        measured(running, job_size=2 * GIB, resident=2 * GIB)
        self.machine.memory(2 * GIB)
        self.assertEqual(self.machine.run().admit(1), 1)

    def test_nothing_starts_under_memory_pressure(self):
        run = self.machine.run()
        self.machine.stall(0.25)
        self.assertEqual(run.admit(1), 0)
        self.machine.stall(0)
        self.assertEqual(run.admit(1), 1)

    def test_every_job_needs_a_slot_of_its_own(self):
        holder = self.machine.run()
        self.assertEqual(holder.admit(10), 4)
        self.assertEqual(self.machine.run().admit(1), 0)

    def test_a_command_beyond_its_share_waits_while_another_wants_more(self):
        first, second = self.machine.run(), self.machine.run()
        self.assertEqual((first.admit(1), second.admit(1)), (1, 1))
        second.wants = True
        second.admit(0)
        # Two commands share four cores, so the first one stops at two.
        self.assertEqual(first.admit(3), 1)
        second.wants = False
        second.admit(0)
        self.assertEqual(first.admit(1), 1)


class Jobs(unittest.TestCase):
    def setUp(self):
        self.machine = Machine(self)

    def test_a_job_waits_for_memory_and_its_slot_returns_after_it(self):
        report, release = self.machine.fifo("report"), self.machine.fifo("release")
        run = self.machine.run()
        self.addCleanup(run.finish)
        self.assertEqual(run.admit(1), 1)
        run.start([sys.executable, "-c", JOB, str(report), str(release)])
        run.job_size = 4 * GIB
        self.machine.memory(1 * GIB)
        run.tick()
        self.assertEqual(run.jobserver.handed_out, 0)
        self.machine.memory(64 * GIB)
        run.tick()
        self.assertEqual(run.jobserver.handed_out, 1)
        with report.open() as reported:
            self.assertEqual(reported.readline(), "job\n")
        with release.open("w") as done:
            done.write("done\n")
        self.assertEqual(run.child.wait(), 0)
        run.tick()
        self.assertEqual((run.jobserver.handed_out, len(run.slots)), (0, 1))
        run.finish()
        self.assertEqual(self.machine.free_slots(), 4)


class Release(unittest.TestCase):
    def setUp(self):
        self.machine = Machine(self)

    def test_the_slots_of_a_killed_command_are_free(self):
        holder = subprocess.Popen([sys.executable, "-c", HOLDER, str(HERE), str(self.machine.directory)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.assertEqual(holder.stdout.readline(), "ready\n")
        self.assertEqual(self.machine.free_slots(), 1)
        holder.send_signal(signal.SIGKILL)
        holder.wait()
        holder.stdin.close()
        holder.stdout.close()
        self.assertEqual(self.machine.free_slots(), 4)

    def test_a_byte_lost_with_a_killed_job_returns_with_the_command(self):
        run = self.machine.run()
        self.assertEqual(run.admit(1), 1)
        run.start([sys.executable, "-c", KILLED_JOB])
        run.tick()
        self.assertEqual(run.child.wait(), -signal.SIGKILL)
        self.assertEqual(run.jobserver.take_back(), 0)
        self.assertEqual(self.machine.free_slots(), 2)
        run.finish()
        self.assertEqual(self.machine.free_slots(), 4)


class Host(unittest.TestCase):
    def setUp(self):
        self.machine = Machine(self)

    def test_the_available_column_is_read_by_its_name(self):
        self.machine.host.write_text(
            free_sample(100) + free_sample(300, header="total used free shared buffers cache available"))
        self.assertEqual(slots.host_available(self.machine.host, self.machine.host.stat().st_mtime),
                         300 * slots.MIB)

    def test_a_sample_still_being_written_is_left_out(self):
        self.machine.host.write_text(free_sample(100) + free_sample(300)[:60])
        self.assertEqual(slots.host_available(self.machine.host, self.machine.host.stat().st_mtime),
                         100 * slots.MIB)

    def test_a_missing_or_old_sample_means_the_host_is_unknown(self):
        with self.assertRaises(slots.HostUnknown):
            slots.host_available(self.machine.host, 0)
        self.machine.host_sample(8 * GIB)
        written = self.machine.host.stat().st_mtime
        self.assertEqual(slots.host_available(self.machine.host, written), 8 * GIB)
        with self.assertRaises(slots.HostUnknown):
            slots.host_available(self.machine.host, written + slots.HOST_SAMPLE_LIFETIME + 1)

    def test_the_host_limits_jobs_when_it_has_less_available(self):
        running = self.machine.run(watch_host=True)
        self.machine.host_sample(64 * GIB)
        running.admit(1)
        measured(running, job_size=2 * GIB)
        self.machine.host_sample(3 * GIB)
        self.assertEqual(self.machine.run(watch_host=True).admit(1), 0)
        self.machine.host_sample(4 * GIB)
        self.assertEqual(self.machine.run(watch_host=True).admit(1), 1)

    def test_an_unknown_host_starts_a_command_only_on_an_empty_machine(self):
        running = self.machine.run(watch_host=True)
        waiting = self.machine.run(watch_host=True)
        with redirect_stderr(io.StringIO()) as told:
            self.assertEqual(running.admit(1), 1)
            self.assertEqual(waiting.admit(1), 0)
            # The running command still gets more jobs on the memory of the machine.
            self.assertEqual(running.admit(1), 1)
            running.finish()
            self.assertEqual(waiting.admit(1), 1)
        self.assertIn("the host memory is unknown", told.getvalue())


if __name__ == "__main__":
    unittest.main()
