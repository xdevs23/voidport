#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import asyncio
import importlib.util
import json
import os
from pathlib import Path
import pty
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

spec = importlib.util.spec_from_file_location("run_guest", Path(__file__).with_name("run-guest.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
events = runner.events
verdicts = runner.mount_verdicts
# The interpreter used by the guests to run guest-events.py. It lacks modules of
# the full build that runs this test.
guest_python = os.environ["VOIDPORT_GUEST_PYTHON"]


class Protocol(unittest.TestCase):
    def serial_request(self, program, *arguments):
        master, slave = pty.openpty()
        child = subprocess.Popen([
            guest_python, str(Path(__file__).with_name(program)),
            *arguments, "--device", f"/proc/self/fd/{slave}",
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(slave,))
        # Only the child retains the terminal's other end, so its exit ends a
        # blocked read even if it fails before publishing the request.
        os.close(slave)
        try:
            with os.fdopen(master, "r+b", buffering=0) as channel:
                message = events.decode(channel.readline())
                channel.write(events.encode({"id": message["id"], "ok": True}))
                output, error = child.communicate()
                self.assertEqual((child.returncode, output, error), (0, b"", b""))
                return message
        finally:
            if child.poll() is None:
                child.terminate()
            child.communicate()

    def test_serial_client_waits_for_the_matching_reply(self):
        message = self.serial_request("guest-events.py", "mutate")
        self.assertEqual(message["operation"], events.Operation.MUTATE.value)

    def test_verdict_client_sends_the_verdict_as_its_evidence(self):
        message = self.serial_request("mount-verdicts.py", "close-frame", "FAILED")
        self.assertEqual(
            (message["operation"], verdicts.Verdict.of_json(message["evidence"])),
            (events.Operation.VERDICT.value,
             verdicts.Verdict("close-frame", verdicts.Outcome.FAILED)))

    def test_round_trip_and_fragmentation(self):
        guest, host = socket.socketpair()
        errors = []
        def reply():
            try:
                with host, host.makefile("rwb", buffering=0) as channel:
                    message = events.decode(channel.readline())
                    self.assertEqual(message["operation"], events.Operation.MUTATE.value)
                    # Byte-sized writes exercise framing without depending on
                    # how a serial implementation groups reads.
                    for byte in events.encode({"id": message["id"], "ok": True}):
                        channel.write(bytes([byte]))
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=reply)
        worker.start()
        with guest, guest.makefile("rwb", buffering=0) as channel:
            events.request(channel, events.Operation.MUTATE)
        worker.join()
        self.assertEqual(errors, [])

    def test_rejects_wrong_identity_and_failed_acknowledgement(self):
        for reply in ({"id": "wrong", "ok": True}, {"ok": False}):
            class Channel:
                def write(self, data):
                    self.message = events.decode(bytes(data))
                    return len(data)
                def flush(self):
                    pass
                def readline(self):
                    return events.encode({"id": self.message["id"], **reply})
            with self.assertRaises(RuntimeError):
                events.request(Channel(), events.Operation.MUTATE)

    def test_closed_or_malformed_channel_is_not_an_acknowledgement(self):
        for line in (b"", b"[]\n", b"not-json\n"):
            with self.assertRaises((EOFError, ValueError)):
                events.decode(line)

    def test_mutation_changes_both_content_and_mtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary) / "tree"
            runner.lay_tree(tree, b"a note", b"a pattern")
            before = (tree / "mtime.txt").stat().st_mtime_ns
            runner.mutate(tree)
            self.assertGreater((tree / "mtime.txt").stat().st_mtime_ns, before)
            self.assertEqual((tree / "mtime.txt").read_bytes(), b"after!")
            self.assertTrue((tree / "swap").is_dir())
            self.assertEqual((tree / "appeared").read_bytes(), b"now here")


class GuestMemory(unittest.TestCase):
    def test_memory_rounds_two_copies_of_the_archive_up_to_whole_mib(self):
        size = 3 * runner.MIB + 1
        self.assertEqual(runner.guest_memory_mib(size, generic_kasan=False),
                         runner.BASE_GUEST_MIB + 7)

    def test_the_generic_address_sanitizer_adds_its_shadow_share(self):
        size = 7 * runner.MIB
        self.assertEqual(runner.guest_memory_mib(size, generic_kasan=True),
                         runner.BASE_GUEST_MIB + 16)
        self.assertEqual(runner.guest_memory_mib(size + 1, generic_kasan=True),
                         runner.BASE_GUEST_MIB + 17)


class Processes(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.children = []
        self.async_errors = []
        asyncio.get_running_loop().set_exception_handler(
            lambda loop, context: self.async_errors.append(context)
        )

    async def asyncTearDown(self):
        for child in self.children:
            await child.stop()
        self.temporary.cleanup()
        self.assertEqual(self.async_errors, [])

    async def child(self, program, name="child"):
        child = await runner.Child.start(
            [sys.executable, "-c", program], self.directory, name,
            stdin=asyncio.subprocess.PIPE,
        )
        self.children.append(child)
        return child

    async def test_readiness_and_actual_exit_are_retained(self):
        child = await self.child("import sys; print('ready', flush=True); sys.stdin.read(1); sys.exit(7)")
        await runner.observed(child.contains("ready"), child)
        child.process.stdin.write(b"x")
        await child.process.stdin.drain()
        self.assertEqual(await child.finished(), 7)
        await child.reader
        self.assertEqual(json.loads(child.receipt.read_bytes()), {"exit": 7})
        self.assertEqual(child.log.read_text(), "ready\n")

    async def test_exit_ends_readiness_and_channel_waits(self):
        child = await self.child("import sys; sys.exit(9)")
        with self.assertRaises(RuntimeError):
            await runner.observed(child.contains("missing"), child)
        with self.assertRaises(RuntimeError):
            await runner.observed(asyncio.Future(), child)
        self.assertEqual(await child.exit, 9)

    async def test_fatal_kernel_output_ends_a_wait_before_process_exit(self):
        child = await self.child(
            "import sys; print('KASAN: use-after-free', flush=True); sys.stdin.read(1)", "guest"
        )
        with self.assertRaisesRegex(RuntimeError, "fatal kernel diagnostic"):
            await runner.observed(asyncio.Future(), child)
        self.assertIsNone(child.process.returncode)

    async def test_delay_diagnostics_do_not_end_a_wait(self):
        child = await self.child(
            "import sys; print('watchdog: BUG: soft lockup', flush=True); "
            "print('ready', flush=True); sys.stdin.read(1)", "guest"
        )
        await runner.observed(child.contains("ready"), child)
        self.assertFalse(child.failure.done())
        child.process.stdin.write(b"x")
        await child.process.stdin.drain()
        self.assertEqual(await child.finished(), 0)

    def control_client(self, response):
        path = self.directory / "ctl"
        path.write_text(f"#!{sys.executable}\nprint({json.dumps(response)!r})\n")
        path.chmod(0o755)
        return str(path)

    async def test_the_bound_port_comes_from_the_one_tcp_listener(self):
        ctl = self.control_client({"status": "ok", "result": {
            "reply": "server-info",
            "listeners": [{"transport": "tcp", "endpoint": "127.0.0.1:4321"}],
        }})
        self.assertEqual(await runner.bound_port(ctl, self.directory), 4321)

    async def test_a_vhost_user_listener_beside_the_tcp_listener_has_no_port(self):
        ctl = self.control_client({"status": "ok", "result": {
            "reply": "server-info",
            "listeners": [{"transport": "vhost-user", "endpoint": "vhost-user.sock"},
                          {"transport": "tcp", "endpoint": "127.0.0.1:4321"}],
        }})
        self.assertEqual(await runner.bound_port(ctl, self.directory), 4321)

    async def test_an_unexpected_listener_report_fails(self):
        tcp = {"transport": "tcp", "endpoint": "127.0.0.1:4321"}
        for response in (
            {"status": "error", "error": {"code": "internal", "message": "no"}},
            {"status": "ok", "result": {"reply": "server-info", "listeners": []}},
            {"status": "ok", "result": {"reply": "server-info", "listeners": [tcp, tcp]}},
            {"status": "ok", "result": {"reply": "server-info", "listeners": [
                {"transport": "unix", "endpoint": "/run/voidport.sock"}]}},
            {"status": "ok", "result": {"reply": "server-info", "listeners": [
                {"transport": "vhost-user", "endpoint": "vhost-user.sock"}]}},
            {"status": "ok", "result": {"reply": "server-info", "listeners": [
                {"transport": "tcp", "endpoint": "127.0.0.1:0"}]}},
        ):
            with self.subTest(response=response), self.assertRaises(ValueError):
                await runner.bound_port(self.control_client(response), self.directory)

    async def test_a_lock_of_another_process_makes_the_file_not_free(self):
        path = self.directory / "lock"
        path.write_bytes(b"")
        child = await self.child(
            "import fcntl, sys\n"
            f"holder = open({str(path)!r}, 'r+b')\n"
            "fcntl.lockf(holder, fcntl.LOCK_SH | fcntl.LOCK_NB)\n"
            "print('ready', flush=True)\n"
            "sys.stdin.read(1)\n"
        )
        await runner.observed(child.contains("ready"), child)
        self.assertFalse(runner.lock_free(path))
        child.process.stdin.write(b"x")
        await child.process.stdin.drain()
        self.assertEqual(await child.finished(), 0)
        self.assertTrue(runner.lock_free(path))

    async def test_cancelling_a_wait_does_not_lose_the_child_exit(self):
        child = await self.child("import sys; print('ready', flush=True); sys.stdin.read(1)")
        await runner.observed(child.contains("ready"), child)
        started = asyncio.Event()
        async def pending():
            started.set()
            await asyncio.Future()
        observer = asyncio.create_task(runner.observed(pending(), child))
        await started.wait()
        observer.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await observer
        await child.stop()
        self.assertEqual(json.loads(child.receipt.read_bytes()), {"exit": -15})


if __name__ == "__main__":
    unittest.main()
