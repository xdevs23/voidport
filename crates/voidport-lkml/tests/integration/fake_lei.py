#!/usr/bin/env python3
"""Offline subprocess fixture. It implements only the client calls under test."""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys

ROOT = Path.cwd()
# A fixture process waits at most as long as the test process that started it
# runs. A failed test therefore leaves no fixture process behind.
TEST_PROCESS = os.pidfd_open(int(os.environ["VOIDPORT_LKML_TEST_PROCESS"]))


def record(name, value):
    # The rename publishes the record complete. A test that sees the file may
    # read it at once, which a write in place does not allow: the file exists
    # empty between its creation and the write.
    staged = ROOT / f".{name}.tmp"
    staged.write_text(json.dumps(value))
    staged.rename(ROOT / name)


def hold(*descriptors):
    """Waits until one of `descriptors` is readable, or a signal ends the
    process. It exits when the test process ends first."""
    poller = select.poll()
    for descriptor in (TEST_PROCESS, *descriptors):
        poller.register(descriptor, select.POLLIN)
    if TEST_PROCESS in [descriptor for descriptor, _ in poller.poll()]:
        sys.exit("the test process ended")


def daemon(ready):
    # Tests replace this assignment to make the daemon ignore SIGTERM.
    ignore_terminate = False
    if ignore_terminate:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    record("daemon-ready.json", {"pid": os.getpid()})
    os.close(ready)
    hold()


def mail(sender, identifier, reply="", body="body"):
    fields = [f"From: {sender}", f"Message-ID: <{identifier}>", "Subject: synthetic"]
    if reply:
        fields.append(f"In-Reply-To: <{reply}>")
    return ("\r\n".join(fields) + "\r\n\r\n" + body + "\r\n").encode()


args = sys.argv[1:]
if args[:1] == ["--fixture-daemon"]:
    daemon(int(args[1]))
elif args == ["daemon-pid"]:
    if not (ROOT / "daemon.json").exists():
        # The daemon closes its end of this pipe once it is ready, and the
        # read below returns when the daemon is ready or has ended.
        ready, ready_end = os.pipe()
        child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--fixture-daemon",
                                  str(ready_end)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True,
                                 pass_fds=[ready_end])
        os.close(ready_end)
        record("daemon.json", {"pid": child.pid})
        os.read(ready, 1)
        if not (ROOT / "daemon-ready.json").exists():
            sys.exit(f"fixture daemon ended before it wrote {ROOT / 'daemon-ready.json'}")
        # Tests replace this assignment to hold setup before its PID reply.
        hold_setup = False
        if hold_setup:
            hold()
    else:
        # Tests replace this assignment to hold the identification that runs
        # in cleanup.
        hold_identify = False
        if hold_identify:
            # The test releases the identification through this FIFO. Opening
            # it without waiting for a writer lets the test open it once it
            # sees the record below.
            os.mkfifo(ROOT / "identify-release")
            release = os.open(ROOT / "identify-release", os.O_RDONLY | os.O_NONBLOCK)
            record("identify-ready.json", {"pid": os.getpid()})
            hold(release)
    print(json.loads((ROOT / "daemon.json").read_text())["pid"], flush=True)
elif args == ["daemon-kill", "--signal", "KILL"]:
    daemon_process = os.pidfd_open(json.loads((ROOT / "daemon.json").read_text())["pid"])
    signal.pidfd_send_signal(daemon_process, signal.SIGKILL)
    hold(daemon_process)
elif args and args[0] == "q":
    receipt = {"arguments": args, "pid": os.getpid(), "cwd": str(ROOT),
               "environment": dict(os.environ), "descriptors": {}}
    for fd in Path("/proc/self/fd").iterdir():
        try:
            receipt["descriptors"][fd.name] = os.readlink(fd)
        except FileNotFoundError:
            pass
    record("query.json", receipt)
    source = args[args.index("--only") + 1]
    expected = ["q", "--threads", "--no-local", "--remote", "--no-save", "--dedupe=none",
                "--only", source, "--output", "maildir:maildir", "--"]
    assert args[:-1] == expected, args
    case = args[-1]
    if case == "refused":
        print("synthetic refusal; wait for operator guidance", file=sys.stderr)
        sys.exit(23)
    for directory in ["new", "cur", "tmp"]:
        (ROOT / "maildir" / directory).mkdir(parents=True)
    parent = mail("other@example.invalid", "parent@example.invalid")
    child = mail("torvalds@osdl.org", "child@example.invalid", "parent@example.invalid",
                 "From literal\r\n>From literal\r\n>>From literal")
    deliveries = []
    if case in ["pair", "overlap", "variants", "failed-delivery", "aliased-setup-log", "wait",
                "later-parent"]:
        deliveries.append(("new/anything", parent))
    if case in ["pair", "overlap", "variants", "failed-delivery", "aliased-setup-log", "wait",
                "child-only", "file-new"]:
        deliveries.append(("cur/unusual-name", child))
    if case in ["hardlinks", "large-tmp", "symlink", "fifo", "tmp-symlink", "tmp-fifo"]:
        deliveries.append(("new/anything", parent))
    if case in ["filename-signal", "wait-filename-signal"]:
        deliveries.extend([("new/anything", parent), ("cur/unusual-name", child)])
        os.mkfifo(ROOT / "maildir/new/signal")
    if case == "fatal-store":
        os.mkfifo(ROOT / "maildir/new/a-invalid")
        deliveries.extend([("new/b-store", parent), ("new/c-later", child),
                           ("cur/later", child)])
    if case == "sensitive-id":
        deliveries.append(("new/sensitive", mail("other@example.invalid", "a/b?c#d%25@example.invalid")))
    if case == "variants":
        deliveries.append(("new/variant", parent + b"variant\r\n"))
    if case == "bare-html":
        deliveries.append(("new/html", b"<html>denied</html>"))
    if case == "malformed":
        deliveries.append(("cur/invalid", b"\xff\0garbage"))
    if case == "html-mail":
        deliveries.append(("new/html", b"From: torvalds@osdl.org\r\nContent-Type: text/html\r\n\r\n<p>body</p>"))
    for name, data in deliveries:
        (ROOT / "maildir" / name).write_bytes(data)
    (ROOT / "maildir/tmp/partial").write_bytes(b"not delivered")
    if case == "hardlinks":
        os.link(ROOT / "maildir/new/anything", ROOT / "maildir/cur/alias")
        os.link(ROOT / "maildir/tmp/partial", ROOT / "tmp-alias")
    if case == "large-tmp":
        with (ROOT / "maildir/tmp/partial").open("wb") as stream:
            stream.truncate(16 * 1024 * 1024 * 1024)
    if case == "tmp-symlink":
        (ROOT / "maildir/tmp/link").symlink_to(ROOT / "query.json")
    if case == "tmp-fifo":
        os.mkfifo(ROOT / "maildir/tmp/pipe")
    if case == "missing-cur":
        (ROOT / "maildir/cur").rmdir()
    if case == "file-new":
        (ROOT / "maildir/new").rmdir()
        (ROOT / "maildir/new").write_bytes(parent)
    if case == "symlink":
        (ROOT / "maildir/new/link").symlink_to(ROOT / "query.json")
    if case == "fifo":
        os.mkfifo(ROOT / "maildir/new/pipe")
    record("delivery-ready.json", {"files": [name for name, _ in deliveries]})
    if case in ["wait", "wait-filename-signal"]:
        hold()
    if case == "aliased-setup-log":
        os.link(ROOT / "setup.stderr", ROOT / "log-alias")
    if case in ["failed-delivery", "aliased-setup-log"]:
        print("synthetic failure after delivery", file=sys.stderr)
        sys.exit(24)
    print("ordinary progress", file=sys.stderr)
else:
    raise AssertionError(args)
