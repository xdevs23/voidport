#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Acknowledged test requests on the second serial port of the guest."""

import argparse
import enum
import json
import termios
import tty
import uuid

DEVICE = "/dev/ttyS1"


class Operation(enum.Enum):
    MUTATE = "mutate"
    KILL_SERVER = "kill-server"
    RESTART_SERVER = "restart-server"
    LOCK_HOLD = "lock-hold"
    LOCK_RELEASE = "lock-release"
    LOCK_FREE = "lock-free"
    VERDICT = "verdict"
    RECORD = "record"
    SPEED_FAILED = "speed-failed"
    BOOT_COMPLETE = "boot-complete"
    CLOSURE_FAILED = "closure-failed"
    COMPLETE = "complete"


def encode(value):
    return (json.dumps(value, ensure_ascii=True) + "\n").encode("ascii")


def decode(line):
    if not line:
        raise EOFError("test event channel closed")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("test event must be an object")
    return value


def request(stream, operation, evidence=None):
    identity = uuid.uuid4().hex
    message = {"id": identity, "operation": operation.value}
    if evidence is not None:
        message["evidence"] = evidence
    remaining = memoryview(encode(message))
    while remaining:
        written = stream.write(remaining)
        if not written:
            raise EOFError("test event channel stopped accepting writes")
        remaining = remaining[written:]
    stream.flush()
    reply = decode(stream.readline())
    if reply.get("id") != identity or reply.get("ok") is not True:
        raise RuntimeError(f"test request was not acknowledged: {reply!r}")


def send(device, operation, evidence=None):
    with open(device, "r+b", buffering=0) as channel:
        tty.setraw(channel.fileno(), termios.TCSANOW)
        request(channel, operation, evidence)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", type=Operation)
    parser.add_argument("--device", default=DEVICE)
    args = parser.parse_args()
    send(args.device, args.operation)


if __name__ == "__main__":
    main()
