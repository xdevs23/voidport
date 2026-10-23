#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Classify the kernel diagnostics on the console of a guest."""

import argparse
from pathlib import Path
import re

DELAY = re.compile(
    r"task .* blocked for more than|watchdog:.*(?:soft lockup|hard lockup)|rcu:.*(?:stall|starv)",
    re.IGNORECASE,
)
FATAL = re.compile(
    r"BUG:|WARNING:|KASAN:|UBSAN:|possible circular locking|sleeping function called|"
    r"Oops:|Kernel panic|general protection fault|Unable to handle kernel|"
    r"Kernel memory leak detector disabled|enqueued on deprecated workqueue"
)
WATCHDOG_LABEL = re.compile(r"(watchdog:) BUG: ((?:soft lockup|hard LOCKUP))")


def fatal(text):
    # Remove only the watchdog's delay label. Other errors, even on this same
    # line, remain errors and the original text remains in the console evidence.
    return FATAL.search(WATCHDOG_LABEL.sub(r"\1 \2", text)) is not None


def self_test():
    for diagnostic in (
        "BUG: bad page state", "WARNING: CPU: 0", "KASAN: use-after-free",
        "UBSAN: array-index-out-of-bounds", "possible circular locking dependency",
        "sleeping function called from invalid context", "Oops: 0000",
        "Kernel panic - not syncing: Fatal exception", "general protection fault",
        "Unable to handle kernel paging request",
        "kmemleak: Kernel memory leak detector disabled",
        "workqueue: work func returned [voidport] enqueued on deprecated workqueue. "
        "Use system_{percpu|dfl}_wq instead.",
    ):
        assert fatal(diagnostic)
    for observation in (
        "INFO: task worker:1 blocked for more than 120 seconds.",
        "watchdog: BUG: soft lockup", "watchdog: Watchdog detected hard LOCKUP",
        "watchdog: BUG: hard LOCKUP",
        "rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:",
        "rcu: rcu_preempt kthread starved for 123 jiffies!",
    ):
        assert DELAY.search(observation)
        assert not fatal(observation)
        for separator in ("\n", " "):
            assert fatal(observation + separator + "KASAN: use-after-free")
    console = ("[    0.000000] Linux version 6.18.56\r\n"
               "[    0.512345] kasan: KernelAddressSanitizer initialized (generic)\r\n"
               "[   18.800000] reboot: Power down\r\n")
    assert not fatal(console)
    assert fatal(console + "[   19.000000] BUG: kernel NULL pointer dereference\r\n")
    print("guest-console: fatal errors and delay observations distinguished")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.log is None:
        parser.error("a console log is required")
    text = args.log.read_text(errors="replace")
    failed = fatal(text)
    for line in text.splitlines():
        if fatal(line) or DELAY.search(line):
            print(line)
    if failed:
        print("mount-harness: the guest reported a kernel diagnostic; retain the full console")
    elif DELAY.search(text):
        print("mount-harness: delay-only watchdog observations retained")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
