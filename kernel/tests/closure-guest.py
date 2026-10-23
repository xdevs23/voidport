#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import termios
import tty


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def unit_state(unit):
    return subprocess.run(["systemctl", "is-active", unit],
                          capture_output=True, text=True).stdout.strip()


def verify(firewall, reference, witness):
    manifest_bytes = Path("/run/closure-manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    if Path("/run/closure-store-before").read_text() != "empty\n":
        raise AssertionError("bootstrap did not verify the empty store")
    if manifest["witness"] != witness:
        raise AssertionError("wrong read-only witness")
    mounts = json.loads(command("findmnt", "--json", "--mountpoint", "/nix/store",
                                "--output", "TARGET,SOURCE,FSTYPE,OPTIONS"))["filesystems"]
    if len(mounts) != 1 or mounts[0]["fstype"] != "voidport":
        raise AssertionError("store is not the native voidport filesystem")
    if mounts[0]["source"] != "closure" or "ro" not in mounts[0]["options"].split(","):
        raise AssertionError("wrong namespace or writable store")
    if command("stat", "-f", "-c", "%t", "/nix/store") != "766f6964":
        raise AssertionError("wrong native filesystem magic")
    entries = manifest["entries"]
    expected = {Path(entry["path"]).name for entry in entries}
    if set(os.listdir("/nix/store")) != expected:
        raise AssertionError("guest store differs from the complete manifest")
    for entry in entries:
        path = Path(entry["path"])
        if stat.S_IFMT(path.lstat().st_mode) != entry["mode"]:
            raise AssertionError(f"store path type differs: {path}")
        if "link" in entry and str(path.readlink()) != entry["link"]:
            raise AssertionError(f"store symlink differs: {path}")
        if "sha256" in entry:
            with path.open("rb") as source:
                if hashlib.file_digest(source, "sha256").hexdigest() != entry["sha256"]:
                    raise AssertionError(f"store bytes differ: {path}")
    try:
        os.lstat(manifest["excluded"])
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("unexported store path is accessible")
    refused = []
    for path, flags in ((witness, os.O_WRONLY | os.O_TRUNC),
                        ("/nix/store/voidport-must-not-exist", os.O_WRONLY | os.O_CREAT)):
        try:
            fd = os.open(path, flags, 0o600)
        except OSError as error:
            if error.errno != errno.EROFS:
                raise
            refused.append({"path": path, "errno": error.errno})
        else:
            os.close(fd)
            raise AssertionError(f"write was not refused: {path}")
    if Path("/run/current-system").resolve() != Path(manifest["toplevel"]):
        raise AssertionError("stage 2 did not activate the collected system")
    if Path("/run/booted-system").resolve() != Path(manifest["toplevel"]):
        raise AssertionError("wrong booted system")
    if unit_state(manifest["target"]) != "active":
        raise AssertionError("configured system target is not active")
    return {"manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "paths_checked": len(entries), "store_before": "empty",
            "mounts": mounts, "magic": "766f6964", "writes_refused": refused,
            "excluded": manifest["excluded"], "target": manifest["target"],
            "target_state": "active", "system": manifest["toplevel"],
            "firewall": firewall.observe(unit_state, subprocess.run, reference)}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    events = load("events", sys.argv[1])
    firewall = load("firewall", sys.argv[2])
    with open("/dev/ttyS1", "r+b", buffering=0) as channel:
        tty.setraw(channel.fileno(), termios.TCSANOW)
        try:
            evidence = verify(firewall, sys.argv[3], sys.argv[4])
        except Exception as error:
            events.request(channel, events.Operation.CLOSURE_FAILED, {"reason": str(error)})
            raise
        events.request(channel, events.Operation.BOOT_COMPLETE, evidence)
        # Acknowledgement precedes the service's normal systemctl poweroff.
        events.request(channel, events.Operation.COMPLETE, {"shutdown": "systemctl poweroff"})


if __name__ == "__main__":
    main()
