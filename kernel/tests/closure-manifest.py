#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import hashlib
import json
from pathlib import Path
import stat
import sys


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def collect(paths, toplevel, witness, excluded):
    if len(paths) != len(set(paths)) or toplevel not in paths or witness not in paths:
        raise ValueError("closure must contain unique paths, its toplevel and witness")
    if excluded in paths:
        raise ValueError("excluded path belongs to the system closure")
    entries = []
    for path in sorted(paths):
        location = Path(path)
        if location.parent != Path("/nix/store"):
            raise ValueError(f"not a store root: {path}")
        mode = location.lstat().st_mode
        entry = {"path": path, "mode": stat.S_IFMT(mode)}
        if stat.S_ISREG(mode):
            entry["sha256"] = digest(location)
        elif stat.S_ISLNK(mode):
            entry["link"] = str(location.readlink())
        elif not stat.S_ISDIR(mode):
            raise ValueError(f"unsupported store root: {path}")
        entries.append(entry)
    return {"toplevel": toplevel, "witness": witness, "excluded": excluded,
            "target": "multi-user.target", "entries": entries}


if __name__ == "__main__":
    source, toplevel, witness, excluded, output = sys.argv[1:]
    manifest = collect(Path(source).read_text().splitlines(), toplevel, witness, excluded)
    Path(output).write_text(json.dumps(manifest, indent=2) + "\n")
