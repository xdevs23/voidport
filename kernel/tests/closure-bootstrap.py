#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import lzma
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

# The modules the early init loads, in this order, with the parameters each
# loads with. The virtio console contains the output of the programs, the
# driver chain needed by the network card is used by the store connection, and
# connection tracking loads with its hooks on, so that it tracks that
# connection from its first packet.
BOOTSTRAP = (
    ("virtio_pci", ()),
    ("virtio_console", ()),
    ("virtio_net", ()),
    ("nf_conntrack", ("enable_hooks=1",)),
)


def assemble(tree, release, root, modules):
    root = Path(root)
    destination = root / "modules"
    destination.mkdir()
    seen = set()
    commands = []
    for name, parameters in modules:
        output = subprocess.check_output(
            ["modprobe", "-d", tree, "-S", release, "--show-depends",
             "--ignore-install", name], text=True)
        lines = output.splitlines()
        # modprobe names the dependencies first and the module itself last.
        for index, line in enumerate(lines):
            own = parameters if index == len(lines) - 1 else ()
            operation, *arguments = shlex.split(line)
            if operation == "builtin":
                continue
            if operation != "insmod" or len(arguments) != 1:
                raise ValueError(f"unexpected module load command: {line}")
            source = Path(arguments[0])
            if source in seen:
                continue
            seen.add(source)
            target = destination / f"{len(seen)}.ko"
            if source.suffix == ".xz":
                with lzma.open(source, "rb") as input_file, target.open("wb") as output_file:
                    shutil.copyfileobj(input_file, output_file)
            else:
                shutil.copyfile(source, target)
            commands.append(shlex.join(["insmod", "/modules/" + target.name, *own]))
    (root / "load-modules").write_text("\n".join(commands) + "\n")


if __name__ == "__main__":
    assemble(*sys.argv[1:], BOOTSTRAP)
