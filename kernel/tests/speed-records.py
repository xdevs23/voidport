#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import dataclasses
import enum
import json


class Pass(enum.Enum):
    TIMED = "timed"
    COUNTED = "counted"


class Client(enum.Enum):
    KERNEL = "kernel"
    USERSPACE = "userspace"

    @property
    def copies_per_written_byte(self):
        """How often the write path of the client copies a byte written with
        write(2), as stated by the data path and not measured.

        The kernel module copies the byte into the page cache and from there
        into the socket. Through the userspace client, FUSE copies the byte
        into the page cache, the client reads it from /dev/fuse, copies it into
        the data of its request, and sends it into the socket.
        """
        return {Client.KERNEL: 2, Client.USERSPACE: 4}[self]


@dataclasses.dataclass(frozen=True)
class Totals:
    requests: int
    bytes_received: int
    bytes_sent: int


@dataclasses.dataclass(frozen=True)
class Run:
    client: Client
    scenario: str
    mib_per_second: float
    ops_per_second: float
    document: dict

    @classmethod
    def read(cls, document):
        summary = document["summary"]
        return cls(Client(document["label"]), document["scenario"],
                   summary["mib_per_second"]["mean"], summary["ops_per_second"]["mean"],
                   document)


@dataclasses.dataclass(frozen=True)
class Record:
    pass_kind: Pass
    run: Run
    totals: Totals | None = None

    def __post_init__(self):
        if (self.totals is None) != (self.pass_kind is Pass.TIMED):
            raise ValueError(f"a {self.pass_kind.value} pass with totals {self.totals}")

    def as_json(self):
        return {"pass": self.pass_kind.value, "run": self.run.document,
                "totals": None if self.totals is None else dataclasses.asdict(self.totals)}

    @classmethod
    def of_json(cls, value):
        totals = value["totals"]
        return cls(Pass(value["pass"]), Run.read(value["run"]),
                   None if totals is None else Totals(**totals))


COLUMNS = ["scenario", "client", "MiB/s, mean", "operations/s, mean", "requests",
           "bytes to the server", "bytes from the server",
           "copies per written byte, stated by the write path"]


def rows(records):
    passes = {}
    for record in records:
        key = (record.run.scenario, record.run.client, record.pass_kind)
        if key in passes:
            raise ValueError(f"two records of the {record.pass_kind.value} pass of "
                             f"{record.run.client.value} through {record.run.scenario}")
        passes[key] = record
    for (scenario, client, kind), timed in passes.items():
        if kind is not Pass.TIMED:
            continue
        counted = passes.get((scenario, client, Pass.COUNTED))
        if counted is None:
            raise ValueError(f"no counted pass of {client.value} through {scenario}")
        yield [scenario, client.value,
               f"{timed.run.mib_per_second:.1f}", f"{timed.run.ops_per_second:.1f}",
               counted.totals.requests, counted.totals.bytes_received,
               counted.totals.bytes_sent, client.copies_per_written_byte]


def table(records):
    lines = [COLUMNS, ["---"] * len(COLUMNS), *rows(records)]
    return "".join("| " + " | ".join(map(str, line)) + " |\n" for line in lines)


class Comparison:
    def __init__(self, directory):
        self.directory = directory
        self.records = []

    def prepare(self, tree):
        tree.mkdir()

    def record(self, evidence):
        record = Record.of_json(evidence)
        with (self.directory / "records.jsonl").open("a") as output:
            output.write(json.dumps(record.as_json()) + "\n")
        self.records.append(record)

    def complete(self):
        (self.directory / "table.md").write_text(table(self.records))
