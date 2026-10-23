#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import dataclasses
import enum
import importlib.util
from pathlib import Path


def helper(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


events = helper("guest-events")


class Outcome(enum.Enum):
    OK = "ok"
    FAILED = "FAILED"


@dataclasses.dataclass(frozen=True)
class Verdict:
    case: str
    outcome: Outcome

    def as_json(self):
        return {"case": self.case, "outcome": self.outcome.value}

    @classmethod
    def of_json(cls, value):
        match value:
            case {"case": str(case), "outcome": str(outcome)}:
                return cls(case, Outcome(outcome))
        raise ValueError(f"a verdict needs a case and an outcome: {value!r}")


class Verdicts:
    def __init__(self):
        self.outcomes = {}

    def record(self, evidence):
        verdict = Verdict.of_json(evidence)
        if verdict.case in self.outcomes:
            raise ValueError(f"the guest sent a second verdict for {verdict.case}")
        self.outcomes[verdict.case] = verdict.outcome

    def complete(self, expected):
        missing = sorted(set(expected) - self.outcomes.keys())
        unexpected = sorted(self.outcomes.keys() - set(expected))
        failed = sorted(case for case, outcome in self.outcomes.items()
                        if outcome is not Outcome.OK)
        if missing or unexpected or failed:
            raise AssertionError(f"guest verdicts: failed {failed}, missing {missing}, "
                                 f"unexpected {unexpected}")


def main():
    parser = argparse.ArgumentParser(description="Send the verdict of one case to the host.")
    parser.add_argument("case")
    parser.add_argument("outcome", type=Outcome)
    parser.add_argument("--device", default=events.DEVICE)
    args = parser.parse_args()
    events.send(args.device, events.Operation.VERDICT, Verdict(args.case, args.outcome).as_json())


if __name__ == "__main__":
    main()
