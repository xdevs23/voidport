#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "mount_verdicts", Path(__file__).with_name("mount-verdicts.py"))
verdicts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verdicts)
OK, FAILED = verdicts.Outcome.OK, verdicts.Outcome.FAILED


def collected(*sent):
    collection = verdicts.Verdicts()
    for case, outcome in sent:
        collection.record(verdicts.Verdict(case, outcome).as_json())
    return collection


class Verdicts(unittest.TestCase):
    def test_one_passing_verdict_for_every_expected_case_passes(self):
        collected(("one", OK), ("two", OK)).complete(["one", "two"])

    def test_a_failed_missing_or_unexpected_verdict_fails(self):
        for sent, expected in (
            ([("one", OK), ("two", FAILED)], ["one", "two"]),
            ([("one", OK)], ["one", "two"]),
            ([("one", OK), ("other", OK)], ["one"]),
            ([("other", FAILED)], []),
        ):
            with self.subTest(sent=sent), self.assertRaises(AssertionError):
                collected(*sent).complete(expected)

    def test_a_second_verdict_for_a_case_fails(self):
        with self.assertRaises(ValueError):
            collected(("one", OK), ("one", FAILED))

    def test_a_malformed_verdict_fails(self):
        for evidence in (None, {}, {"case": "one"}, {"case": "one", "outcome": "passed"},
                         {"case": 1, "outcome": "ok"}):
            with self.subTest(evidence=evidence), self.assertRaises(ValueError):
                verdicts.Verdicts().record(evidence)


if __name__ == "__main__":
    unittest.main()
