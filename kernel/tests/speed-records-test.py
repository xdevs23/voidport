#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "speed_records", Path(__file__).with_name("speed-records.py"))
records = importlib.util.module_from_spec(spec)
spec.loader.exec_module(records)


def run(client, mib):
    summary = {"mib_per_second": {"mean": mib}, "ops_per_second": {"mean": 2 * mib}}
    return records.Run.read({"label": client.value, "scenario": "seq-write",
                             "summary": summary})


def timed(client, mib):
    return records.Record(records.Pass.TIMED, run(client, mib))


def counted(client, requests):
    totals = records.Totals(requests=requests, bytes_received=10 * requests,
                            bytes_sent=requests)
    return records.Record(records.Pass.COUNTED, run(client, 0.5), totals)


class Records(unittest.TestCase):
    def test_a_row_joins_the_timed_and_the_counted_pass_of_one_client(self):
        kernel, userspace = records.Client.KERNEL, records.Client.USERSPACE
        rows = list(records.rows([
            counted(kernel, 7), timed(userspace, 3.0), timed(kernel, 4.0),
            counted(userspace, 40),
        ]))
        self.assertEqual(rows, [
            ["seq-write", "userspace", "3.0", "6.0", 40, 400, 40,
             userspace.copies_per_written_byte],
            ["seq-write", "kernel", "4.0", "8.0", 7, 70, 7, kernel.copies_per_written_byte],
        ])

    def test_a_record_reads_back_from_the_json_sent_for_it(self):
        for record in (timed(records.Client.KERNEL, 1.0), counted(records.Client.USERSPACE, 3)):
            sent = json.loads(json.dumps(record.as_json()))
            self.assertEqual(records.Record.of_json(sent), record)

    def test_a_pass_recorded_twice_is_refused(self):
        twice = [timed(records.Client.KERNEL, 1.0), timed(records.Client.KERNEL, 2.0),
                 counted(records.Client.KERNEL, 1)]
        with self.assertRaises(ValueError):
            list(records.rows(twice))

    def test_a_timed_pass_without_its_counted_pass_is_refused(self):
        with self.assertRaises(ValueError):
            list(records.rows([timed(records.Client.KERNEL, 1.0)]))

    def test_totals_belong_to_the_counted_pass_only(self):
        totals = records.Totals(requests=1, bytes_received=1, bytes_sent=1)
        with self.assertRaises(ValueError):
            records.Record(records.Pass.TIMED, run(records.Client.KERNEL, 1.0), totals)
        with self.assertRaises(ValueError):
            records.Record(records.Pass.COUNTED, run(records.Client.KERNEL, 1.0))


if __name__ == "__main__":
    unittest.main()
