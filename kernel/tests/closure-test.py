#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import copy
import errno
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def helper(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


host = helper("closure-host")
firewall = helper("closure-firewall")
events = helper("guest-events")
bootstrap = helper("closure-bootstrap")


def rules(tool, table):
    chain = f"{tool}-{table}"
    return ["-P INPUT ACCEPT", f"-N {chain}", f"-A INPUT -j {chain}",
            f"-A {chain} -i lo -j ACCEPT", f"-A {chain} -j DROP"]

EVERY_TABLE = [(tool, table) for tool in firewall.TOOLS for table in firewall.TABLES]


def tables(listing):
    return [{"tool": tool, "table": table, "listing": listing(tool, table)}
            for tool, table in EVERY_TABLE]


def started_firewall():
    return {"service": "active", "tables": tables(rules), "reference": tables(rules)}


def manifest():
    return {"toplevel": "/nix/store/aaa-system", "witness": "/nix/store/bbb-witness",
            "excluded": "/nix/store/ccc-excluded", "target": "multi-user.target",
            "entries": [{"path": "/nix/store/aaa-system", "mode": 16384},
                        {"path": "/nix/store/bbb-witness", "mode": 32768}]}


class Mapping(unittest.TestCase):
    def test_every_path_has_its_original_name_and_readonly_backing(self):
        source = manifest()
        self.assertEqual(host.rules_for(source), [
            {"path": "/aaa-system", "target": "/nix/store/aaa-system", "mode": "ro"},
            {"path": "/bbb-witness", "target": "/nix/store/bbb-witness", "mode": "ro"},
        ])
        host.verify_mapping(source, list(reversed(host.rules_for(source))))

    def test_equal_counts_cannot_hide_wrong_mapping(self):
        source = manifest()
        for key, value in (("path", "/wrong"), ("target", source["excluded"]), ("mode", "rw")):
            rules = host.rules_for(source)
            rules[0][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                host.verify_mapping(source, rules)
        rules = host.rules_for(source)
        rules[0], rules[1] = rules[1], rules[1]
        with self.assertRaises(AssertionError):
            host.verify_mapping(source, rules)

    def test_truncation_duplicates_and_wildcards_are_rejected(self):
        source = manifest()
        with self.assertRaises(AssertionError):
            host.verify_mapping(source, host.rules_for(source)[:1])
        for entry in (source["entries"][0], {"path": "/nix/store/*"},
                      {"path": "/outside/store/path"}, {"path": source["excluded"]}):
            invalid = copy.deepcopy(source)
            invalid["entries"].append(entry)
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                host.rules_for(invalid)

    def test_evidence_uses_the_existing_acknowledged_protocol(self):
        class Channel:
            def __init__(self):
                self.message = bytearray()
            def write(self, data):
                self.message.extend(data[:1])
                return 1
            def flush(self):
                pass
            def readline(self):
                return events.encode({"id": events.decode(self.message)["id"], "ok": True})
        channel = Channel()
        events.request(channel, events.Operation.BOOT_COMPLETE, {"target_state": "active"})
        message = events.decode(channel.message)
        self.assertEqual(message["operation"], events.Operation.BOOT_COMPLETE.value)
        self.assertEqual(message["evidence"], {"target_state": "active"})


class BootEvidence(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.closure = host.Closure.__new__(host.Closure)
        self.closure.work = Path(self.temporary.name)
        self.closure.manifest = manifest()
        self.closure.data = json.dumps(self.closure.manifest).encode()
        self.closure.rules = host.rules_for(self.closure.manifest)
        self.closure.before = b"unchanged"
        self.closure.booted = False
        self.closure.firewall = firewall
        self.evidence = {
            "manifest_sha256": hashlib.sha256(self.closure.data).hexdigest(),
            "paths_checked": 2, "store_before": "empty", "magic": "766f6964",
            "target_state": "active", "target": "multi-user.target",
            "system": manifest()["toplevel"], "excluded": manifest()["excluded"],
            "mounts": [{"target": "/nix/store", "fstype": "voidport",
                        "source": "closure", "options": "ro,nodev,nosuid"}],
            "writes_refused": [
                {"path": manifest()["witness"], "errno": errno.EROFS},
                {"path": "/nix/store/voidport-must-not-exist", "errno": errno.EROFS}],
            "firewall": started_firewall(),
        }

    def test_shutdown_requires_complete_boot_evidence(self):
        shutdown = {"shutdown": "systemctl poweroff"}
        with self.assertRaises(AssertionError):
            self.closure.complete(shutdown)
        with patch.object(Path, "read_bytes", return_value=b"unchanged"):
            self.closure.boot(self.evidence)
            self.closure.complete(shutdown)
        self.assertTrue(self.closure.booted)
        self.assertEqual(json.loads((self.closure.work / "boot.json").read_text()), self.evidence)

    def test_missing_or_incorrect_assertions_cannot_complete(self):
        for key in self.evidence:
            incomplete = {k: v for k, v in self.evidence.items() if k != key}
            with self.subTest(key=key), self.assertRaises(AssertionError):
                self.closure.boot(incomplete)
        self.assertFalse(self.closure.booted)

    def test_incorrect_firewall_evidence_cannot_complete(self):
        started = started_firewall()
        changed = copy.deepcopy(started)
        changed["tables"][0]["listing"].append("-A INPUT -s 10.0.2.2/32 -j ACCEPT")
        for observed in (dict(started, service="failed"), dict(started, service="inactive"),
                         {"service": "active", "tables": started["tables"]},
                         dict(started, tables=started["tables"][1:]), changed, {}, None):
            evidence = dict(self.evidence, firewall=observed)
            with self.subTest(firewall=observed), self.assertRaisesRegex(
                    AssertionError, "firewall"):
                self.closure.boot(evidence)
        self.assertFalse(self.closure.booted)

    def test_changed_server_bytes_fail_the_boot_event(self):
        with patch.object(Path, "read_bytes", return_value=b"changed"):
            with self.assertRaisesRegex(AssertionError, "backing store bytes"):
                self.closure.boot(self.evidence)
        self.assertFalse(self.closure.booted)


class Bootstrap(unittest.TestCase):
    DEPENDENCIES = {
        "virtio_pci": ["virtio/virtio_ring.ko.xz", "virtio/virtio.ko.xz",
                       "virtio/virtio_pci_modern_dev.ko.xz",
                       "virtio/virtio_pci_legacy_dev.ko.xz", "virtio/virtio_pci.ko.xz"],
        "virtio_net": ["virtio/virtio_ring.ko.xz", "virtio/virtio.ko.xz",
                       "net/failover.ko.xz", "net/net_failover.ko.xz",
                       "net/virtio_net.ko.xz"],
        "nf_conntrack": ["netfilter/nf_defrag_ipv4.ko", "netfilter/nf_defrag_ipv6.ko.xz",
                         "netfilter/nf_conntrack.ko.xz"],
    }
    MODULES = (("virtio_pci", ()), ("virtio_net", ()), ("nf_conntrack", ("enable_hooks=1",)))

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.tree = Path(self.temporary.name) / "tree"
        for paths in self.DEPENDENCIES.values():
            for path in paths:
                module = self.tree / path
                module.parent.mkdir(parents=True, exist_ok=True)
                content = self.content(path)
                module.write_bytes(lzma.compress(content, format=lzma.FORMAT_XZ)
                                   if module.suffix == ".xz" else content)

    @staticmethod
    def content(path):
        return f"module {Path(path).name.split('.')[0]}\n".encode()

    def assemble(self, dependencies):
        calls = []

        def show_depends(args, text):
            calls.append(args)
            self.assertTrue(text)
            return "".join(line + "\n" for line in dependencies[args[-1]])

        root = Path(tempfile.mkdtemp(dir=self.temporary.name))
        with patch.object(bootstrap.subprocess, "check_output", side_effect=show_depends):
            bootstrap.assemble("/modules-tree", "7.1.8", root, self.MODULES)
        return calls, root

    def modprobe_output(self, builtin=()):
        return {name: [*(f"builtin {module}" for module in builtin),
                       *(f"insmod {self.tree / path} " for path in paths)]
                for name, paths in self.DEPENDENCIES.items()}

    def test_modules_load_in_dependency_order_once_with_hooks_on_conntrack(self):
        calls, root = self.assemble(self.modprobe_output(builtin=("crc32c",)))
        self.assertEqual(calls, [
            ["modprobe", "-d", "/modules-tree", "-S", "7.1.8", "--show-depends",
             "--ignore-install", name]
            for name, _ in self.MODULES])
        order = list(dict.fromkeys(
            path for name, _ in self.MODULES for path in self.DEPENDENCIES[name]))
        self.assertEqual((root / "load-modules").read_text().splitlines(), [
            *(f"insmod /modules/{index}.ko" for index in range(1, len(order))),
            f"insmod /modules/{len(order)}.ko enable_hooks=1"])
        copies = sorted((root / "modules").iterdir(),
                        key=lambda copy: int(copy.name.split(".")[0]))
        self.assertEqual([copy.read_bytes() for copy in copies],
                         [self.content(path) for path in order])

    def test_an_unexpected_modprobe_command_is_refused(self):
        for line in ("install /bin/true", "insmod", "insmod a.ko b.ko", "rmmod virtio"):
            dependencies = self.modprobe_output()
            dependencies["virtio_net"] = [*dependencies["virtio_net"][:-1], line]
            with self.subTest(line=line), self.assertRaisesRegex(
                    ValueError, "unexpected module load command"):
                self.assemble(dependencies)


class Firewall(unittest.TestCase):
    CHANGES = {
        "rule added": lambda lines: [*lines, "-A INPUT -s 10.0.2.2/32 -j ACCEPT"],
        "rule added before the jump": lambda lines: [
            *lines[:2], "-A INPUT -s 10.0.2.2/32 -j ACCEPT", *lines[2:]],
        "rule removed": lambda lines: lines[:-1],
        "rules swapped": lambda lines: [*lines[:-2], lines[-1], lines[-2]],
        "policy changed": lambda lines: ["-P INPUT DROP", *lines[1:]],
        "chain added": lambda lines: [*lines, "-N extra"],
    }

    def changed(self, side, key, change):
        observed = started_firewall()
        entry = observed[side][EVERY_TABLE.index(key)]
        entry["listing"] = change(entry["listing"])
        return observed

    def test_equal_tables_pass(self):
        firewall.check(started_firewall())

    def test_a_service_that_is_not_active_is_refused(self):
        for state in ("failed", "inactive", "activating", ""):
            with self.subTest(state=state), self.assertRaisesRegex(
                    AssertionError, "firewall service"):
                firewall.check(dict(started_firewall(), service=state))

    def test_a_table_that_cannot_be_listed_is_refused(self):
        for side in ("tables", "reference"):
            for tool, table in EVERY_TABLE:
                observed = self.changed(side, (tool, table), lambda lines: None)
                with self.subTest(side=side, tool=tool, table=table), self.assertRaisesRegex(
                        AssertionError, f"the {table} table in {tool} cannot be listed"):
                    firewall.check(observed)

    def test_a_missing_repeated_or_unknown_table_is_refused(self):
        for side in ("tables", "reference"):
            entries = started_firewall()[side]
            unknown = dict(entries[0], table="broute")
            for name, changed in (("missing", entries[1:]), ("repeated", [*entries, entries[0]]),
                                  ("unknown", [*entries, unknown])):
                observed = dict(started_firewall(), **{side: changed})
                with self.subTest(side=side, change=name), self.assertRaisesRegex(
                        AssertionError, "lists other tables"):
                    firewall.check(observed)

    def test_every_change_to_a_table_is_refused(self):
        for side in ("tables", "reference"):
            for name, change in self.CHANGES.items():
                for tool, table in EVERY_TABLE:
                    observed = self.changed(side, (tool, table), change)
                    with self.subTest(side=side, change=name, tool=tool, table=table), \
                            self.assertRaisesRegex(
                                AssertionError, f"the {table} table in {tool} differs"):
                        firewall.check(observed)


class Observation(unittest.TestCase):
    def observe(self, guest):
        namespaces = {}

        def run(args, **_):
            match args:
                case ["ip", "netns", "add", name]:
                    namespaces[name] = lambda tool, table: []
                case ["systemctl", "start", unit]:
                    name = unit.removesuffix(".service")
                    self.assertIn(name, namespaces)
                    namespaces[name] = rules
                case ["ip", "netns", "exec", name, tool, "-w", "-t", table, "-S"]:
                    return self.listed(args, namespaces[name](tool, table))
                case [tool, "-w", "-t", table, "-S"]:
                    return self.listed(args, guest(tool, table))
                case _:
                    self.fail(f"unexpected command: {args}")
            return subprocess.CompletedProcess(args, 0)

        return firewall.observe({"firewall.service": "active"}.get, run, "reference")

    @staticmethod
    def listed(args, lines):
        return subprocess.CompletedProcess(args, 0, stdout="".join(line + "\n" for line in lines))

    def test_a_guest_with_the_started_tables_passes(self):
        firewall.check(self.observe(rules))

    def test_a_guest_with_other_tables_is_refused(self):
        observed = self.observe(lambda tool, table: [*rules(tool, table), "-A INPUT -j ACCEPT"])
        with self.assertRaisesRegex(AssertionError, "differs"):
            firewall.check(observed)


if __name__ == "__main__":
    unittest.main()
