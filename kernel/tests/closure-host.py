#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import errno
import hashlib
import json
from pathlib import Path
import tomllib


def rules_for(manifest):
    paths = [entry["path"] for entry in manifest["entries"]]
    if len(paths) != len(set(paths)) or not paths:
        raise ValueError("closure manifest is empty or has duplicate paths")
    if manifest["toplevel"] not in paths or manifest["witness"] not in paths:
        raise ValueError("closure omits the system or read-only witness")
    if manifest["excluded"] in paths:
        raise ValueError("excluded path is exported")
    rules = []
    for path in paths:
        location = Path(path)
        if location.parent != Path("/nix/store") or any(c in location.name for c in "*?[]{}\\"):
            raise ValueError(f"not a literal store path: {path}")
        rules.append({"path": "/" + location.name, "target": path, "mode": "ro"})
    return rules


def verify_mapping(manifest, rules):
    expected = rules_for(manifest)
    if len(rules) != len(expected):
        raise AssertionError("rule count differs from closure count")
    actual = {rule["path"]: rule for rule in rules}
    if len(actual) != len(rules) or actual != {rule["path"]: rule for rule in expected}:
        raise AssertionError("literal path-to-target mapping differs from closure")


class Closure:
    def __init__(self, guest, work, firewall):
        self.work = work
        self.firewall = firewall
        self.data = (guest / "manifest.json").read_bytes()
        self.manifest = json.loads(self.data)
        self.rules = rules_for(self.manifest)
        collected = (guest / "store-paths").read_text().splitlines()
        if sorted(collected) != sorted(entry["path"] for entry in self.manifest["entries"]):
            raise AssertionError("manifest does not describe the complete closureInfo result")
        if str((guest / "toplevel").resolve()) != self.manifest["toplevel"]:
            raise AssertionError("closure has the wrong toplevel root")
        if not Path(self.manifest["excluded"]).exists():
            raise AssertionError("excluded host path must exist")
        self.before = Path(self.manifest["witness"]).read_bytes()
        self.booted = False
        (work / "manifest.json").write_bytes(self.data)
        (work / "store-paths").write_text("\n".join(collected) + "\n")
        (work / "closure-inputs.json").write_text(json.dumps({
            "toplevel": self.manifest["toplevel"], "closure": str((guest / "closure").resolve()),
            "module": str((guest / "module").resolve()), "rule_count": len(self.rules),
            "witness_sha256": hashlib.sha256(self.before).hexdigest(),
        }, indent=2) + "\n")

    def namespace(self, name):
        if name != "closure":
            raise ValueError("closure fixture uses the closure namespace")
        return {"name": name, "rules": self.rules}

    def verify(self, serialized):
        namespaces = tomllib.loads(serialized)["namespaces"]
        if len(namespaces) != 1:
            raise AssertionError("the closure state contains more than the closure namespace")
        verify_mapping(self.manifest, namespaces[0]["rules"])
        (self.work / "rules.toml").write_text(serialized)

    def boot(self, evidence):
        if evidence.get("manifest_sha256") != hashlib.sha256(self.data).hexdigest():
            raise AssertionError("guest verified a different manifest")
        expected = {"paths_checked": len(self.rules), "store_before": "empty",
                    "magic": "766f6964", "target_state": "active",
                    "target": self.manifest["target"], "system": self.manifest["toplevel"],
                    "excluded": self.manifest["excluded"]}
        if any(evidence.get(key) != value for key, value in expected.items()):
            raise AssertionError("incomplete closure boot evidence")
        self.firewall.check(evidence.get("firewall"))
        mounts = evidence.get("mounts", [])
        if (len(mounts) != 1 or mounts[0].get("target") != "/nix/store"
                or mounts[0].get("fstype") != "voidport"
                or mounts[0].get("source") != "closure"
                or "ro" not in mounts[0].get("options", "").split(",")):
            raise AssertionError("wrong guest store mount")
        if evidence.get("writes_refused") != [
            {"path": self.manifest["witness"], "errno": errno.EROFS},
            {"path": "/nix/store/voidport-must-not-exist", "errno": errno.EROFS},
        ]:
            raise AssertionError("missing read-only write results")
        self.unchanged()
        (self.work / "boot.json").write_text(json.dumps(evidence, indent=2) + "\n")
        self.booted = True

    def unchanged(self):
        if Path(self.manifest["witness"]).read_bytes() != self.before:
            raise AssertionError("guest changed backing store bytes")

    def complete(self, evidence):
        if not self.booted or evidence != {"shutdown": "systemctl poweroff"}:
            raise AssertionError("shutdown preceded boot verification")
        self.unchanged()
