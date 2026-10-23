# SPDX-License-Identifier: GPL-2.0-only

TOOLS = ("iptables", "ip6tables")
TABLES = ("filter", "mangle", "nat", "raw", "security")


def listings(run, prefix=()):
    entries = []
    for tool in TOOLS:
        for table in TABLES:
            listed = run([*prefix, tool, "-w", "-t", table, "-S"],
                         capture_output=True, text=True)
            entries.append({"tool": tool, "table": table,
                            "listing": listed.stdout.splitlines() if listed.returncode == 0
                            else None})
    return entries


def observe(unit_state, run, reference):
    run(["ip", "netns", "add", reference], check=True)
    run(["systemctl", "start", f"{reference}.service"], check=True)
    return {"service": unit_state("firewall.service"), "tables": listings(run),
            "reference": listings(run, ["ip", "netns", "exec", reference])}


def tables_in(entries, place):
    found = {}
    for entry in entries:
        match entry:
            case {"tool": str(tool), "table": str(table), "listing": list(listing)}:
                found[tool, table] = listing
            case {"tool": str(tool), "table": str(table), "listing": None}:
                raise AssertionError(f"the {table} table in {tool} cannot be listed {place}")
            case _:
                raise AssertionError(f"malformed firewall table evidence: {entry!r}")
    if len(found) != len(entries) or found.keys() != {
            (tool, table) for tool in TOOLS for table in TABLES}:
        raise AssertionError(f"the firewall evidence lists other tables {place}: "
                             f"{sorted(found)}")
    return found


def check(observed):
    match observed:
        case {"service": str(service), "tables": list(tables), "reference": list(reference)}:
            pass
        case _:
            raise AssertionError(f"malformed firewall evidence: {observed!r}")
    if service != "active":
        raise AssertionError(f"firewall service is {service or 'unknown'}")
    guest = tables_in(tables, "in the guest")
    started = tables_in(reference, "in the empty namespace")
    for (tool, table), lines in started.items():
        if guest[tool, table] != lines:
            raise AssertionError(f"the {table} table in {tool} differs from the firewall "
                                 f"started in an empty namespace: {guest[tool, table]!r}")
