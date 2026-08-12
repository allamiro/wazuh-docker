#!/usr/bin/env python3
"""Apply config/iris-groups.conf to DFIR-IRIS.

Creates or updates the IRIS groups that back the SOC roles, sets their
permission mask, and gives each group its default access to every case.
Idempotent - run it whenever the file changes or new cases are created.

    python3 scripts/iris-sync-groups.py
    python3 scripts/iris-sync-groups.py --dry-run

IRIS stores group permissions as a bitmask (the UI shows the same names) and
resolves case access through customer -> group -> user, materialising the
result into user_case_effective_access. This script writes the group layer;
scripts/iris-sync-users.py maps users into groups and refreshes the effective
table.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONF = ROOT / "config/iris-groups.conf"
DRY = "--dry-run" in sys.argv

# IRIS permission bits - verified against the shipped groups
# (Analysts = 1133 = standard_user + alerts_read + alerts_write +
#  search_across_cases + customers_read + activities_read)
PERMS = {
    "standard_user": 1,
    "server_administrator": 2,
    "alerts_read": 4,
    "alerts_write": 8,
    "alerts_delete": 16,
    "search_across_cases": 32,
    "customers_read": 64,
    "customers_write": 128,
    "case_templates_read": 256,
    "case_templates_write": 512,
    "activities_read": 1024,
    "all_activities_read": 2048,
    "statistics_read": 4096,
    "custom_dashboards_read": 8192,
    "custom_dashboards_write": 16384,
    "custom_dashboards_share": 32768,
}

ACCESS = {"deny_all": 1, "read_only": 2, "full_access": 4}


def sql(query):
    out = subprocess.run(["docker", "exec", "iris-db", "psql", "-U", "raccoon_admin",
                          "-d", "iris_db", "-tAc", query],
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"[FAIL] {out.stderr.strip()[:200]}")
    return out.stdout.strip()


def mask(names):
    total = 0
    for n in names:
        if n not in PERMS:
            sys.exit(f"[FAIL] unknown permission '{n}' - see the list in {CONF.name}")
        total |= PERMS[n]
    return total


def parse():
    rows = []
    for line in CONF.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 4:
            sys.exit(f"[FAIL] malformed line: {line}")
        kc, group, perms, access = parts
        if access not in ACCESS:
            sys.exit(f"[FAIL] bad case_access '{access}' in: {line}")
        rows.append({"keycloak": kc, "group": group,
                     "perms": [p for p in perms.split(",") if p],
                     "access": access})
    return rows


def main():
    rows = parse()
    print(f"IRIS groups from {CONF.relative_to(ROOT)} "
          f"({len(rows)} mapping(s)){' [DRY RUN]' if DRY else ''}\n")

    cases = [c for c in sql("select case_id from cases order by case_id").splitlines() if c]
    print(f"{len(cases)} case(s) in IRIS\n")

    seen = set()
    for r in rows:
        name = r["group"]
        bits = mask(r["perms"])
        level = ACCESS[r["access"]]
        gid = sql(f"select group_id from groups where group_name = '{name}'")

        if not gid:
            if DRY:
                print(f"  {name:<16} would create (perms {bits}, {r['access']})")
                continue
            sql("insert into groups (group_name, group_description, group_permissions, group_auto_follow, group_auto_follow_access_level, group_uuid) values "
                "('%s', 'SOC role - managed by config/iris-groups.conf', %d, false, %d, gen_random_uuid())" % (name, bits, level))
            gid = sql(f"select group_id from groups where group_name = '{name}'")
            state = "created"
        else:
            current = sql(f"select group_permissions from groups where group_id = {gid}")
            if current != str(bits) and not DRY:
                sql(f"update groups set group_permissions = {bits} where group_id = {gid}")
                state = f"permissions updated ({current} -> {bits})"
            else:
                state = "up to date" if current == str(bits) else f"would set perms {bits}"

        # default case access for this group
        if not DRY:
            for case_id in cases:
                have = sql(f"select access_level from group_case_access "
                           f"where group_id = {gid} and case_id = {case_id}")
                if have == str(level):
                    continue
                if have:
                    sql(f"update group_case_access set access_level = {level} "
                        f"where group_id = {gid} and case_id = {case_id}")
                else:
                    sql(f"insert into group_case_access (group_id, case_id, access_level) "
                        f"values ({gid}, {case_id}, {level})")

        if name not in seen:
            print(f"  {name:<16} {state}")
            print(f"     keycloak   {r['keycloak']}")
            print(f"     case access {r['access']} on {len(cases)} case(s)")
            print(f"     permissions {', '.join(r['perms'])}\n")
            seen.add(name)

    if not DRY:
        print("Now map users into these groups and refresh effective access:")
        print("  python3 scripts/iris-sync-users.py")


if __name__ == "__main__":
    main()
