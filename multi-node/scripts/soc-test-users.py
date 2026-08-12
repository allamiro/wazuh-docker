#!/usr/bin/env python3
"""Create one test user per SOC role, so every permission set can be exercised.

Gives you a realm you can log into as each role and confirm what it actually
sees in Wazuh, MISP and IRIS - the fastest way to validate an authorisation
model before real people depend on it.

    python3 scripts/soc-test-users.py                 # create/refresh
    python3 scripts/soc-test-users.py --dry-run
    python3 scripts/soc-test-users.py --delete        # remove them again

Passwords are generated, written to soc-test-users.txt (gitignored) and
printed as a table. Users are created directly in Keycloak; with an
ADFS/LDAP federation these are the equivalent of the directory accounts, so
delete them before go-live.
"""
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / ".env"
CA = ROOT / "config/wazuh_indexer_ssl_certs/root-ca.pem"
OUT = ROOT / "soc-test-users.txt"
DRY = "--dry-run" in sys.argv
DELETE = "--delete" in sys.argv

# login | group | full name | what the account is for
USERS = [
    ("t1.analyst",    "soc-tier1",     "Tier 1 Analyst",     "alert triage, read-only cases"),
    ("t2.analyst",    "soc-tier2",     "Tier 2 Investigator", "owns cases, full case access"),
    ("t3.responder",  "soc-tier3",     "Tier 3 Responder",   "containment, agent admin"),
    ("intel.analyst", "soc-intel",     "Threat Intel Analyst", "MISP org admin"),
    ("soc.manager",   "soc-manager",   "SOC Manager",        "metrics, review, templates"),
    ("soc.engineer",  "soc-engineer",  "SOC Engineer",       "platform admin everywhere"),
    ("auditor",       "soc-audit",     "Compliance Auditor", "read-only, activities"),
]


def env(key, default=None):
    for line in ENV.read_text().splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    if default is not None:
        return default
    sys.exit(f"[FAIL] {key} missing from .env")


DOMAIN = env("SIEM_DOMAIN", "siem.local.domain")
KC = f"https://sso.{DOMAIN}:8443"
RESOLVE = f"sso.{DOMAIN}:8443:127.0.0.1"


def curl(*args):
    return subprocess.run(["curl", "-ks", "--cacert", str(CA), "--resolve", RESOLVE, *args],
                          capture_output=True, text=True).stdout


def token():
    out = curl("-d", "client_id=admin-cli", "-d", "username=admin",
               "-d", f"password={env('KEYCLOAK_ADMIN_PASSWORD')}",
               "-d", "grant_type=password",
               f"{KC}/realms/master/protocol/openid-connect/token")
    try:
        return json.loads(out)["access_token"]
    except (json.JSONDecodeError, KeyError):
        sys.exit(f"[FAIL] cannot authenticate to Keycloak: {out[:160]}")


def main():
    auth = f"Authorization: Bearer {token()}"
    groups = {g["name"]: g["id"] for g in
              json.loads(curl("-H", auth, f"{KC}/admin/realms/siem/groups"))}
    rows = []

    for login, group, name, purpose in USERS:
        existing = json.loads(curl("-H", auth,
                                   f"{KC}/admin/realms/siem/users?username={login}&exact=true"))
        uid = existing[0]["id"] if existing else None

        if DELETE:
            if uid and not DRY:
                curl("-o", "/dev/null", "-X", "DELETE", "-H", auth,
                     f"{KC}/admin/realms/siem/users/{uid}")
            print(f"  [{'..' if DRY else 'OK'}] {login} deleted")
            continue

        if group not in groups:
            print(f"  [FAIL] group {group} missing - run scripts/sync-keycloak-groups.py")
            continue

        pw = "Soc1." + secrets.token_hex(10)
        first, _, last = name.partition(" ")
        body = {
            "username": login, "enabled": True, "emailVerified": True,
            "firstName": first, "lastName": last or "User",
            "email": f"{login}@{DOMAIN.split('.', 1)[0]}.local",
            "credentials": [{"type": "password", "value": pw, "temporary": False}],
        }

        if DRY:
            print(f"  [ .. ] {login:<14} -> {group}")
            continue

        if uid:
            curl("-o", "/dev/null", "-X", "PUT", "-H", auth,
                 "-H", "Content-Type: application/json",
                 f"{KC}/admin/realms/siem/users/{uid}", "-d", json.dumps(body))
        else:
            curl("-o", "/dev/null", "-X", "POST", "-H", auth,
                 "-H", "Content-Type: application/json",
                 f"{KC}/admin/realms/siem/users", "-d", json.dumps(body))
            found = json.loads(curl("-H", auth,
                                    f"{KC}/admin/realms/siem/users?username={login}&exact=true"))
            uid = found[0]["id"] if found else None

        if not uid:
            print(f"  [FAIL] {login} could not be created")
            continue

        # (re)set the password explicitly - PUT above does not always apply it
        curl("-o", "/dev/null", "-X", "PUT", "-H", auth,
             "-H", "Content-Type: application/json",
             f"{KC}/admin/realms/siem/users/{uid}/reset-password",
             "-d", json.dumps({"type": "password", "value": pw, "temporary": False}))
        code = curl("-o", "/dev/null", "-w", "%{http_code}", "-X", "PUT", "-H", auth,
                    f"{KC}/admin/realms/siem/users/{uid}/groups/{groups[group]}")
        print(f"  [{'OK  ' if code in ('204', '201') else 'WARN'}] {login:<14} -> {group}")
        rows.append((login, pw, group, body["email"], purpose))

    if DELETE or DRY or not rows:
        return

    width = max(len(r[0]) for r in rows)
    lines = ["SOC test accounts (Keycloak realm 'siem')", ""]
    lines.append(f"{'login'.ljust(width)}  {'password':<28} {'group':<14} purpose")
    for login, pw, group, email, purpose in rows:
        lines.append(f"{login.ljust(width)}  {pw:<28} {group:<14} {purpose}")
    lines += ["", f"Sign in at https://{DOMAIN} (Keycloak SSO), "
                  f"https://misp.{DOMAIN}:8081 and https://iris.{DOMAIN}:8082",
              "IRIS provisions the account on first login; afterwards run:",
              "  python3 scripts/iris-sync-users.py   (grants the IRIS group + case access)"]
    OUT.write_text("\n".join(lines) + "\n")
    OUT.chmod(0o600)
    print("\n" + "\n".join(lines))
    print(f"\nAlso written to {OUT.name} (chmod 600, gitignored)")


if __name__ == "__main__":
    main()
