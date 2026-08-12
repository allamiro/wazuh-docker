#!/usr/bin/env python3
"""Make sure every group referenced by the deployment exists in Keycloak.

Keycloak is the single source of identity: Wazuh, MISP and IRIS all authorise
from the `groups` claim. The group names live in two config files, so this
script reads both and creates whatever is missing in the realm - no manual
clicking, and nothing drifts.

    config/sso-groups.conf    -> Wazuh (indexer roles, API roles, tenant, DLS)
    config/iris-groups.conf   -> IRIS  (permissions + case access)

    python3 scripts/sync-keycloak-groups.py
    python3 scripts/sync-keycloak-groups.py --dry-run
    python3 scripts/sync-keycloak-groups.py --export realm-export.json

With an ADFS / LDAP / AD user federation in front, you do NOT create users
here: you map the directory's groups onto these names (Keycloak: User
Federation -> LDAP -> Mappers -> group-ldap-mapper, or Identity Providers ->
Mappers for ADFS claims). Everything downstream then follows automatically.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / ".env"
CA = ROOT / "config/wazuh_indexer_ssl_certs/root-ca.pem"
SOURCES = [ROOT / "config/sso-groups.conf", ROOT / "config/iris-groups.conf"]
DRY = "--dry-run" in sys.argv
EXPORT = None
if "--export" in sys.argv:
    EXPORT = sys.argv[sys.argv.index("--export") + 1]


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


def wanted_groups():
    """First field of every non-comment line in both config files."""
    names = []
    for src in SOURCES:
        if not src.exists():
            continue
        for line in src.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name = line.split("|")[0].strip()
            if name and name not in names:
                names.append(name)
    return names


def main():
    auth = f"Authorization: Bearer {token()}"

    if EXPORT:
        # full realm: clients, groups, roles, mappers - importable elsewhere
        realm = curl("-H", auth, f"{KC}/admin/realms/siem")
        clients = curl("-H", auth, f"{KC}/admin/realms/siem/clients")
        groups = curl("-H", auth, f"{KC}/admin/realms/siem/groups")
        roles = curl("-H", auth, f"{KC}/admin/realms/siem/roles")
        data = json.loads(realm)
        data["clients"] = [c for c in json.loads(clients)
                           if not c["clientId"].startswith(("account", "admin-cli",
                                                            "broker", "realm-management",
                                                            "security-admin-console"))]
        data["groups"] = json.loads(groups)
        data["roles"] = {"realm": json.loads(roles)}
        # secrets are NOT exported by the admin API; note where they live
        data["_note"] = ("client secrets are in .env as <NAME>_OIDC_SECRET - "
                         "re-apply them with scripts/apply-sso-clients.py after import")
        Path(EXPORT).write_text(json.dumps(data, indent=2))
        print(f"[OK] realm exported to {EXPORT}")
        print(f"     clients: {len(data['clients'])}  groups: {len(data['groups'])}")
        print("     import with: kc.sh import --file <this> --override true")
        print("     then: python3 scripts/apply-sso-clients.py   (restores secrets)")
        return

    existing = {g["name"] for g in json.loads(curl("-H", auth, f"{KC}/admin/realms/siem/groups"))}
    names = wanted_groups()
    print(f"Groups referenced by the deployment: {len(names)}"
          f"{' [DRY RUN]' if DRY else ''}\n")

    for name in names:
        if name in existing:
            print(f"  [OK  ] {name} exists")
            continue
        if DRY:
            print(f"  [ .. ] {name} would be created")
            continue
        code = curl("-o", "/dev/null", "-w", "%{http_code}", "-X", "POST", "-H", auth,
                    "-H", "Content-Type: application/json",
                    f"{KC}/admin/realms/siem/groups",
                    "-d", json.dumps({"name": name}))
        print(f"  [{'OK  ' if code in ('201', '409') else 'FAIL'}] {name} created (HTTP {code})")

    print("\nSources:", ", ".join(str(s.relative_to(ROOT)) for s in SOURCES))
    print("Assign members in Keycloak, or map them from ADFS/LDAP - see docs/SSO.md")


if __name__ == "__main__":
    main()
