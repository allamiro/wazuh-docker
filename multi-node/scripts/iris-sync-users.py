#!/usr/bin/env python3
"""Create the SSO identities inside DFIR-IRIS.

IRIS 2.4 in oidc_proxy mode authenticates by looking the user up by e-mail
(`app/util.py::_authenticate_with_email`) and fails if the account does not
already exist - it never provisions on the fly, whatever
IRIS_AUTHENTICATION_CREATE_USER_IF_NOT_EXIST suggests. So every Keycloak user
that should reach IRIS needs a matching local account whose e-mail equals the
`sub` claim the realm emits (the deployment maps sub -> e-mail).

Idempotent: existing users are left alone. Run again after adding people to
Keycloak.

    python3 scripts/iris-sync-users.py
"""
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CA = os.path.join(ROOT, "config/wazuh_indexer_ssl_certs/root-ca.pem")
BASE = "https://iris-app:8000"

# Keycloak users that should have IRIS access: (login, email, admin?)
USERS = [
    ("ssoadmin", "ssoadmin@siem.local", True),
    ("analyst1", "analyst1@siem.local", False),
]


def env(key):
    with open(os.path.join(ROOT, ".env")) as fh:
        for line in fh:
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
    sys.exit(f"[FAIL] {key} missing from .env")


def api(path, payload=None):
    """Call the IRIS API from inside the siem network via the app container."""
    import subprocess
    cmd = ["docker", "exec", "iris-app", "curl", "-s",
           "-H", f"Authorization: Bearer {env('IRIS_API_KEY')}",
           "-H", "Content-Type: application/json",
           f"http://127.0.0.1:8000{path}"]
    if payload is not None:
        cmd += ["-X", "POST", "-d", json.dumps(payload)]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"status": "error", "raw": out[:200]}


def main():
    existing = api("/manage/users/list")
    emails = {u.get("user_email") for u in existing.get("data", [])} \
        if isinstance(existing.get("data"), list) else set()
    print(f"IRIS already knows {len(emails)} user(s)")

    import secrets
    for login, email, is_admin in USERS:
        if email in emails:
            print(f"  [SKIP] {login} ({email}) exists")
            continue
        res = api("/manage/users/add", {
            "user_name": login,
            "user_login": login,
            "user_email": email,
            # SSO users never use this password; IRIS requires one anyway
            "user_password": "Sso." + secrets.token_urlsafe(24),
            "user_isadmin": is_admin,
        })
        status = res.get("status", "?")
        print(f"  [{'OK  ' if status == 'success' else 'FAIL'}] {login} ({email})"
              + ("" if status == "success" else f" - {str(res)[:140]}"))




# --- group membership -------------------------------------------------------
# IRIS auto-creates an SSO user on first login but puts it in NO group, and
# since v2.4.0 the default case access is deny_all - so the user logs in and
# then gets "ACCESS DENIED" everywhere. Map Keycloak groups to IRIS groups.
#
#   Keycloak group -> IRIS group name
IRIS_GROUP_MAP = {
    "siem-admins": "Administrators",
    "soc-engineer": "Administrators",
    "siem-analysts": "Analysts",
    "siem-readonly": "Analysts",
    "soc-tier1": "Analysts",
    "soc-tier2": "Analysts",
    "soc-tier3": "Analysts",
}

# Which IRIS group each shipped SSO account belongs in
USER_GROUPS = {
    "ssoadmin@siem.local": "Administrators",
    "analyst1@siem.local": "Analysts",
}


def sql(query):
    import subprocess
    out = subprocess.run(["docker", "exec", "iris-db", "psql", "-U", "raccoon_admin",
                          "-d", "iris_db", "-tAc", query],
                         capture_output=True, text=True)
    return out.stdout.strip()


def sync_groups():
    """Put every known user into its IRIS group (idempotent)."""
    print("\nGroup membership:")
    for email, group in USER_GROUPS.items():
        # IRIS stores the login rather than the address as e-mail when the
        # IdP omits the email claim, so match on either form
        login = email.split("@")[0]
        uid = sql("select id from \"user\" where email = '%s' or email = '%s' or \"user\" = '%s' limit 1" % (email, login, login))
        gid = sql(f"select group_id from groups where group_name = '{group}'")
        if not uid or not gid:
            print(f"  [SKIP] {email} -> {group} (user or group missing yet)")
            continue
        sql(f"insert into user_group (user_id, group_id) select {uid}, {gid} "
            f"where not exists (select 1 from user_group where user_id={uid} and group_id={gid})")
        print(f"  [OK  ] {email} -> {group}")
    print("\nUsers appear here only after their first SSO login (IRIS creates")
    print("them then); re-run this script afterwards to grant the group.")


if __name__ == "__main__":
    main()
    sync_groups()
