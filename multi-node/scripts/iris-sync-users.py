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


if __name__ == "__main__":
    main()
