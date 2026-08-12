#!/usr/bin/env python3
"""Create/update every Keycloak client declared in config/sso-clients.conf.

Idempotent: existing clients are updated in place (same secret kept unless
--rotate is passed); missing ones are created with a fresh secret written to
.env as <NAME>_OIDC_SECRET.

    python3 scripts/apply-sso-clients.py            # apply
    python3 scripts/apply-sso-clients.py --dry-run  # show what would change
    python3 scripts/apply-sso-clients.py --rotate   # issue new secrets
"""
import base64
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLIENTS = ROOT / "config/sso-clients.conf"
ENV = ROOT / ".env"
CA = ROOT / "config/wazuh_indexer_ssl_certs/root-ca.pem"
DRY = "--dry-run" in sys.argv
ROTATE = "--rotate" in sys.argv


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
    return subprocess.run(
        ["curl", "-ks", "--cacert", str(CA), "--resolve", RESOLVE, *args],
        capture_output=True, text=True).stdout


def admin_token():
    out = curl("-d", "client_id=admin-cli", "-d", "username=admin",
               "-d", f"password={env('KEYCLOAK_ADMIN_PASSWORD')}",
               "-d", "grant_type=password",
               f"{KC}/realms/master/protocol/openid-connect/token")
    try:
        return json.loads(out)["access_token"]
    except (json.JSONDecodeError, KeyError):
        sys.exit(f"[FAIL] cannot authenticate to Keycloak: {out[:160]}")


def set_env(key, value):
    text = ENV.read_text()
    lines = [l for l in text.splitlines() if not l.startswith(key + "=")]
    lines.append(f"{key}={value}")
    ENV.write_text("\n".join(lines) + "\n")


def mappers(kinds, client_id):
    out = []
    if "groups" in kinds:
        out.append({
            "name": "groups", "protocol": "openid-connect",
            "protocolMapper": "oidc-group-membership-mapper",
            "config": {"claim.name": "groups", "full.path": "false",
                       "id.token.claim": "true", "access.token.claim": "true",
                       "userinfo.token.claim": "true"}})
    if "audience" in kinds:
        out.append({
            "name": "audience", "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {"included.client.audience": client_id,
                       "id.token.claim": "true", "access.token.claim": "true"}})
    if "sub-as-email" in kinds:
        out.append({
            "name": "sub-as-email", "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-property-mapper",
            "config": {"user.attribute": "email", "claim.name": "sub",
                       "jsonType.label": "String", "id.token.claim": "true",
                       "access.token.claim": "true", "userinfo.token.claim": "true"}})
    return out


def parse():
    rows = []
    for line in CLIENTS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 6:
            sys.exit(f"[FAIL] malformed line: {line}")
        name, cid, base, path, scopes, claims = parts
        base = base.replace("@DOMAIN@", DOMAIN)
        redirect = f"{base}/{path.lstrip('/')}" if path != "*" else f"{base}/*"
        rows.append({"name": name, "client_id": cid, "base": base,
                     "redirect": redirect,
                     "scopes": [] if scopes == "-" else scopes.split(","),
                     "claims": [] if claims == "-" else claims.split(",")})
    return rows


def main():
    rows = parse()
    print(f"SSO clients from {CLIENTS.relative_to(ROOT)} "
          f"({len(rows)}){' [DRY RUN]' if DRY else ''}\n")
    tok = admin_token()
    auth = f"Authorization: Bearer {tok}"
    existing = {c["clientId"]: c for c in
                json.loads(curl("-H", auth, f"{KC}/admin/realms/siem/clients"))}

    for r in rows:
        key = f"{r['name']}_OIDC_SECRET"
        current = None
        for line in ENV.read_text().splitlines():
            if line.startswith(key + "="):
                current = line.split("=", 1)[1].strip()
        secret = current if (current and not ROTATE) else secrets.token_hex(20)

        body = {
            "clientId": r["client_id"], "enabled": True,
            "protocol": "openid-connect", "publicClient": False,
            "secret": secret,
            "redirectUris": sorted({r["redirect"], f"{r['base']}/*"}),
            "webOrigins": [r["base"]],
            "standardFlowEnabled": True, "directAccessGrantsEnabled": True,
            "protocolMappers": mappers(r["claims"], r["client_id"]),
        }

        if DRY:
            state = "would update" if r["client_id"] in existing else "would create"
        elif r["client_id"] in existing:
            cid = existing[r["client_id"]]["id"]
            body["id"] = cid
            code = curl("-o", "/dev/null", "-w", "%{http_code}", "-X", "PUT",
                        "-H", auth, "-H", "Content-Type: application/json",
                        f"{KC}/admin/realms/siem/clients/{cid}", "-d", json.dumps(body))
            # replace mappers so claim config always matches the file
            for m in json.loads(curl("-H", auth,
                    f"{KC}/admin/realms/siem/clients/{cid}/protocol-mappers/models")):
                curl("-o", "/dev/null", "-X", "DELETE", "-H", auth,
                     f"{KC}/admin/realms/siem/clients/{cid}/protocol-mappers/models/{m['id']}")
            for m in body["protocolMappers"]:
                curl("-o", "/dev/null", "-X", "POST", "-H", auth,
                     "-H", "Content-Type: application/json",
                     f"{KC}/admin/realms/siem/clients/{cid}/protocol-mappers/models",
                     "-d", json.dumps(m))
            state = f"updated (HTTP {code})"
            set_env(key, secret)
        else:
            code = curl("-o", "/dev/null", "-w", "%{http_code}", "-X", "POST",
                        "-H", auth, "-H", "Content-Type: application/json",
                        f"{KC}/admin/realms/siem/clients", "-d", json.dumps(body))
            state = f"created (HTTP {code})"
            set_env(key, secret)

        print(f"  {r['client_id']:<18} {state}")
        print(f"     redirect  {r['redirect']}")
        print(f"     claims    {','.join(r['claims']) or '-'}")
        print(f"     secret    .env:{key}\n")

    if not DRY:
        print("Secrets are in .env. Restart any service whose secret changed.")


if __name__ == "__main__":
    main()
