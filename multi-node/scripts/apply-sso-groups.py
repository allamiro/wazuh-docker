#!/usr/bin/env python3
"""Apply config/sso-groups.conf to every permission layer.

One Keycloak group -> OpenSearch security roles (data) + Wazuh API RBAC roles
(modules) + an OpenSearch tenant (workspace, the equivalent of Kibana spaces).

Idempotent: re-running only adds what is missing. Called by
'./wazuh-deploy.sh sso init'; safe to run directly for a dry run:

    python3 scripts/apply-sso-groups.py --dry-run
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GROUPS = ROOT / "config/sso-groups.conf"
ENV = ROOT / ".env"
CA = ROOT / "config/wazuh_indexer_ssl_certs/root-ca.pem"
IDX_NODE = "master1.indexer"
DRY = "--dry-run" in sys.argv


def env(key):
    for line in ENV.read_text().splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1]
    raise SystemExit(f"[FAIL] {key} missing from .env")


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.stdout


def idx(method, path, body=None):
    """OpenSearch security REST API, called from inside the trust domain."""
    cmd = ["docker", "exec", IDX_NODE, "curl", "-s", "-X", method,
           "--cacert", "/usr/share/wazuh-indexer/config/certs/root-ca.pem",
           "-u", f"admin:{env('INDEXER_PASSWORD')}",
           f"https://{IDX_NODE}:9200{path}"]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    out = run(cmd)
    try:
        return json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        return {"_raw": out}


_token = None


def api(method, path, body=None):
    """Wazuh API (RBAC for the app modules)."""
    global _token
    base = ["curl", "-ks", "--cacert", str(CA),
            "--resolve", "wazuh.master:55000:127.0.0.1"]
    if _token is None:
        _token = run(base + ["-u", f"wazuh-wui:{env('API_PASSWORD')}", "-X", "POST",
                             "https://wazuh.master:55000/security/user/authenticate?raw=true"]).strip()
        if not _token:
            raise SystemExit("[FAIL] cannot authenticate to the Wazuh API")
    cmd = base + ["-H", f"Authorization: Bearer {_token}", "-X", method,
                  f"https://wazuh.master:55000{path}"]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    out = run(cmd)
    try:
        return json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        return {"_raw": out}


def parse_groups():
    rows = []
    for line in GROUPS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) not in (4, 5):
            raise SystemExit(f"[FAIL] malformed line in sso-groups.conf: {line}")
        group, idx_roles, api_roles, tenant = parts[:4]
        scope = parts[4] if len(parts) == 5 else "-"
        rows.append({
            "group": group,
            "indexer_roles": [r for r in idx_roles.split(",") if r and r != "-"],
            "api_roles": [r for r in api_roles.split(",") if r and r != "-"],
            "tenant": tenant if tenant != "-" else None,
            "data_scope": scope if scope != "-" else None,
        })
    return rows


def ensure_indexer_role_mapping(role, group):
    """Add group as a backend role of an OpenSearch security role."""
    cur = idx("GET", f"/_plugins/_security/api/rolesmapping/{role}")
    body = cur.get(role, {}) if isinstance(cur, dict) else {}
    backend = list(body.get("backend_roles", []))
    if group in backend:
        return "already mapped"
    if DRY:
        return "WOULD add"
    backend.append(group)
    payload = {"backend_roles": backend,
               "hosts": body.get("hosts", []),
               "users": body.get("users", [])}
    res = idx("PUT", f"/_plugins/_security/api/rolesmapping/{role}", payload)
    return "mapped" if res.get("status") in ("OK", "CREATED") else f"FAILED: {res}"


def ensure_tenant(name, access, group):
    """Create the tenant (workspace) + a role granting access, map the group."""
    if name == "global_tenant":
        role = "kibana_user"          # global tenant access ships with kibana_user
        return ensure_indexer_role_mapping(role, group), role
    if not DRY:
        idx("PUT", f"/_plugins/_security/api/tenants/{name}",
            {"description": f"SIEM workspace for {group}"})
    role = f"tenant_{name}_{'rw' if access == 'RW' else 'ro'}"
    actions = ["kibana_all_write"] if access == "RW" else ["kibana_all_read"]
    if not DRY:
        idx("PUT", f"/_plugins/_security/api/roles/{role}",
            {"cluster_permissions": [],
             "index_permissions": [],
             "tenant_permissions": [{"tenant_patterns": [name],
                                     "allowed_actions": actions}]})
    return ensure_indexer_role_mapping(role, group), role


def ensure_data_scope(group, query):
    """Document-level security: this group only sees matching alerts.

    NOTE: DLS is additive across roles - a group that also holds an
    unrestricted read role (e.g. readall) is NOT restricted. Give scoped
    groups kibana_user only.
    """
    role = f"scope_{group.replace('-', '_')}"
    if not DRY:
        idx("PUT", f"/_plugins/_security/api/roles/{role}", {
            "cluster_permissions": ["cluster_composite_ops_ro"],
            "index_permissions": [{
                "index_patterns": ["wazuh-alerts-*", "wazuh-archives-*",
                                   "wazuh-states-*", "wazuh-monitoring-*"],
                "dls": json.dumps({"query_string": {"query": query}}),
                "fls": [],
                "masked_fields": [],
                "allowed_actions": ["read", "indices:admin/mappings/get",
                                    "indices:admin/get"],
            }],
            "tenant_permissions": [],
        })
    return ensure_indexer_role_mapping(role, group), role


def ensure_api_rule(group, api_roles, role_ids, rules):
    rule_name = "sso_" + group.replace("-", "_")
    rid = rules.get(rule_name)
    if rid is None:
        if DRY:
            return "WOULD create rule", None
        res = api("POST", "/security/rules",
                  {"name": rule_name, "rule": {"FIND": {"backend_roles": group}}})
        items = res.get("data", {}).get("affected_items", [])
        if not items:
            return f"FAILED: {res.get('data', res)}", None
        rid = items[0]["id"]
    for name in api_roles:
        role_id = role_ids.get(name)
        if role_id is None:
            print(f"       [WARN] unknown Wazuh API role '{name}' - skipped")
            continue
        if not DRY:
            api("POST", f"/security/roles/{role_id}/rules?rule_ids={rid}")
    return "linked", rid


def main():
    rows = parse_groups()
    print(f"Applying {GROUPS.relative_to(ROOT)} "
          f"({len(rows)} group(s)){' [DRY RUN]' if DRY else ''}\n")

    role_ids = {r["name"]: r["id"] for r in
                api("GET", "/security/roles").get("data", {}).get("affected_items", [])}
    rules = {r["name"]: r["id"] for r in
             api("GET", "/security/rules").get("data", {}).get("affected_items", [])}

    for row in rows:
        g = row["group"]
        print(f"  {g}")
        for role in row["indexer_roles"]:
            print(f"     data     {role:<28} {ensure_indexer_role_mapping(role, g)}")
        if row["tenant"]:
            name, _, access = row["tenant"].partition(":")
            state, role = ensure_tenant(name, access or "RW", g)
            print(f"     tenant   {name + ' (' + (access or 'RW') + ')':<28} {state} via {role}")
        if row["data_scope"]:
            state, role = ensure_data_scope(g, row["data_scope"])
            print(f"     scope    {row['data_scope'][:28]:<28} {state} via {role}")
            if any(r in ("readall", "all_access") for r in row["indexer_roles"]):
                print("       [WARN] this group also has readall/all_access - "
                      "DLS is additive, so the scope will NOT restrict it")
        state, rid = ensure_api_rule(g, row["api_roles"], role_ids, rules)
        print(f"     modules  {','.join(row['api_roles']):<28} {state}"
              + (f" (rule {rid})" if rid else ""))
        print()

    print("Done. Users must log out and back in - roles are minted into the")
    print("token at login on both the indexer and the Wazuh API side.")


if __name__ == "__main__":
    main()
