# Single sign-on with Keycloak (optional `sso` module)

Adds a Keycloak OIDC identity provider so people log in with **their own
accounts and group-based permissions**, while all service/internal accounts
(admin, kibanaserver, Filebeat) keep working over basic auth as a fallback.

```text
   Browser ── https://siem.local.domain ──► Wazuh dashboard
      │                                        │  "Keycloak SSO" button
      ▼                                        ▼
   https://sso.siem.local.domain:8443 ◄── OIDC redirect
              Keycloak (realm "siem")
                     │ token (groups claim)
                     ▼
        Indexer security plugin: groups -> backend roles -> permissions
```

## Two permission layers (both must be mapped)

This trips people up: a Wazuh deployment has **two independent RBAC systems**,
and an SSO user needs a mapping in each.

```text
                    Keycloak group (groups claim)
                              │
             ┌────────────────┴────────────────┐
             ▼                                 ▼
  Indexer security plugin              Wazuh API RBAC
  (what DATA you can see:              (what the app MODULES can call:
   indices, dashboards)                 mitre:read, agent:read, rules:update…)
             │                                 │
    roles_mapping.yml                 /security/rules  +  /security/roles
   siem-admins -> all_access          siem-admins -> administrator
```

Map only the first and login succeeds but every module shows
*"You have no permissions — this section requires mitre:read (*:*:*)"*.
`sso init` configures **both**; the API side is applied by `wazuh_api_rbac()`
in `wazuh-deploy.sh` and is idempotent.

| Keycloak group | Indexer security roles (data) | Wazuh API roles (modules) |
|---|---|---|
| `siem-admins` | `all_access` | `administrator` — full API, incl. `mitre:read`, agent management, rules/decoders, security config |
| `siem-analysts` | `kibana_user`, `readall` | `readonly`, `agents_readonly`, `cluster_readonly` — read every module, change nothing |
| `siem-readonly` | `kibana_user`, `readall` | `readonly` — separate group so it can be tightened independently |

The dashboard reaches the API as `wazuh-wui` with **run_as**, forwarding the
logged-in user's authentication context (`user_name` + `backend_roles`); the
API rules match on `backend_roles`, i.e. the Keycloak groups. Verify both
layers at once with `./wazuh-deploy.sh sso status`.

**After changing group membership or role mappings, log out and back in** —
both the OIDC token and the API run_as context are minted at login.

Add more teams (e.g. `soc-managers`, `idp-team`) by creating the group in
Keycloak, mapping it in `config/wazuh_indexer/security/roles_mapping.yml`
(data layer) **and** adding it to the `map=(...)` list in `wazuh_api_rbac()`
(module layer), then re-running `sso init` — it is idempotent. Two test users ship in the
realm import: `ssoadmin` (siem-admins) and `analyst1` (siem-analysts) —
passwords in `.env`.

## Where the secrets live

| Secret | Location |
|---|---|
| Keycloak admin console (`admin`) | `KEYCLOAK_ADMIN_PASSWORD` in `.env` |
| OIDC client secret (`wazuh-dashboard` client) | `OIDC_CLIENT_SECRET` in `.env` → rendered into `config/keycloak/realm-siem.json` and the generated `config/wazuh_dashboard/opensearch_dashboards.yml` (both gitignored) |
| Test users | `SSO_ADMIN_PASSWORD`, `SSO_ANALYST_PASSWORD` in `.env` |

Keycloak gets its own PKI identity (`keycloak`, SAN `sso.<domain>`) — no
extra certificates anywhere else; the dashboard and indexers just trust the
root CA.

## Enable

```bash
./wazuh-deploy.sh sso enable      # secrets, realm import, dashboard config
./wazuh-deploy.sh pki csr && ./wazuh-deploy.sh pki sign   # keycloak cert
docker compose up -d && docker compose up -d --force-recreate wazuh.dashboard
./wazuh-deploy.sh sso init        # OIDC auth domain + role mappings (securityadmin)
./wazuh-deploy.sh sso status      # end-to-end test: token grant -> indexer authinfo
```

DNS: add `sso.<domain>` → host IP (the `dns records` script includes it).
The login page then shows both **username/password** and **"Keycloak SSO"**.

Design notes: basic auth stays at order 0 with `challenge: false` so internal
users and Filebeat are unaffected; OIDC is order 1 with `roles_key: groups`;
the plugin fetches JWKS from Keycloak over TLS verified against the root CA.
Keycloak runs with a dev-file database — switch `KC_DB` to postgres for a
production multi-user deployment.

## Auditing

The indexer security audit trail is enabled on every node
(`plugins.security.audit.type: internal_opensearch`): logins, failed logins,
and privileged/admin actions land in `security-auditlog-*` indices
(`kibanaserver` is excluded as noise). Retention is 180 days via the
`security-audit-retention` ISM policy (applied by `sso init`; adjust
`config/ism/security-audit-retention-policy.json`). Browse the audit trail in
the dashboard under Index Management, or query `security-auditlog-*` like any
index.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `"You have no permissions … mitre:read (*:*:*)"` | the Wazuh **API** RBAC mapping is missing for that group — re-run `./wazuh-deploy.sh sso init`, then log out and back in |
| browser redirects to the wrong port (e.g. `:8444`) | the dashboard caches Keycloak's OIDC discovery document at startup — `docker compose restart wazuh.dashboard` after any Keycloak hostname/port change |
| `DNS_PROBE_FINISHED_NXDOMAIN` / "can't find the server" for `sso.<domain>` | the SSO hostname is not in DNS or the client's hosts file — run `./wazuh-deploy.sh dns records` (the `sso` record is included) |
| certificate warning on the Keycloak page | import `config/certs-ca/root-ca.pem` into the OS/browser trust store (System keychain → Always Trust on macOS) |
| SSO login works but shows no data | indexer-side mapping missing — check `./wazuh-deploy.sh sso status` reports indexer roles for the user |
