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

## Groups → roles (who can do what)

| Keycloak group | Indexer security roles | Meaning |
|---|---|---|
| `siem-admins` | `all_access` | full administration |
| `siem-analysts` | `kibana_user`, `readall` | dashboards + read all data |
| `siem-readonly` | `kibana_user`, `readall` | same read profile; separate group so it can be tightened independently |

Add more teams (e.g. `soc-managers`, `idp-team`) by creating the group in
Keycloak and mapping it in
`config/wazuh_indexer/security/roles_mapping.yml`, then re-running the
securityadmin step (`sso init` is idempotent). Two test users ship in the
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
