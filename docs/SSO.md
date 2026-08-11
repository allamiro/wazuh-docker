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

## Permissions: one file, three layers

Wazuh has **three independent permission systems**, and this trips everyone up:
map only one and users log in fine but see *"You have no permissions — this
section requires mitre:read (\*:\*:\*)"*, or land in an empty workspace.

```text
                 config/sso-groups.conf          ← the only file you edit
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
  indexer roles        Wazuh API roles       tenant
  (what DATA you       (what MODULES can     (which WORKSPACE:
   can see: indices,    do: mitre:read,       dashboards, saved
   dashboards)          agent:read…)          searches — see below)
        │                   │                   │
  rolesmapping API    /security/rules +    tenants + tenant_* roles
                      /security/roles
```

`./wazuh-deploy.sh sso init` applies all three from that one file
(`scripts/apply-sso-groups.py`, idempotent — re-run any time).

### Does Wazuh have "spaces" like Kibana?

Not by that name. The Wazuh dashboard is OpenSearch Dashboards, whose
equivalent of Kibana **spaces** is **tenants**: a named workspace holding its
own dashboards, visualizations and saved searches, shared by everyone granted
access. This deployment enables multi-tenancy and ships two workspaces:

| Tenant | Who | Purpose |
|---|---|---|
| `Global` | everyone | shared/default dashboards (Wazuh's own modules live here) |
| `soc` | analysts (RW), readonly group (R) | the SOC team's own saved objects |

Private per-user tenants are disabled deliberately (they fragment content and
complicate backups). Add a workspace by naming a new tenant in
`sso-groups.conf` — it is created automatically.

**Important:** a tenant separates *saved objects* (dashboards, visualizations,
saved searches), **not the data behind them**. Two teams in different tenants
still query the same alerts unless you also scope the data. For real
multi-organization separation combine all three columns:

| Goal | Mechanism | Column |
|---|---|---|
| separate dashboards/saved searches | tenant (workspace) | `tenant` |
| separate the alerts each team can query | document-level security (DLS) | `data_scope` |
| separate which agents a team can manage | Wazuh API roles scoped to `agent:group:<name>` | `api_roles` |

Example — a finance business unit that only ever sees its own agents:

```text
finance-soc|kibana_user|readonly|finance:RW|agent.name:fin-*
```

Verified behaviour (measured on this deployment, 1115 alerts total): a group
scoped to `agent.name:nonexistent-*` sees **0**; scoped to
`agent.name:docker-host*` it sees **184** — only that agent's alerts, while an
unscoped admin still sees all 1115.

⚠️ **DLS is additive across roles.** A scoped group must *not* also hold
`readall` or `all_access`, or it sees everything regardless of the filter —
`sso init` warns when that combination appears.

### The shipped map

| Keycloak group | Data (indexer roles) | Modules (Wazuh API roles) | Workspace |
|---|---|---|---|
| `siem-admins` | `all_access` | `administrator` — everything, incl. `mitre:read`, agents, rules, security config | `Global` RW |
| `siem-analysts` | `kibana_user`, `readall` | `readonly`, `agents_readonly`, `cluster_readonly` — read every module, change nothing | `soc` RW |
| `siem-readonly` | `kibana_user`, `readall` | `readonly` | `soc` read-only |

### Adding a team with its own permissions and workspace

```bash
# 1. create the group in Keycloak (Groups → New), add members
# 2. one line in config/sso-groups.conf:
#      compliance|kibana_user,readall|readonly|compliance:RW
# 3. apply (idempotent):
./wazuh-deploy.sh sso init          # or: python3 scripts/apply-sso-groups.py
python3 scripts/apply-sso-groups.py --dry-run    # preview without changing anything
# 4. members log out and back in
```

The building blocks you can put in each column are listed in the header of
`config/sso-groups.conf` (and enumerated live with
`GET /_plugins/_security/api/roles` on the indexer and `GET /security/roles`
on the Wazuh API).

**Why log out/in matters:** both the OIDC token and the Wazuh API run_as token
have their resolved roles minted **at login** (API tokens last ~15 min), so
permission changes never apply to an existing session.

The dashboard reaches the API as `wazuh-wui` with **run_as**, forwarding the
logged-in user's authentication context (`user_name`, `backend_roles`,
`roles`, `tenants`); the API rules match on `backend_roles`, i.e. the Keycloak
groups. Verify every layer at once with `./wazuh-deploy.sh sso status`.

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
| SSO login works but shows no data | indexer-side mapping missing — `./wazuh-deploy.sh sso status` should list indexer roles for the user |
| user lands in an empty workspace / can't save objects | no tenant access — give the group a `tenant` in `config/sso-groups.conf` and re-run `sso init` |
| changed a group mapping, nothing happened | log out and back in; roles are minted into both tokens at login |
