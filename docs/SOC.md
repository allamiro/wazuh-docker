# SOC tier: MISP + DFIR-IRIS (optional `soc` profile)

Adds threat intelligence and case management next to Wazuh, all behind the
same CA and the same Keycloak realm.

```text
     Wazuh alert (level >= 10)                Wazuh alert (web/attack/auth)
              │                                          │
       custom-iris integration                   custom-misp integration
              │ POST /alerts/add                         │ IoC lookup
              ▼                                          ▼
        DFIR-IRIS  ── case, timeline, IoCs ──►      MISP  ── attributes, events
        :8082 TLS                                   :8081 TLS
              └──────────── Keycloak realm "siem" ────────┘
```

**Why these two:** TheHive 5 is commercial (StrangeBee) and TheHive 4 is
archived, so **DFIR-IRIS** is the open-source case-management replacement.
**MISP** remains the standard IoC store and works fully offline once seeded.
Cortex was deliberately left out: most of its analyzers call the internet, so
it adds little in an air gap.

## Enable

```bash
./wazuh-deploy.sh sso enable        # prerequisite - the SOC tier reuses the realm
./wazuh-deploy.sh soc enable        # secrets, realm clients, profile
./wazuh-deploy.sh pki csr && ./wazuh-deploy.sh pki sign   # misp + iris certs
docker compose up -d
./wazuh-deploy.sh soc init          # installs the Wazuh integrations, checks endpoints
```

DNS/hosts: `misp.<domain>` and `iris.<domain>` → host IP (`dns records`
includes them).

| Service | URL | First login |
|---|---|---|
| MISP | `https://misp.siem.local.domain:8081` | `MISP_ADMIN_EMAIL` / `MISP_ADMIN_PASSWORD` in `.env` |
| DFIR-IRIS | `https://iris.siem.local.domain:8082` | `administrator` / `IRIS_ADMIN_PASSWORD` in `.env` |

Resource note: this tier costs ~5 GB. To make room on a 32 GB host the cold
indexer tier was reduced to one node — it is a topology simulation on a single
disk anyway, and one node still exercises the ISM transition.

## Keycloak clients

`soc enable` renders both clients into the realm import, and they can also be
created directly against a running Keycloak (what `soc init` verifies):

| Client | Redirect URI | Secret |
|---|---|---|
| `misp` | `https://misp.<domain>:8081/*` | `MISP_OIDC_SECRET` in `.env` |
| `iris` | `https://iris.<domain>:8082/*` | `IRIS_OIDC_SECRET` in `.env` |

Both carry a **groups** mapper (`claim.name: groups`, full path off), so the
same `siem-admins` / `siem-analysts` / `siem-readonly` groups from
[`config/sso-groups.conf`](../multi-node/config/sso-groups.conf) drive
authorization here too.

To create or repair a client by hand:

```bash
source .env
KC=https://sso.siem.local.domain:8443
AT=$(curl -ks --cacert config/wazuh_indexer_ssl_certs/root-ca.pem \
  --resolve sso.siem.local.domain:8443:127.0.0.1 \
  -d client_id=admin-cli -d username=admin -d "password=$KEYCLOAK_ADMIN_PASSWORD" \
  -d grant_type=password "$KC/realms/master/protocol/openid-connect/token" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
# then POST the client JSON to $KC/admin/realms/siem/clients (see soc init)
```

### MISP SSO — native OIDC

MISP speaks OIDC directly; the container is configured through
`OIDC_*` environment variables, including a role mapping:

```
OIDC_ROLES_PROPERTY=groups
OIDC_ROLES_MAPPING={"siem-admins":"1","siem-analysts":"3","siem-readonly":"6"}
```

(MISP role ids: 1 admin, 3 user, 6 read-only.) Set `MISP_OIDC_ENABLE=false` in
`.env` to fall back to local MISP accounts.

### IRIS SSO — native OIDC (IRIS >= 2.4.27)

IRIS speaks OIDC directly from 2.4.27 onward: it runs the authorization-code
flow itself against Keycloak and no OAuth2 proxy is involved. The deployment
runs **v2.4.29** configured this way:

```yaml
  - IRIS_AUTHENTICATION_TYPE=oidc
  - OIDC_ISSUER_URL=https://sso.siem.local.domain:8443/realms/siem
  - OIDC_CLIENT_ID=iris
  - OIDC_CLIENT_SECRET=${IRIS_OIDC_SECRET}
  - OIDC_SCOPES=openid email profile
  - OIDC_MAPPING_USERNAME=preferred_username
  - OIDC_MAPPING_EMAIL=email
  - AUTHENTICATION_LOCAL_FALLBACK=True     # break-glass local login
  - TLS_ROOT_CA=/etc/ssl/certs/siem-root-ca.pem
```

The Keycloak redirect URI is **`/oidc-authorize`** — already registered for
the `iris` client in
[`config/sso-clients.conf`](../multi-node/config/sso-clients.conf). The login
page then shows an **SSO** link; users land back on `/dashboard` authenticated.

`AUTHENTICATION_LOCAL_FALLBACK=True` keeps the local `administrator` account
usable when Keycloak is unavailable — deliberate: SSO is a single point of
failure and this is the way back in.

**Users must still exist in IRIS.** Its documentation is explicit that for
local, LDAP *and* OIDC "users need to be declared in IRIS"; the platform
authenticates by lookup. Provision them with:

```bash
python3 scripts/iris-sync-users.py     # idempotent; re-run after adding people
```

### Upgrading IRIS (and what to change)

Version is a single variable, so an upgrade is a pull plus a recreate:

```bash
# connected side: pull and ship in the bundle
docker pull ghcr.io/dfir-iris/iriswebapp_app:v2.4.29
docker pull ghcr.io/dfir-iris/iriswebapp_db:v2.4.29
./wazuh-deploy.sh airgap bundle

# air-gapped side
./wazuh-deploy.sh airgap import /media/<bundle>
sed -i 's/^IRIS_VERSION=.*/IRIS_VERSION=v2.4.29/' .env   # or edit by hand
docker compose up -d --force-recreate iris-app iris-worker iris-db
```

Configuration changes that come with the versions:

| From → to | What changes | Action |
|---|---|---|
| ≤ 2.4.20 → ≥ 2.4.27 | native `oidc` auth type appears | set `IRIS_AUTH_TYPE=oidc` and the `OIDC_*` block above; delete any oauth2-proxy service and point the nginx `8082` vhost back at `iris-app:8000` |
| any | database schema migrations | run automatically by the app on first start — watch `docker compose logs -f iris-app` for alembic output before declaring the upgrade done |
| any | module versions | modules live in the image; after upgrading, `python3 scripts/iris-modules.py list` and re-apply configuration if a module reset (`configure-misp`) |

Roll back by setting `IRIS_VERSION` to the previous tag and recreating —
**but** database migrations are not reversible, so snapshot the `iris-db-data`
volume before a major upgrade:

```bash
docker run --rm -v multi-node_iris-db-data:/v -v "$PWD:/backup" \
  nginx:1.29-alpine tar czf /backup/iris-db-$(date +%F).tar.gz -C /v .
```

## Wazuh integrations

`soc init` installs two scripts into `/var/ossec/integrations` on the master;
the `<integration>` blocks live in the manager template, so they survive
config regeneration:

| Integration | Trigger | Effect |
|---|---|---|
| `custom-iris` | alerts at level ≥ 10 | creates an IRIS **alert** (title, severity mapped from the rule level, full alert JSON, source IoCs) ready to promote into a case |
| `custom-misp` | alerts in `web,attack,authentication_failed,sysmon` | looks up srcip/dstip/hashes/url in MISP; a hit is re-injected as a Wazuh event (`misp` group) so it is indexed and alertable |

Both talk only to the local containers, verify TLS against the deployment root
CA, and log failures to `/var/ossec/logs/integrations.log` without ever
blocking alert processing. Tune thresholds by editing the `<level>` / `<group>`
values in `config/templates/wazuh_manager.conf.tpl` and re-running
`generate-credentials.sh`-style rendering (secrets are injected from `.env`).

## IRIS modules (and how they survive the air gap)

Every module DFIR-IRIS ships is **already inside the container image** — so an
air-gapped deployment downloads nothing to use them. They only need enabling
and configuring:

| Module | Version | Purpose |
|---|---|---|
| `iris_misp_module` | 1.3.0 | enrich IOCs from MISP (manual right-click, or automatically on IOC create/update) |
| `iris_webhooks_module` | 1.0.8 | push IRIS events to Slack/Teams/SOAR webhooks |
| `iris_vt_module` | 1.2.1 | VirusTotal enrichment (internet-dependent — leave off in an enclave) |
| `iris_intelowl_module` | 0.1.0 | IntelOwl analysis |
| `iris_check_module` | 1.0.1 | logs every hook; useful to prove the module pipeline works |

```bash
python3 scripts/iris-modules.py list                    # what exists, what is on
python3 scripts/iris-modules.py configure-misp          # point IrisMISP at our MISP + enable
python3 scripts/iris-modules.py configure-webhook https://soar.internal/hook
python3 scripts/iris-modules.py enable  iris_check_module
python3 scripts/iris-modules.py disable iris_vt_module  # no internet in the enclave
docker compose restart iris-app iris-worker             # required after changes
```

`configure-misp` writes the module's JSON configuration (URL `https://misp`
on the internal network, TLS verified against the deployment CA) and turns on
enrichment for IOC create, IOC update and the manual right-click. It needs a
MISP API key: create one in MISP under **Administration → List Auth Keys →
Add**, then

```bash
echo 'MISP_API_KEY=<key>' >> .env
python3 scripts/iris-modules.py configure-misp
```

Once enabled, IOCs added to a case are enriched from MISP automatically —
which replaces most of what the Wazuh-side `custom-misp` integration does, and
puts the intel where the analyst is working. Keep both if you also want MISP
hits to become Wazuh alerts.

### Modules that are NOT in the image

Build the wheel on the connected staging host, ship it in the bundle, install
offline:

```bash
# connected side
git clone https://github.com/dfir-iris/iris-misp-module.git && cd iris-misp-module
python3 setup.py bdist_wheel
cp dist/*.whl <repo>/multi-node/airgap-cache/iris-modules/
./wazuh-deploy.sh airgap bundle          # carries airgap-cache/iris-modules/

# air-gapped side, after 'airgap import'
python3 scripts/iris-modules.py install airgap-cache/iris-modules/<file>.whl
docker compose restart iris-app iris-worker
```

`pip3 install --no-index` is used, so nothing reaches for an index.

### Report templates

IRIS generates DOCX/Markdown/HTML reports from templates, and the example
templates are downloads — so they are fetched on the connected side and
carried in the bundle:

```bash
./wazuh-deploy.sh fetch        # -> airgap-cache/iris-templates/
```

Upload them in IRIS under **Advanced → Templates** (investigation report and
activities report). Tags available to a template are listed at
`/case/export?cid=1` on your own instance — useful when tailoring the
document to your reporting standard.

## Troubleshooting (real issues hit during deployment)

| Symptom | Cause | Fix |
|---|---|---|
| MISP: every page *Internal Server Error*; log shows `RedisException: ERR AUTH called without any password configured` | MISP always authenticates to Redis, but the server had no password set | `misp-redis` now starts with `--requirepass` and MISP gets a matching `REDIS_PASSWORD` (both from `MISP_REDIS_PASSWORD` in `.env`) |
| MISP: 500 with `OpenIDConnectClientException: cURL error #60: SSL certificate problem` | PHP cURL could not verify Keycloak's TLS certificate - the deployment root CA was not in the container's system trust store | `scripts/misp-init.sh` installs the CA with `update-ca-certificates` before the stock entrypoint runs |
| IRIS: *An Internal Error Has Occurred*; log shows `RuntimeError: A secret key is required to use CSRF` | `configuration.py` assigns `SECRET_KEY` only when `IRIS_WORKER` is **absent** - even `IRIS_WORKER=0` skips the whole block | the variable is set only on `iris-worker`, never on `iris-app` |
| IRIS: 502; log shows `database "iris_db" does not exist` | the app crashed before its first-boot database initialisation could run | create it once: `docker exec iris-db createdb -U raccoon_admin -O raccoon iris_db` |
| IRIS: 502; log shows `function gen_random_uuid() does not exist` | a hand-created database lacks the `pgcrypto` extension the schema needs | `docker exec iris-db psql -U raccoon_admin -d iris_db -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'` |

## Operating notes

- MISP's first boot initializes its database and can take several minutes;
  `soc init` reports HTTP 500 until it finishes.
- Feeds: in an air gap, load MISP feeds from files/media
  (**Sync Actions → Feeds → Add**, `local` input) rather than remote URLs.
- IRIS API key for automation is `IRIS_API_KEY` in `.env` (used by the
  integration).
- Back up the `misp-*` and `iris-*` volumes alongside the Wazuh ones.
