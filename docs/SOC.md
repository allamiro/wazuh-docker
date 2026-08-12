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

### IRIS SSO — via an OAuth2 proxy

**IRIS 2.4 does not speak OIDC natively.** Its `IRIS_AUTHENTICATION_TYPE`
accepts only `local` or `oidc_proxy`; in the latter it trusts an OAuth2 proxy
in front of it. The deployment ships with `local` so it boots cleanly, and the
Keycloak `iris` client is already created for when you switch. To enable:

```yaml
  iris-sso:                       # add to docker-compose.yml, profile: [ "soc" ]
    image: quay.io/oauth2-proxy/oauth2-proxy:v7.6.0
    environment:
      - OAUTH2_PROXY_PROVIDER=oidc
      - OAUTH2_PROXY_OIDC_ISSUER_URL=https://sso.siem.local.domain:8443/realms/siem
      - OAUTH2_PROXY_CLIENT_ID=iris
      - OAUTH2_PROXY_CLIENT_SECRET=${IRIS_OIDC_SECRET}
      - OAUTH2_PROXY_COOKIE_SECRET=<openssl rand -base64 32>
      - OAUTH2_PROXY_UPSTREAMS=http://iris-app:8000
      - OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180
      - OAUTH2_PROXY_EMAIL_DOMAINS=*
      - OAUTH2_PROXY_PROVIDER_CA_FILES=/etc/ssl/certs/siem-root-ca.pem
      - OAUTH2_PROXY_SET_XAUTHREQUEST=true
      - OAUTH2_PROXY_PASS_AUTHORIZATION_HEADER=true
```

then point the nginx `8082` vhost at `http://iris-sso:4180` and set
`IRIS_AUTH_TYPE=oidc_proxy` in `.env`. IRIS reads the group claim through
`OIDC_IRIS_APP_ADMIN_ROLE_NAME=siem-admins` (already set) to grant admin.

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
