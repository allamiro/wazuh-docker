# Air-gapped Wazuh multi-node deployment guide

**Branch:** `airgp` · **Wazuh:** 4.14.7 (latest published stable) · **Public name:** `https://siem.local.domain`

This guide walks through deploying a hardened, enterprise-topology Wazuh stack
with Docker Compose on a **single 32 GB RAM server inside an air-gapped
network**, with every TLS certificate signed by an **external CA**.

---

## 1. Architecture

```
                                agents / users
                                      │
                   DNS: siem.local.domain ──► docker host
        ┌─────────────────┬───────────┴──────────┬────────────────┐
        │ 443/tcp (HTTPS) │ 1514/tcp (events)    │ 1515/tcp (enroll)
        ▼                 ▼                      ▼
  wazuh.dashboard   nginx (stream LB) ──► wazuh.master:1515
        │                 │
        │            ┌────┴─────────────────────────────┐
        │            ▼                                   ▼
        │      wazuh.master ◄── cluster (1516) ──► wazuh.worker1..4
        │            │  Filebeat                        │  Filebeat
        │            └──────────────┬───────────────────┘
        ▼                           ▼
  coord1-2.indexer            ingest1-2.indexer
   (query fan-out)             (bulk ingestion)
        └──────────────┬────────────┘
                       ▼
   ┌───────────────────────────────────────────────┐
   │  OpenSearch cluster  "wazuh-cluster"          │
   │  master1-3.indexer   dedicated cluster mgrs   │
   │  hot1-3.indexer      data  (node.attr.temp=hot)│
   │  warm1-3.indexer     data  (node.attr.temp=warm)│
   │  cold1-3.indexer     data  (node.attr.temp=cold)│
   └───────────────────────────────────────────────┘
```

### Node inventory (23 containers)

| Container | Role | Count |
|---|---|---|
| `master1-3.indexer` | Dedicated cluster managers — cluster state, quorum of 3 | 3 |
| `hot1-3.indexer` | Hot-tier data nodes — new indices are written here | 3 |
| `warm1-3.indexer` | Warm-tier data nodes — indices older than 7 days | 3 |
| `cold1-3.indexer` | Cold-tier data nodes — indices older than 30 days, read-only | 3 |
| `ingest1-2.indexer` | Dedicated ingest nodes — Filebeat bulk traffic lands here | 2 |
| `coord1-2.indexer` | Dedicated coordinating nodes — dashboard queries fan out from here | 2 |
| `wazuh.master` | Wazuh server master — agent enrollment (authd), cluster sync, API | 1 |
| `wazuh.worker1-4` | Wazuh server workers — agent event processing | 4 |
| `wazuh.dashboard` | Wazuh dashboard (HTTPS on 443) | 1 |
| `nginx` | TCP stream load balancer for agent traffic | 1 |

Two topology facts worth knowing:

- **The Wazuh server cluster allows exactly one master.** "Three masters" in
  the Elastic sense lives on the indexer side: the three dedicated
  `cluster_manager` nodes. The Wazuh master is a singleton by protocol design;
  if it fails, workers keep receiving and forwarding events, but enrollment
  and centralized config pause until it returns.
- **OpenSearch has no `data_hot`/`data_warm`/`data_cold` roles** (that is
  Elasticsearch). The equivalent mechanism — used here — is a custom node
  attribute (`node.attr.temp: hot|warm|cold`) plus an ISM policy that moves
  indices between tiers by age (section 8).

### Why hot/warm/cold on one host?

On a single server this is a **topology simulation** — the tiers share the
same disk, so there is no hardware benefit yet. The value is that the
configuration is *production-shaped*: when you later split it across real
hardware (NVMe hot boxes, HDD cold boxes), only the compose placement changes,
not the cluster design, certificates, or ISM policies.

---

## 2. Requirements

- Linux server (or Docker Desktop for a lab), **32 GB RAM**, 8+ CPU cores,
  fast disk (the indexer tiers all live on it).
- Docker Engine 24+ with Docker Compose v2.
- Kernel setting on the host (required by OpenSearch):
  ```bash
  sudo sysctl -w vm.max_map_count=262144
  echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf
  ```
- DNS: `siem.local.domain` must resolve to this host inside your network
  (internal DNS zone, or `/etc/hosts` on every agent/client:
  `10.0.0.X  siem.local.domain`).

### Memory budget (32 GB host)

Limits are *ceilings*, not reservations; the JVM heaps are the committed part.
Steady-state RSS for the whole stack is ≈ 19–22 GB, leaving headroom for the
OS page cache (which OpenSearch relies on heavily).

| Service | Heap (`Xms=Xmx`) | Container limit | × | Limit total |
|---|---|---|---|---|
| master1-3.indexer | 512 MB | 1 GB | 3 | 3 GB |
| hot1-3.indexer | 1.5 GB | 3 GB | 3 | 9 GB |
| warm1-3.indexer | 1 GB | 2 GB | 3 | 6 GB |
| cold1-3.indexer | 768 MB | 1.5 GB | 3 | 4.5 GB |
| ingest1-2.indexer | 512 MB | 1 GB | 2 | 2 GB |
| coord1-2.indexer | 512 MB | 1 GB | 2 | 2 GB |
| wazuh.master, worker1-4 | n/a (C daemons) | 1.5 GB | 5 | 7.5 GB |
| wazuh.dashboard | n/a (Node.js) | 1.5 GB | 1 | 1.5 GB |
| nginx | n/a | 256 MB | 1 | 0.25 GB |
| **Total** | **≈ 13.25 GB heap** | | | **≈ 35.75 GB caps** |

Every value is overridable in `.env` (`IDX_HOT_HEAP`, `MANAGER_MEM_LIMIT`, …).
If your host also runs other services, shrink the warm/cold tier first.

---

## 3. Air-gap transfer

On a connected machine:

```bash
# 1. Pull the exact pinned images
docker pull wazuh/wazuh-manager:4.14.7
docker pull wazuh/wazuh-indexer:4.14.7
docker pull wazuh/wazuh-dashboard:4.14.7
docker pull nginx:1.29-alpine
docker pull smallstep/step-ca:latest        # only needed for CA_MODE=step

# 2. Export them (~5 GB total)
docker save -o wazuh-airgap-images.tar \
  wazuh/wazuh-manager:4.14.7 wazuh/wazuh-indexer:4.14.7 \
  wazuh/wazuh-dashboard:4.14.7 nginx:1.29-alpine smallstep/step-ca:latest

# 3. Clone this branch
git clone -b airgp https://github.com/allamiro/wazuh-docker.git
```

Move `wazuh-airgap-images.tar` + the repo across the air gap (approved media),
then on the target host:

```bash
docker load -i wazuh-airgap-images.tar
cd wazuh-docker/multi-node
```

Nothing else in this deployment reaches out to the internet. Vulnerability
detection is **disabled by default** in the manager templates because it needs
the online Wazuh CTI feed; re-enable it in
`config/templates/wazuh_manager.conf.tpl` only if you operate an internal
feed mirror.

---

## 4. Certificates — the external CA workflow

### 4.1 Inventory: what gets created and why

**23 certificates total: 1 root CA + 22 leaf certificates** (each leaf with
its own private key). All leaf certs: RSA-2048, SHA-256, `serverAuth` +
`clientAuth`, subject `CN=<name>` and DNS SANs; root CA: RSA-4096, 10 years.

| # | Certificate (CN) | Used by | Purpose | Extra SANs |
|---|---|---|---|---|
| 1 | `SIEM Root CA (siem.local.domain)` | everyone | Trust anchor; signs all below | — |
| 2-4 | `master1-3.indexer` | indexer | TLS for transport (9300) + REST (9200) | `masterN.siem.local.domain` |
| 5-7 | `hot1-3.indexer` | indexer | same | `hotN.siem.local.domain` |
| 8-10 | `warm1-3.indexer` | indexer | same | `warmN.siem.local.domain` |
| 11-13 | `cold1-3.indexer` | indexer | same | `coldN.siem.local.domain` |
| 14-15 | `ingest1-2.indexer` | indexer | same | `ingestN.siem.local.domain` |
| 16-17 | `coord1-2.indexer` | indexer | same | `indexer.siem.local.domain` |
| 18 | `admin` | securityadmin CLI | Client cert with security-admin power (matches `plugins.security.authcz.admin_dn`) | — |
| 19 | `wazuh.master` | manager | Filebeat→indexer client cert **and** authd server cert for agent enrollment on 1515 | `siem.local.domain`, `manager.siem.local.domain` |
| 20-23 | `wazuh.worker1-4` | managers | Filebeat→indexer client certs | — |
| 24* | `wazuh.dashboard` | dashboard | HTTPS server cert browsers see on 443 | `siem.local.domain`, `dashboard.siem.local.domain`, `localhost` |

\* numbering: 22 leaf entries, rows 2–17 are 16 indexer certs.

The indexer configs pin identities by DN: `plugins.security.nodes_dn` lists
the 16 indexer CNs (only holders of those certs may join the cluster), and
`plugins.security.authcz.admin_dn: CN=admin` grants security-admin rights to
the admin cert alone. If you rename nodes, those lists must match.

### 4.2 Option A — bundled CA (default)

`generate-certs.sh` creates the root CA and performs the full
**key → CSR → CA-signs-CSR** cycle for every component. Two engines:

```bash
./generate-certs.sh                    # CA_MODE=step: runs everything inside
                                       # the smallstep/step-ca container
CA_MODE=openssl ./generate-certs.sh    # pure openssl on the host, no image
```

Both produce identical layouts:

```
config/certs-ca/root-ca.key            ← the CA. chmod 600. NOT needed at runtime.
config/certs-ca/root-ca.pem
config/wazuh_indexer_ssl_certs/        ← mounted into containers
├── root-ca.pem
├── <name>.pem / <name>-key.pem        (22 pairs)
└── csr/<name>.csr                     (kept for re-issuance/audit)
```

The script is idempotent (skips existing certs) and ends by verifying every
leaf against the CA and printing its SANs. Move `config/certs-ca/` offline
(encrypted USB, vault) once certs are issued — the stack never reads it.

### 4.3 Option B — a real external / corporate CA (recommended for production)

This is the exact flow to have certificates signed by the CA your
organization already trusts (Microsoft ADCS, EJBCA, a step-ca server, …):

```bash
# 1. Generate keys + CSRs only. Private keys NEVER leave this host.
GENERATE_CSR_ONLY=yes ./generate-certs.sh
#    → 22 CSRs in config/wazuh_indexer_ssl_certs/csr/

# 2. Submit the CSRs to your CA and request a profile with BOTH
#    "TLS server auth" and "TLS client auth" EKUs, preserving the CSR's
#    CN and SANs. (indexer nodes and Filebeat authenticate as clients too —
#    server-only certs WILL break indexer transport.)
#    Examples:
#      ADCS:    certreq -submit -attrib "CertificateTemplate:WazuhNode" hot1.indexer.csr
#      step-ca: step ca sign hot1.indexer.csr hot1.indexer.pem
#      openssl CA: openssl ca -in hot1.indexer.csr -extensions server_client_ext ...
# 3. Drop the signed certs back, keeping the exact file names:
#      config/wazuh_indexer_ssl_certs/<name>.pem
#    and your CA chain as:
#      config/wazuh_indexer_ssl_certs/root-ca.pem   (root, or root+intermediate bundle)
# 4. Verify before starting anything:
openssl verify -CAfile config/wazuh_indexer_ssl_certs/root-ca.pem \
    config/wazuh_indexer_ssl_certs/*.indexer.pem
```

If your CA issues from an **intermediate**, concatenate
`intermediate.pem + root.pem` into `root-ca.pem`, and append the intermediate
to each leaf `.pem` (leaf first, then intermediate).

### 4.4 How the certs attach to each service

You don't need to configure anything manually — the compose file mounts them —
but for review/audit this is the mapping:

| Service | Cert material inside the container | Config that points at it |
|---|---|---|
| every indexer | `/usr/share/wazuh-indexer/config/certs/{node}.pem,.key,root-ca.pem}` | `plugins.security.ssl.{http,transport}.*` in its `opensearch.yml` |
| `master1.indexer` (only) | `admin.pem`, `admin-key.pem` | used by `securityadmin.sh` runs |
| managers | `/etc/ssl/{filebeat.pem,filebeat.key,root-ca.pem}` | Filebeat output TLS (`FILEBEAT_SSL_VERIFICATION_MODE=full`) |
| `wazuh.master` | `/var/ossec/etc/sslmanager.{cert,key}` (same cert) | authd — agents can verify the manager during enrollment |
| dashboard | `/usr/share/wazuh-dashboard/certs/…` | `server.ssl.*` + `opensearch.ssl.certificateAuthorities` |

### 4.5 Renewal

Leaf certs default to 825 days (`CERT_DAYS`). To renew: delete the expiring
`<name>.pem` (keep the key or regenerate — the script recreates missing keys),
re-run `./generate-certs.sh` (or the CSR-only flow), then restart the affected
container: `docker compose restart <service>`. Rolling restarts of indexer
nodes are safe — the cluster stays green if you go one node at a time.

---

## 5. Credentials

```bash
./generate-credentials.sh
```

Generates and installs, in one shot:

| Secret | Where it lands |
|---|---|
| indexer `admin` password | `.env` → compose env; bcrypt hash → `internal_users.yml` |
| `kibanaserver` password | `.env`; bcrypt hash → `internal_users.yml` |
| Wazuh API `wazuh-wui` password | `.env`; plaintext → `config/wazuh_dashboard/wazuh.yml` (dashboard→API login) |
| Wazuh cluster key (32 hex) | rendered into `wazuh_manager.conf` + `wazuh_worker1-4.conf` |
| agent enrollment password | `config/wazuh_cluster/authd.pass` |

Details that matter:

- Hashes are produced with the **indexer image's own `hash.sh`** (bcrypt), so
  no extra tooling is needed on the air-gapped host.
- The upstream **demo users are removed** (`kibanaro`, `logstash`, `readall`,
  `snapshotrestore`) — only `admin` and `kibanaserver` exist.
- Everything generated is **gitignored**: `.env` (chmod 600), rendered
  configs, `authd.pass`, all certs and the CA. Nothing secret can be pushed.
- `--force` regenerates from scratch — on a *live* stack that locks services
  out until you wipe the security index, so treat it as a rebuild step.

---

## 6. Deploy

```bash
docker compose up -d          # first boot takes 3-6 minutes
```

Boot order (enforced via healthchecks): the 16 indexer nodes come up in
parallel and elect a cluster manager → security index initializes from
`internal_users.yml` → `wazuh.master` starts once `ingest1` is healthy →
workers join the master → dashboard starts once `coord1` is healthy.

### Verify

```bash
source .env

# 1. All 23 containers Up, indexers healthy
docker compose ps

# 2. Cluster formed: 16 nodes, green
curl -ks -u "admin:$INDEXER_PASSWORD" https://127.0.0.1:9200/_cluster/health?pretty
# expect: "status":"green", "number_of_nodes":16

# 3. Node roles landed as designed
curl -ks -u "admin:$INDEXER_PASSWORD" \
  "https://127.0.0.1:9200/_cat/nodes?v&h=name,node.roles,attr.temp,heap.max&s=name"

# 4. Wazuh server cluster: master + 4 workers connected
docker exec wazuh.master /var/ossec/bin/cluster_control -l

# 5. Alerts flowing into the hot tier
curl -ks -u "admin:$INDEXER_PASSWORD" "https://127.0.0.1:9200/_cat/indices/wazuh-*?v"

# 6. Dashboard
curl -k -I https://siem.local.domain/   # or https://localhost if DNS not set yet
```

Log in at `https://siem.local.domain` with `admin` / `$INDEXER_PASSWORD`.
Your browser trusts it once you import `config/certs-ca/root-ca.pem`
(or your corporate root) into the OS/browser trust store.

---

## 7. Agent enrollment

Agents need **only two things**: the name `siem.local.domain` and the
enrollment password.

```bash
# on the agent host (Linux example, 4.14.x agent already installed offline)
WAZUH_MANAGER=siem.local.domain \
WAZUH_REGISTRATION_SERVER=siem.local.domain \
WAZUH_REGISTRATION_PASSWORD='<contents of config/wazuh_cluster/authd.pass>' \
  dpkg -i wazuh-agent_4.14.7-1_amd64.deb   # or configure ossec.conf manually
systemctl enable --now wazuh-agent
```

Flow: enrollment hits `siem.local.domain:1515` → nginx forwards to the
master's authd (password-protected, CA-signed cert). Event traffic hits
`:1514` → nginx balances it across master + 4 workers with source-IP
affinity. To make agents *verify* the manager cert, drop `root-ca.pem` on the
agent and set `<server-ca-path>` in the agent's `ossec.conf`.

---

## 8. Hot / warm / cold lifecycle (ISM)

Apply the shipped policy once after first boot:

```bash
source .env
curl -ks -u "admin:$INDEXER_PASSWORD" -X PUT \
  "https://127.0.0.1:9200/_plugins/_ism/policies/wazuh-hot-warm-cold" \
  -H 'Content-Type: application/json' \
  -d @config/ism/wazuh-hot-warm-cold-policy.json
```

What it does to every `wazuh-alerts-*` / `wazuh-archives-*` index:

| Age | State | Placement | Actions |
|---|---|---|---|
| 0–7 d | hot | `hot1-3` | — |
| 7–30 d | warm | `warm1-3` | force-merge to 1 segment, lower priority |
| 30–90 d | cold | `cold1-3` | read-only |
| 90 d | delete | — | index deleted |

The policy auto-attaches to **new** daily indices (via `ism_template`).
Adjust the ages/retention to your compliance needs before applying. To pin
*new* indices to the hot tier from the moment of creation, also set the
allocation attribute in the Wazuh index template — not required, the hot
state's allocation action handles it within seconds of attachment.

---

## 9. Load balancing & TLS termination — "do we put nginx in front?"

Three kinds of traffic, three answers:

1. **Agent TCP (1514/1515)** — yes, and it's already there: the nginx
   `stream` (L4) block is the single `siem.local.domain` entry point.
   Wazuh's agent protocol is its own encrypted TCP protocol (AES, pre-shared
   keys) — it is *not* TLS you can terminate; only L4 balancing is valid.
2. **Dashboard HTTPS (443)** — this stack exposes the dashboard **directly**,
   with its CA-signed `siem.local.domain` cert: fewer moving parts and
   end-to-end TLS. Putting nginx in front as an L7 terminating proxy is a
   legitimate alternative when you need WAF rules, client-cert auth for
   operators, or several UIs behind one IP — issue the `siem.local.domain`
   cert to nginx instead and re-encrypt upstream (`proxy_pass https://wazuh.dashboard:5601`
   with `proxy_ssl_trusted_certificate root-ca.pem; proxy_ssl_verify on;`).
   Do **not** terminate and forward plaintext.
3. **Indexer REST (9200)** — never exposed beyond `127.0.0.1`. The
   coordinating nodes *are* the internal load-balancing layer; external LBs
   have no business here.

---

## 10. Security posture (what's hardened vs upstream)

- **No default passwords anywhere** — upstream ships `SecretPassword`,
  `kibanaserver`, a public cluster key; here everything is generated, and
  compose refuses to start without `.env` (`:?` interpolation guards).
- **Single external root CA**; full-chain verification everywhere:
  Filebeat→indexer `full`, dashboard→indexer `verificationMode: full`,
  indexer transport `enforce_hostname_verification: true` (all stricter than
  upstream defaults).
- **TLS 1.3/1.2 only**, AEAD ciphers only.
- **Node identity pinning** via `nodes_dn` (16 CNs) + `admin_dn`.
- **Minimal exposure**: 443, 1514, 1515 public; 9200 and 55000 bound to
  `127.0.0.1`; indexer transport (9300) and Wazuh cluster (1516) never leave
  the `siem` bridge network. Syslog 514 not exposed (add it deliberately if
  you must ingest device syslog; prefer agents).
- **Enrollment hardened**: authd requires a password and presents a CA-signed
  cert; demo indexer users removed; dashboard cookies TLS-only, 15-min
  session TTL.
- **Secrets never in git** — `.gitignore` covers `.env`, certs, CA, rendered
  configs; templates carry placeholders only.

Residual risks to manage operationally: protect `config/certs-ca/root-ca.key`
(move offline), protect `.env` and `authd.pass` file permissions, and put the
Docker host itself under Wazuh monitoring (install an agent on it).

---

## 11. Operations

- **Logs**: `docker compose logs -f <service>`.
- **Backup**: the indexer data volumes (`indexer-data-*`), the manager `etc`/
  `queue` volumes, `.env`, `config/` (includes certs), and the offline CA key.
  Snapshot repositories can be added later via a mounted `path.repo`.
- **Restart a tier**: `docker compose restart warm1.indexer` — one node at a
  time keeps the cluster green (replicas live on the other two tier members).
- **Password rotation**: edit `.env` + re-hash into `internal_users.yml`
  (`generate-credentials.sh --force` rebuilds all; then
  `docker compose up -d` to recreate, and re-run securityadmin or wipe the
  security index so new hashes load).
- **Scaling out to real hardware**: this compose is one file per host away —
  split services across hosts, switch `network.host`/`discovery.seed_hosts`
  to real FQDNs (`hot1.siem.local.domain` — already in the certs' SANs!), and
  keep the same certs/CA. That SAN planning is deliberate.

## 12. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| indexer exits with `memory locking requested ... but memory is not locked` | remove `bootstrap.memory_lock` or raise memlock ulimit (already `-1` in compose; some hosts need `default-ulimits` in daemon.json) |
| indexer: `max virtual memory areas vm.max_map_count [65530] is too low` | set `vm.max_map_count=262144` on the **host** (section 2) |
| `Not initialized` from `/_plugins/_security/health` for >5 min | cluster couldn't form quorum — check `docker logs master1.indexer` for discovery errors |
| Filebeat: `x509: certificate signed by unknown authority` | `root-ca.pem` mounted into the manager doesn't match the CA that signed the indexer certs (mixed old/new cert dirs — regenerate all) |
| Filebeat: certificate valid for X, not ingest1.indexer | cert/SAN mismatch — cert files renamed or issued without SANs (external CA stripped them; re-issue with SANs preserved) |
| dashboard: `self signed certificate in certificate chain` | same root-ca mismatch, dashboard side |
| agents can't enroll | wrong enrollment password (`authd.pass`), or 1515 blocked between agent and host |
| cluster yellow after a tier restart | normal while replicas re-sync; watch `_cluster/health` |
