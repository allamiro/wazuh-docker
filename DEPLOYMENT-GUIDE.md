# Air-gapped Wazuh multi-node deployment guide

**Branch:** `airgp` · **Wazuh:** 4.14.7 (latest published stable) · **Public name:** `https://siem.local.domain`

This guide walks through deploying a hardened, enterprise-topology Wazuh stack
inside an **air-gapped network**, with every TLS certificate signed by an
**external CA** through an explicit PKI lifecycle:

```text
private key → CSR → CA signing → signed certificate → import → verification → deploy
```

The PKI layer is deployment-agnostic: the same certificates serve the Docker
Compose stack (model A) or a fleet of VMs/bare-metal servers (model B).

---

## 0. Choosing your path

```text
                        START
                          │
               Is the network connected?
                   /              \
                 YES              NO
                  │                │
             Connected          Air-gap
                  │                │
   ./wazuh-deploy.sh fetch    bundle on a connected host,
                  │           ./wazuh-deploy.sh airgap import
                  └───────┬────────┘
                          │
                   Deployment type?
                    /           \
                 Docker       VM/Bare metal
                    │             │
                 Compose       Native packages
                    │             │
                    └─────┬───────┘
                          │
                         PKI  (one-shot when connected,
                          │    staged csr→sign→import when air-gapped)
                          │
              ./wazuh-deploy.sh validate
                          │
              ./wazuh-deploy.sh deploy <platform>
                          │
              ./wazuh-deploy.sh verify
```

Everything is driven by one CLI — `multi-node/wazuh-deploy.sh` — configured
once via `./wazuh-deploy.sh configure` (interactive, or flags for
automation). It orchestrates the underlying single-purpose tools
(`generate-credentials.sh`, `generate-certs.sh`, `deploy-certs.sh`, the
pinned `docker-compose.yml`), which all remain usable directly.

### Quick Start A — Connected + Docker

```bash
cd multi-node
./wazuh-deploy.sh configure          # connected + docker + bundled CA
./generate-credentials.sh
./wazuh-deploy.sh fetch
./wazuh-deploy.sh certificates      # one-shot PKI
./wazuh-deploy.sh deploy docker
./wazuh-deploy.sh verify
```

### Quick Start B — Connected + VM/bare metal

```bash
cd multi-node
./wazuh-deploy.sh configure          # connected + baremetal; set IPs in config/nodes.yml
./generate-credentials.sh
./wazuh-deploy.sh fetch              # pinned deb/rpm packages
./wazuh-deploy.sh certificates
./wazuh-deploy.sh deploy baremetal   # per-node dist/ packages → install.sh on each node
```

### Quick Start C — Air-gapped + Docker

```bash
# connected staging host:
./wazuh-deploy.sh configure --non-interactive --environment airgap --platform docker
./wazuh-deploy.sh fetch && ./wazuh-deploy.sh airgap bundle
# air-gapped target (after media transfer):
./wazuh-deploy.sh airgap import /media/wazuh-airgap-4.14.7
./generate-credentials.sh
./wazuh-deploy.sh pki csr && ./wazuh-deploy.sh pki sign --ca step
./wazuh-deploy.sh pki verify
./wazuh-deploy.sh deploy docker && ./wazuh-deploy.sh verify
```

### Quick Start D — Air-gapped + VM/bare metal

```bash
# as C, but: --platform baremetal (bundle then also carries deb/rpm packages)
./wazuh-deploy.sh airgap import /media/wazuh-airgap-4.14.7
./generate-credentials.sh
./wazuh-deploy.sh pki csr
./wazuh-deploy.sh pki export-csr     # corporate offline CA … pki import <dir>
./wazuh-deploy.sh pki verify
./wazuh-deploy.sh deploy baremetal   # then per node: install.sh + verify.sh
```

Mode walkthroughs: [docs/CONNECTED.md](docs/CONNECTED.md) ·
[docs/AIRGAP.md](docs/AIRGAP.md) · [docs/DOCKER.md](docs/DOCKER.md) ·
[docs/BAREMETAL.md](docs/BAREMETAL.md) · deep PKI: [docs/PKI.md](docs/PKI.md)

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

Topology facts worth knowing:

- **The Wazuh server cluster allows exactly one master.** "Three masters" in
  the Elastic sense lives on the indexer side: the three dedicated
  `cluster_manager` nodes.
- **OpenSearch has no `data_hot`/`data_warm`/`data_cold` roles** (that is
  Elasticsearch). The equivalent mechanism — used here — is a custom node
  attribute (`node.attr.temp`) plus an ISM policy that moves indices between
  tiers by age (section 10).
- On a single host the tier split is a **topology simulation**: the value is a
  production-shaped configuration that later splits across real hardware
  without redesign.

### What is TLS here — and what is not

Understanding which channels use X.509 drives the whole certificate design:

| Channel | Port | Security mechanism | X.509 identity |
|---|---|---|---|
| Indexer transport (node↔node) | 9300 | **mutual TLS** | each indexer's own cert (serverAuth+clientAuth) |
| Indexer REST (Filebeat, dashboard, admin) | 9200 | TLS + basic auth | same indexer cert (server side) |
| Filebeat → indexer | 9200 | TLS client | each manager's Filebeat cert |
| Dashboard HTTPS | 443 | TLS server | `wazuh.dashboard` cert |
| Wazuh API | 55000 | TLS server | `wazuh.master-api` cert (**without it the API self-signs!**) |
| Agent enrollment (authd) | 1515 | TLS server | `wazuh.master-enrollment` cert |
| Wazuh manager cluster (master↔workers) | 1516 | **shared 32-char cluster key** — *not* X.509 | none, by design |
| Agent events | 1514 | Wazuh agent protocol (pre-shared AES keys) — *not* X.509 | none, by design |

Consequences: the manager cluster and agent traffic need **no certificates**;
the master carries **three separate identities** (Filebeat client, API server,
enrollment server) instead of one certificate doing three jobs; and every
X.509 identity needs its **own private key + signed certificate** — the CSR
exists only during issuance and is never consumed at runtime.

---

## 2. Requirements

- Linux server (or Docker Desktop for a lab), **32 GB RAM**, 8+ CPU cores,
  fast disk.
- Docker Engine 24+ with Docker Compose v2.
- Kernel setting on the host (required by OpenSearch):
  ```bash
  sudo sysctl -w vm.max_map_count=262144
  echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf
  ```

### Memory budget (32 GB host)

Limits are *ceilings*, not reservations; the JVM heaps are the committed part.
Steady-state RSS for the whole stack is ≈ 19–23 GB, leaving headroom for the
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

### Performance tuning (all in `.env`)

Every tier is tunable without touching the compose file — `generate-credentials.sh`
seeds `.env` with the defaults; edit and `docker compose up -d`:

| Variable family | Meaning | Notes |
|---|---|---|
| `IDX_<TIER>_HEAP` | JVM max heap (`-Xmx`) per indexer tier (`MASTER/HOT/WARM/COLD/INGEST/COORD/ML`) | keep ≤ 50 % of the tier's memory limit |
| `IDX_<TIER>_HEAP_MIN` | JVM min heap (`-Xms`) | defaults to the max — recommended; set lower only if you must overcommit |
| `IDX_<TIER>_MEM_LIMIT` | container memory ceiling | |
| `IDX_<TIER>_CPU_SHARES` | relative CPU priority under contention | defaults prioritise the busy tiers: hot 2048, ingest 1536, ml 1024, warm 768, others 512 |
| `MANAGER_MEM_LIMIT`, `DASHBOARD_MEM_LIMIT`, `RUSTFS_MEM_LIMIT` | non-JVM services | |

`cpu_shares` only bites when CPUs are saturated — idle tiers still use spare
cycles. The hot and ingest tiers do most of the work (all new writes + queries
over recent data), which is why they get the highest weight.

### Optional dedicated ML node

Wazuh itself ships no machine-learning component, but the bundled indexer
(OpenSearch 2.19) includes the `opensearch-ml` plugin, which supports
dedicated ML nodes. An optional `ml1.indexer` container (`node.roles: [ml]`,
its own certificate, trusted in `nodes_dn`) runs ML workloads — e.g. anomaly
detectors over `wazuh-alerts-*` — without stealing resources from the data
tiers:

```bash
COMPOSE_PROFILES=ml docker compose up -d     # or add "ml" to COMPOSE_PROFILES in .env
```

Tune with `IDX_ML_HEAP` / `IDX_ML_MEM_LIMIT` / `IDX_ML_CPU_SHARES`.

---

## 3. DNS and hostnames

Agents and users reach the stack only through DNS names, and the certificates
pin those names — so name resolution must be in place **before** enrollment
and browsing work. The DNS suffix is configurable: set `SIEM_DOMAIN` when
generating CSRs (default `siem.local.domain`); VM deployments typically use a
real internal zone such as `siem.internal`.

### Model A — Docker single host

Only `siem.local.domain` (and optionally `dashboard.` / `manager.` /
`indexer.` aliases) must resolve to the Docker host. Container-to-container
names (`hot1.indexer`, `wazuh.master`, …) are resolved by Docker's internal
DNS automatically.

**Linux clients / agents (`/etc/hosts`):**

```bash
echo "10.0.0.50  siem.local.domain dashboard.siem.local.domain manager.siem.local.domain" \
  | sudo tee -a /etc/hosts        # replace 10.0.0.50 with the Docker host IP
```

**Windows clients (as Administrator):**

```powershell
Add-Content C:\Windows\System32\drivers\etc\hosts `
  "10.0.0.50  siem.local.domain dashboard.siem.local.domain"
```

**External Windows AD DNS (recommended — and assumed for domain-joined
air-gapped estates)**: the DNS zone and the CA live on Windows servers
*outside* the Wazuh VM. Everything is parameterized in
`config/deployment.yml` (`dns.mode`, `dns.server`, `dns.host_ip`,
`pki.adcs_template`) — update them any time and regenerate:

```bash
./wazuh-deploy.sh dns records
# -> config/dns/add-dns-records.ps1   run on the Windows DNS server: creates the
#                                     zone if needed and adds/updates EVERY record
#                                     (idempotent - safe to re-run after IP changes)
# -> config/dns/hosts.snippet         hosts-file fallback for clients without DNS
```

One host = one IP, many hostnames: in Docker mode every record
(`siem.local.domain`, `dashboard.`, `manager.`, `indexer.`, `s3.`, per-node
names) points at `dns.host_ip`; in bare-metal mode each node record uses its
IP from `config/nodes.yml`.

Or create the core records manually on a domain controller:

```powershell
Add-DnsServerPrimaryZone -Name "siem.local.domain" -ReplicationScope "Forest"
Add-DnsServerResourceRecordA -ZoneName "siem.local.domain" -Name "@"        -IPv4Address 10.0.0.50
Add-DnsServerResourceRecordA -ZoneName "siem.local.domain" -Name "dashboard" -IPv4Address 10.0.0.50
Add-DnsServerResourceRecordA -ZoneName "siem.local.domain" -Name "manager"   -IPv4Address 10.0.0.50
```

(BIND equivalent: a zone file for `siem.local.domain` with `@`, `dashboard`,
`manager` A records pointing at the host.)

### Model B — VMs / bare metal

Every node name in the certificate inventory must resolve to its server —
create one A record per node in AD DNS / BIND, e.g.:

```powershell
Add-DnsServerResourceRecordA -ZoneName "siem.internal" -Name "master1" -IPv4Address 10.0.1.11
Add-DnsServerResourceRecordA -ZoneName "siem.internal" -Name "hot1"    -IPv4Address 10.0.1.21
# ... one per indexer / manager / dashboard node
```

or, without a DNS server, the same list in **every** node's `/etc/hosts`.
Generate the CSRs with the matching suffix: `SIEM_DOMAIN=siem.internal
./generate-certs.sh csr` — the SANs then contain the real FQDNs
(`master1.siem.internal`, …) that TLS peers actually connect to.

### Transitioning commercial → air-gapped (external Windows DNS + ADCS)

The clean cutover order when a connected pilot moves into the enclave with
its own AD DNS + ADCS PKI:

1. **Bundle on the connected side** — `fetch` + `airgap bundle`; transfer.
2. **Import on the enclave host** — `airgap import`; re-run `configure` with
   the enclave's values (`--dns ad --dns-server <DC> --host-ip <VM IP>
   --ca external --adcs-template <template>` — all stored in
   `deployment.yml` for later edits).
3. **DNS first** — `dns records`, run `add-dns-records.ps1` on the Windows
   DNS server; confirm the domain-joined VM resolves `siem.local.domain`.
4. **Re-issue certificates from ADCS** — the existing private keys and CSRs
   are reusable: `pki export-csr` (includes a ready `submit-csrs.ps1`
   certreq script), sign on the CA side, then
   `pki import <dir>` with the ADCS-issued certs + the enterprise chain as
   `root-ca.pem`. The verify gate confirms SANs/EKUs survived the template.
5. **Deploy + verify** as usual. Agents now trust the enterprise root
   already present in the domain — no extra CA distribution needed on
   domain-joined Windows endpoints.

---

## 4. Air-gap transfer

On a connected machine:

```bash
docker pull wazuh/wazuh-manager:4.14.7
docker pull wazuh/wazuh-indexer:4.14.7
docker pull wazuh/wazuh-dashboard:4.14.7
docker pull nginx:1.29-alpine
docker pull smallstep/step-ca:latest        # only needed for the bundled step CA

docker save -o wazuh-airgap-images.tar \
  wazuh/wazuh-manager:4.14.7 wazuh/wazuh-indexer:4.14.7 \
  wazuh/wazuh-dashboard:4.14.7 nginx:1.29-alpine smallstep/step-ca:latest

git clone -b airgp https://github.com/allamiro/wazuh-docker.git
```

Move both across the air gap (approved media), then `docker load -i
wazuh-airgap-images.tar`. Nothing in this deployment reaches the internet;
the PKI tooling is offline by construction (step runs from the transferred
image, openssl mode is host-local). Vulnerability detection is disabled by
default in the manager templates because it needs the online Wazuh CTI feed.

---

## 5. PKI — the certificate lifecycle (summary)

The lifecycle is explicit and staged, driven by one canonical inventory
([`multi-node/config/certs-inventory.conf`](multi-node/config/certs-inventory.conf)):

```text
private key → CSR → CA signing → signed certificate → import → verify → deploy
```

- **26 certificates**: 1 root CA + 25 identities — 16 indexer nodes
  (mutual-TLS transport + REST), 1 `admin` client, 5 Filebeat clients,
  dedicated `wazuh.master-api` (55000), dedicated `wazuh.master-enrollment`
  (1515), 1 dashboard. The manager cluster (1516) and agent events (1514)
  use Wazuh's own key mechanisms — no X.509 by design.
- Connected mode: `./wazuh-deploy.sh certificates` (one shot).
  Air-gap / corporate CA: `pki csr` → `pki sign --ca step|openssl` **or**
  `pki export-csr` → external signing → `pki import <dir>` → `pki verify`.
- `pki verify` is the deployment gate — key↔cert match, chain (intermediates
  supported), CN pinning, SANs, EKUs, validity, key strength; any failure
  blocks `deploy`.
- Private keys never leave the host; the CA key (`config/certs-ca/`) is used
  only for signing and goes to offline storage afterwards.

Full reference — per-phase commands, ADCS/EJBCA/openssl-ca signing recipes,
the CSR `.cnf` format, intermediate-chain ordering, renewal:
**[docs/PKI.md](docs/PKI.md)**.

---

## 6. Deployment models — one PKI, two consumers

```text
                     ONE PKI SYSTEM
                           │
             CSR → SIGN → IMPORT → VERIFY
                           │
               ┌───────────┴───────────┐
               │                       │
               ▼                       ▼
        Docker multi-node       VM / bare-metal
   ./wazuh-deploy.sh deploy    ./wazuh-deploy.sh deploy
          docker                    baremetal
   (compose mounts certs;      (dist/<node>/ packages:
    CA key never mounted)       own key + cert + chain
                                + install.sh + verify.sh)
```

Docker specifics: [docs/DOCKER.md](docs/DOCKER.md). VM/bare-metal — per-node
packages, official install paths, local verification, higher-security
node-local key generation: [docs/BAREMETAL.md](docs/BAREMETAL.md).

---

## 7. Credentials

```bash
./generate-credentials.sh
```

Generates and installs, in one shot:

| Secret | Where it lands |
|---|---|
| indexer `admin` password | `.env` → compose env; bcrypt hash → `internal_users.yml` |
| `kibanaserver` password | `.env`; bcrypt hash → `internal_users.yml` |
| Wazuh API `wazuh-wui` password | `.env`; plaintext → `config/wazuh_dashboard/wazuh.yml` |
| Wazuh cluster key (32 hex) | rendered into `wazuh_manager.conf` + `wazuh_worker1-4.conf` — this is what secures master↔worker (1516), **not** X.509 |
| agent enrollment password | `config/wazuh_cluster/authd.pass` |

Hashes are produced with the indexer image's own `hash.sh` (no extra tooling
on the air-gapped host); upstream demo users are removed; everything
generated is gitignored. `--force` regenerates from scratch (on a live stack
that locks services out until the security index is rebuilt).

---

## 8. Deploy

The one-command path (wraps everything below):

```bash
./wazuh-deploy.sh deploy docker    # = validate → cert/mount preflight → compose up
```

Or the underlying tools directly:

```bash
# 1. credentials
./generate-credentials.sh

# 2. PKI (see section 5 for the corporate-CA variant)
./generate-certs.sh csr
./generate-certs.sh sign --ca step      # or: --ca openssl
./generate-certs.sh verify

# 3. deployment gate + start
./deploy-certs.sh docker
docker compose up -d                    # first boot takes 3-6 minutes
```

`./wazuh-deploy.sh validate` runs the full preflight (config, credentials,
cluster key, certificate preflight, pinned images, kernel/memory/disk, DNS)
and prints `PREFLIGHT PASSED` or `DEPLOYMENT BLOCKED` with the exact problem;
`./wazuh-deploy.sh verify` performs the post-deploy runtime verification
(containers, both clusters, Filebeat, chain-verified API/dashboard/enrollment
certificates, agent ports).

### Verify the running stack

```bash
source .env

docker compose ps                                     # 23 containers Up
curl -ks -u "admin:$INDEXER_PASSWORD" https://127.0.0.1:9200/_cluster/health?pretty
#   expect "status":"green", "number_of_nodes":16
curl -ks -u "admin:$INDEXER_PASSWORD" \
  "https://127.0.0.1:9200/_cat/nodes?v&h=name,node.roles,attr.temp,heap.max&s=name"
docker exec wazuh.master /var/ossec/bin/cluster_control -l   # master + 4 workers
docker exec wazuh.master filebeat test output                # TLS... OK to ingest nodes
curl -ks -u "admin:$INDEXER_PASSWORD" "https://127.0.0.1:9200/_cat/indices/wazuh-*?v"

# the API now serves the CA-signed cert (not self-signed):
echo | openssl s_client -connect 127.0.0.1:55000 2>/dev/null | \
  openssl x509 -noout -subject -issuer
```

Log in at `https://siem.local.domain` with `admin` / `$INDEXER_PASSWORD`
after importing `root-ca.pem` into the OS/browser trust store.

---

## 9. Agent enrollment

Agents need only the name `siem.local.domain` and the enrollment password:

```bash
WAZUH_MANAGER=siem.local.domain \
WAZUH_REGISTRATION_SERVER=siem.local.domain \
WAZUH_REGISTRATION_PASSWORD='<contents of config/wazuh_cluster/authd.pass>' \
  dpkg -i wazuh-agent_4.14.7-1_amd64.deb
systemctl enable --now wazuh-agent
```

Enrollment (1515) → nginx → master's authd, which presents the CA-signed
`wazuh.master-enrollment` certificate; give agents `root-ca.pem` +
`<server-ca-path>` in `ossec.conf` to make them verify it. Event traffic
(1514) → nginx → balanced across master + 4 workers (source-IP affinity);
this channel uses the Wazuh agent protocol, not X.509.

---

## 10. Hot / warm / cold lifecycle (ISM) — and the archive

With the **archive module** enabled (recommended — see
[docs/ARCHIVE.md](docs/ARCHIVE.md)), `./wazuh-deploy.sh archive init` applies
the archive variant of the policy automatically: hot 7 d → warm 30 d →
cold 90 d → **snapshot to RustFS** → delete locally. Long-term retention
(1/3/5/7 years) then lives in the `wazuh-index-snapshots` bucket, and raw
events ship continuously to `wazuh-raw-archives` via the `siem-archiver`
sidecar.

Without the archive module, apply the local-only policy once after first
boot:

```bash
source .env
curl -ks -u "admin:$INDEXER_PASSWORD" -X PUT \
  "https://127.0.0.1:9200/_plugins/_ism/policies/wazuh-hot-warm-cold" \
  -H 'Content-Type: application/json' \
  -d @config/ism/wazuh-hot-warm-cold-policy.json
```

| Age | State | Placement | Actions |
|---|---|---|---|
| 0–7 d | hot | `hot1-3` | — |
| 7–30 d | warm | `warm1-3` | force-merge to 1 segment, lower priority |
| 30–90 d | cold | `cold1-3` | read-only |
| 90 d | delete | — | index deleted |

The policy auto-attaches to new `wazuh-alerts-*` / `wazuh-archives-*` indices;
adjust retention to your compliance needs before applying.

---

## 11. Load balancing & TLS termination — "do we put nginx in front?"

1. **Agent TCP (1514/1515)** — yes, already there: nginx `stream` (L4) is the
   single entry point. The agent protocol is not TLS you can terminate —
   only L4 balancing is valid.
2. **Dashboard HTTPS (443)** — exposed directly with its CA-signed cert
   (end-to-end TLS). An L7 nginx/HAProxy in front is legitimate for WAF /
   operator client-cert auth — then issue the `siem.local.domain` cert to the
   proxy and **re-encrypt** upstream (`proxy_ssl_verify on` against
   `root-ca.pem`); never forward plaintext.
3. **Indexer REST (9200)** — never exposed beyond `127.0.0.1`; the
   coordinating nodes are the internal load-balancing layer.

---

## 12. Security posture (what's hardened vs upstream)

- **No default passwords anywhere**; compose refuses to start without `.env`.
- **Explicit PKI lifecycle** with a verification gate before deployment;
  single external root CA; nothing self-signed — including the Wazuh API
  (dedicated `wazuh.master-api` cert) and enrollment (dedicated
  `wazuh.master-enrollment` cert).
- Full-chain verification everywhere: Filebeat `full`, dashboard
  `verificationMode: full`, indexer transport
  `enforce_hostname_verification: true`.
- **TLS 1.3/1.2 only**, AEAD ciphers; node identity pinning via `nodes_dn`
  (16 CNs) + `admin_dn`; separate identities per protocol role on the master.
- **Minimal exposure**: 443, 1514, 1515 public; 9200/55000 on `127.0.0.1`;
  indexer transport (9300) and Wazuh cluster (1516) never leave the bridge.
- Secrets and PKI material never in git; CA key offline after issuance.

Residual operational duties: protect `.env`, `authd.pass`, and the exported
`dist/` packages; move `config/certs-ca/` offline; put the Docker host itself
under Wazuh monitoring.

---

## 13. Operations

- **Logs**: `docker compose logs -f <service>`.
- **Backup**: indexer data volumes, manager `etc`/`queue` volumes, `.env`,
  `config/` (includes certs), the offline CA key.
- **Restart a tier**: one node at a time keeps the cluster green.
- **Password rotation**: `generate-credentials.sh --force` + recreate +
  security-index rebuild.
- **Cert renewal**: section 5.8.
- **Scaling out**: split services across hosts; the `<node>.<domain>` SANs
  are already in every certificate, so re-pointing `discovery.seed_hosts`
  at real FQDNs requires **no re-issuance**.

## 14. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `verify` fails with `does not chain to root-ca.pem` | wrong/mixed CA generations, or missing intermediate — rebuild `root-ca.pem` as intermediate+root (section 5.5) |
| `verify` fails with `Certificate SAN does not contain: ...` | corporate CA stripped CSR SANs — re-issue with a template that preserves SANs |
| `verify` fails with `required EKU missing: clientAuth` | CA template issued server-only certs — indexer/Filebeat certs need both EKUs |
| `verify` fails with `subject must be exactly 'CN=<name>'` | CA rewrote the subject DN — `nodes_dn` pinning requires CN-only subjects for indexer/admin certs |
| indexer: `max virtual memory areas vm.max_map_count [65530] is too low` | set `vm.max_map_count=262144` on the host |
| `Not initialized` from `/_plugins/_security/health` for >5 min | cluster couldn't form quorum — check `docker logs master1.indexer` |
| Filebeat: `x509: certificate signed by unknown authority` | `root-ca.pem` doesn't match the CA that signed the indexer certs |
| Filebeat: certificate valid for X, not ingest1.indexer | SAN mismatch — run `./generate-certs.sh verify` and re-issue |
| agents can't enroll | wrong enrollment password, DNS for `siem.local.domain` missing (section 3), or 1515 blocked |
| cluster yellow after a tier restart | normal while replicas re-sync |

---

## 15. Deploying agents (Linux & Windows)

Agents need exactly three things: the name **`siem.local.domain`** (one IP —
resolved via the AD DNS records from section 3), the **enrollment password**
(`multi-node/config/wazuh_cluster/authd.pass`), and the agent package
(from your repo mirror or the air-gap bundle's `packages/` directory).
Enrollment goes to `siem.local.domain:1515`, events to `:1514` — nginx
routes both.

Dashboard access for analysts: `https://siem.local.domain` — username
`admin`, password = `INDEXER_PASSWORD` in `multi-node/.env` (printed by
`generate-credentials.sh`).

### Linux agent

```bash
# Debian/Ubuntu (RPM: same variables with rpm -i / yum localinstall)
sudo WAZUH_MANAGER='siem.local.domain' \
     WAZUH_REGISTRATION_SERVER='siem.local.domain' \
     WAZUH_REGISTRATION_PASSWORD='<contents of authd.pass>' \
     WAZUH_AGENT_GROUP='default' \
  dpkg -i wazuh-agent_4.14.7-1_amd64.deb
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent
```

Optional but recommended — make the agent **verify the manager's CA-signed
enrollment certificate**: copy `root-ca.pem` to
`/var/ossec/etc/rootca.pem` on the agent and add inside
`<client><enrollment>` in `/var/ossec/etc/ossec.conf`:

```xml
<server_ca_path>/var/ossec/etc/rootca.pem</server_ca_path>
```

Collecting extra log files — append `<localfile>` blocks to the agent's
`ossec.conf` (or push them centrally via agent groups):

```xml
<ossec_config>
  <!-- any text log -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/myapp/app.log</location>
  </localfile>
  <!-- journald unit -->
  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
    <filter field="_SYSTEMD_UNIT">sshd.service</filter>
  </localfile>
  <!-- extra file-integrity monitoring -->
  <syscheck>
    <directories check_all="yes" realtime="yes">/etc/myapp</directories>
  </syscheck>
</ossec_config>
```

### Windows agent

PowerShell as Administrator (package: `wazuh-agent-4.14.7-1.msi`):

```powershell
msiexec.exe /i wazuh-agent-4.14.7-1.msi /q `
  WAZUH_MANAGER="siem.local.domain" `
  WAZUH_REGISTRATION_SERVER="siem.local.domain" `
  WAZUH_REGISTRATION_PASSWORD="<contents of authd.pass>" `
  WAZUH_AGENT_GROUP="windows"
NET START WazuhSvc
```

Windows event collection — the agent already ships Application/Security/
System by default; add more channels in
`C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<ossec_config>
  <!-- Sysmon (install Sysmon with a config like SwiftOnSecurity first) -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <!-- PowerShell script-block logging -->
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <!-- Windows Defender -->
  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <!-- a flat log file, e.g. IIS -->
  <localfile>
    <location>C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log</location>
    <log_format>iis</log_format>
  </localfile>
</ossec_config>
```

Restart the agent after config changes (`systemctl restart wazuh-agent` /
`Restart-Service WazuhSvc`). Manage fleets centrally with **agent groups**
(shared `agent.conf` pushed from the master) instead of editing every
endpoint: `docker exec wazuh.master /var/ossec/bin/agent_groups -a -g windows -q`,
then edit `/var/ossec/etc/shared/windows/agent.conf` on the master.

Verify enrollment: the agent appears in the dashboard under Agents within a
minute, and `docker exec wazuh.master /var/ossec/bin/agent_control -l` lists
it as Active.

---

## 16. Access reference

Everything an operator needs to reach, in one table. All secrets are
generated at deploy time and live in **`multi-node/.env`** (chmod 600, never
in git); the enrollment password is also in
`multi-node/config/wazuh_cluster/authd.pass`.

| What | Address | Credentials / notes |
|---|---|---|
| **Wazuh dashboard** (analysts) | `https://siem.local.domain` (443) | `admin` / `INDEXER_PASSWORD` from `.env` |
| **Wazuh API** | `https://siem.local.domain:55000` — bound to `127.0.0.1` on the host | `wazuh-wui` / `API_PASSWORD` from `.env` |
| **Indexer REST** (admin/queries) | `https://127.0.0.1:9200` (coord1, localhost-only) | `admin` / `INDEXER_PASSWORD` |
| **Agent events** | `siem.local.domain:1514` (TCP) | Wazuh agent protocol — enrolled agents only |
| **Agent enrollment** | `siem.local.domain:1515` (TLS) | enrollment password from `authd.pass`; CA-signed manager cert |
| **RustFS S3** (archive module) | `https://rustfs:9000` — internal to the `siem` network only | `S3_ACCESS_KEY` / `S3_SECRET_KEY` from `.env` |
| **Internal service user** `kibanaserver` | dashboard → indexer | `DASHBOARD_PASSWORD` from `.env` — not for humans |
| **Root CA** | `multi-node/config/wazuh_indexer_ssl_certs/root-ca.pem` | import into browser/OS trust stores |
| **CA private key** | `multi-node/config/certs-ca/` | signing only — move to offline storage |

Quick operator commands:

```bash
./wazuh-deploy.sh status            # container states
./wazuh-deploy.sh verify            # full runtime health + certificate checks
./wazuh-deploy.sh archive status    # buckets + latest snapshots
grep PASSWORD multi-node/.env       # look up any credential
```
