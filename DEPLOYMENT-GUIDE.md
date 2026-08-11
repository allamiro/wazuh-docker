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

Every value is overridable in `.env` (`IDX_HOT_HEAP`, `MANAGER_MEM_LIMIT`, …).

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

**Active Directory DNS (recommended for a fleet)** — on a domain controller,
create the zone once and one A record for the host:

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

## 5. PKI — the certificate lifecycle

```text
                  CERTIFICATE WORKFLOW

   Wazuh deployment host
            |
            | ./generate-certs.sh csr
            | (generate keys, generate CSRs)
            v
   config/wazuh_indexer_ssl_certs/csr/*.csr
            |
            +----------------------------+
            |                            |
            v                            v
       Local CA                      Corporate CA
    Step / OpenSSL               ADCS / EJBCA / Step / ...
  ./generate-certs.sh sign        (transfer .csr files ONLY)
            |                            |
            | sign CSR                   | sign CSR
            +-------------+--------------+
                          |
                          v
                Signed certificates
                          |
                          | copy back + ./generate-certs.sh import
                          v
             Wazuh deployment host
                          |
                  install CA chain (root-ca.pem)
                          |
              ./generate-certs.sh verify   ← deployment gate
                          |
                          v
                 docker compose up -d
```

**The private keys never leave the deployment host. The CA only ever sees
CSRs. The CSR is an issuance artifact — nothing consumes it at runtime; each
service runs on `<name>.pem` + `<name>-key.pem` + `root-ca.pem` only.**

### 5.1 The canonical inventory

Every identity is defined **once**, in
[`multi-node/config/certs-inventory.conf`](multi-node/config/certs-inventory.conf)
(`name|role|sans|required_ekus`). CSR generation, both bundled CAs, the
verifier, and the deployment adapters all parse that file — the lists cannot
drift apart. Change an identity there, never in the scripts.

**26 certificates total: 1 root CA + 25 leaf identities:**

| # | Identity (CN) | Role | Service / purpose | Required EKUs |
|---|---|---|---|---|
| 1 | `SIEM Root CA` | trust anchor | signs everything; key kept offline | — |
| 2–17 | `master1-3 / hot1-3 / warm1-3 / cold1-3 / ingest1-2 / coord1-2 .indexer` | indexer | node identity for mutual-TLS transport (9300) + HTTPS REST (9200) | serverAuth + clientAuth |
| 18 | `admin` | admin-client | securityadmin client identity (`authcz.admin_dn`) — keep off servers when possible | clientAuth |
| 19–23 | `wazuh.master`, `wazuh.worker1-4` | filebeat | Filebeat **client** identity → indexers | clientAuth |
| 24 | `wazuh.master-api` | wazuh-api | Wazuh API server cert on 55000 (replaces the self-signed one the API otherwise generates) | serverAuth |
| 25 | `wazuh.master-enrollment` | authd | agent-enrollment server cert on 1515 (`sslmanager.cert`) | serverAuth |
| 26 | `wazuh.dashboard` | dashboard | HTTPS cert browsers see on 443 (`siem.local.domain` SAN) | serverAuth |

SANs per identity are in the inventory file; every indexer/admin certificate's
full subject must be exactly `CN=<name>` because it is pinned verbatim in
`plugins.security.nodes_dn` / `authcz.admin_dn`.

### 5.2 Phase 1 — generate keys and CSRs

```bash
cd multi-node
./generate-certs.sh csr           # add SIEM_DOMAIN=... for a different zone
```

For every identity this writes:

```
config/wazuh_indexer_ssl_certs/<name>-key.pem   private key  (STAYS HERE)
config/wazuh_indexer_ssl_certs/csr/<name>.csr   the CSR for the CA
config/wazuh_indexer_ssl_certs/csr/<name>.cnf   the openssl request config —
                                                auditable record of the exact
                                                CN/SANs/EKUs requested
```

Each `.cnf` requests `serverAuth`/`clientAuth` per the inventory, the CN, and
all DNS SANs, e.g. for `hot1.indexer`:

```ini
[req]
default_md = sha256
prompt = no
distinguished_name = dn
req_extensions = ext
[dn]
CN = hot1.indexer
[ext]
basicConstraints = CA:FALSE
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName   = DNS:hot1.indexer,DNS:hot1.siem.local.domain
```

This phase never creates leaf certificates, and re-running it never
overwrites existing keys or CSRs (`[SKIP] ...`) unless you pass `--force`.

### 5.3 Phase 2A — bundled Step CA signs the CSRs

```bash
./generate-certs.sh sign --ca step
```

Creates the root CA in `config/certs-ca/` on first run (RSA-4096, 10 y),
then signs **the existing CSRs** — it refuses to run if CSRs are missing and
never regenerates them silently. Certificates land as
`config/wazuh_indexer_ssl_certs/<name>.pem`, exactly the names Docker Compose
mounts; existing certificates are `[SKIP]`ped without `--force`. CN and SANs
come from the CSR; step's leaf profile issues serverAuth+clientAuth.

### 5.4 Phase 2B — bundled OpenSSL CA signs the CSRs

```bash
./generate-certs.sh sign --ca openssl
```

Same contract, pure host openssl (no container needed): extensions (EKUs +
SANs) are applied from the same canonical inventory the CSRs were built from,
so issued certificates cannot drift from the requested identities.

### 5.5 Phase 2C — corporate / external CA (ADCS, EJBCA, external step-ca, …)

Stop after phase 1 and transfer **only** the CSR files
(`config/wazuh_indexer_ssl_certs/csr/*.csr`) to your CA environment.
Request a profile/template that:

- **preserves the CSR's CN and SANs**, and
- issues **both `serverAuth` and `clientAuth`** for indexer and Filebeat
  identities (server-only certs **will break** the indexer transport layer —
  nodes authenticate to each other as TLS clients).

Signing examples:

```bash
# external step-ca
step ca sign hot1.indexer.csr hot1.indexer.pem
```

```powershell
# Microsoft ADCS (template must allow client+server auth and CSR SANs)
certreq -submit -attrib "CertificateTemplate:WazuhNode" hot1.indexer.csr
```

```bash
# standalone OpenSSL CA - a ready-made config is shipped at
# multi-node/config/templates/openssl-ca.cnf (copy_extensions=copy keeps SANs)
openssl ca -config openssl-ca.cnf -extensions server_client_ext \
  -in hot1.indexer.csr -out hot1.indexer.pem -batch -notext
```

Copy the signed certificates back as
`config/wazuh_indexer_ssl_certs/<name>.pem` (exact names from the inventory),
and install the trust chain as `config/wazuh_indexer_ssl_certs/root-ca.pem`.

**Intermediate CAs** — if your PKI signs leaves from an intermediate:

```text
root-ca.pem      = intermediate.pem + root.pem      (in that order)
<name>.pem       = leaf certificate + intermediate  (in that order)
                   do NOT append the root to leaf files
```

The verifier fully supports both chained and direct-root layouts.

### 5.6 Phase 3 — import and verify (deployment gate)

```bash
./generate-certs.sh import    # checks all expected files exist, then verifies
./generate-certs.sh verify    # the preflight gate, run any time
```

`verify` needs **no CA key**. For the root CA and every one of the 25 leaf
identities it checks: file present · private key present · key matches the
certificate (public-key SHA-256 comparison) · chains to `root-ca.pem`
(catches wrong CA, expired, not-yet-valid) · subject/CN correct (exact
`CN=<name>` where `nodes_dn` pins it) · every required SAN present · every
required EKU present · key strength (RSA ≥ 2048 / EC ≥ 256) · 30-day expiry
warning. Output:

```text
Certificate preflight
======================

[OK] Root CA
[OK] master1.indexer
...
[OK] wazuh.dashboard

26/26 certificates valid.

TLS certificate validation PASSED.

It is now safe to run:

  docker compose up -d
```

Any failure prints the reason and **blocks deployment** (non-zero exit):

```text
[FAIL] hot2.indexer
       Certificate SAN does not contain: hot2.siem.local.domain

DEPLOYMENT BLOCKED.
```

The same key/cert match can be run manually on any node:

```bash
openssl pkey -in hot1.indexer-key.pem -pubout -outform DER | openssl dgst -sha256
openssl x509 -in hot1.indexer.pem -pubkey -noout | openssl pkey -pubin -pubout -outform DER | openssl dgst -sha256
# the two hashes must match
openssl verify -CAfile root-ca.pem hot1.indexer.pem
```

### 5.7 CA key protection

`config/certs-ca/root-ca.key` exists **only** for the bundled CA modes and is
used **only** by `sign`. It is never mounted into any container and is not
required at runtime — the stack needs only `root-ca.pem`, the leaf certs and
leaf keys. **After issuance, move `config/certs-ca/` to offline protected
storage** (encrypted media, vault). With a corporate CA, no CA key ever
exists on this host at all.

### 5.8 Renewal

Delete the expiring `<name>.pem`, re-run the sign phase (bundled CA) or
re-submit the retained CSR (corporate CA), `./generate-certs.sh verify`, then
`docker compose restart <service>`. Rolling one indexer at a time keeps the
cluster green. Keys and CSRs are reused unless you `csr --force`.

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
      ./deploy-certs.sh docker  ./deploy-certs.sh export
```

### Model A — Docker

Compose only **mounts** the validated files from
`config/wazuh_indexer_ssl_certs/` — it never creates identities, and the CA
key is never mounted anywhere. Before starting:

```bash
./deploy-certs.sh docker     # preflight + verifies every compose mount exists
docker compose up -d
```

### Model B — VMs / bare metal

```bash
./deploy-certs.sh export                     # every identity
./deploy-certs.sh vm --node master1.indexer  # a single node
```

builds per-node packages:

```text
dist/master1.indexer/
├── master1.indexer.pem
├── master1.indexer-key.pem
├── root-ca.pem
├── SHA256SUMS
└── INSTALL.txt     ← role-specific target paths + local verify commands
```

Rules the tooling enforces/encodes:

- **A node receives only its own private key** — `master1.indexer-key.pem`
  must never exist on `hot1`, `wazuh.master`, or anywhere else. Each package
  contains exactly: own key, own cert, trust chain.
- Nothing is ever pushed over SSH automatically — in air-gapped environments
  certificate material moves through your controlled administrative channel.
- Install paths follow the official bare-metal layout
  (`/etc/wazuh-indexer/certs`, `/etc/filebeat/certs`,
  `/var/ossec/api/configuration/ssl/`, `/var/ossec/etc/sslmanager.*`,
  `/etc/wazuh-dashboard/certs`) — each `INSTALL.txt` spells them out.
- **Verify twice**: centrally (`./generate-certs.sh verify` before export)
  and locally on each target after installation (commands in `INSTALL.txt`).

**Higher-security variant — local key generation:** for maximum-assurance
environments, generate each node's key + CSR *on that node* (copy its
`csr/<name>.cnf` there and run `openssl genrsa` + `openssl req` with it, or
use the inventory line as reference), send only the CSR to the CA, and
install the returned certificate locally. The key then never exists anywhere
but its own server. The central flow remains the convenient default for
single-host Docker deployments.

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

## 10. Hot / warm / cold lifecycle (ISM)

Apply the shipped policy once after first boot:

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
