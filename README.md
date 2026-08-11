# Wazuh multi-node — air-gapped deployment (`airgp` branch)

This branch is a stripped-down fork of [wazuh/wazuh-docker](https://github.com/wazuh/wazuh-docker)
containing **only** a hardened, enterprise-topology multi-node stack designed
for **air-gapped** environments, published at **`https://siem.local.domain`**.

Everything else from the upstream repository (single-node, image build
tooling, upstream docs) has been removed on purpose.

| | |
|---|---|
| Wazuh version | 4.14.7 (latest published stable) |
| Indexer cluster | 16 nodes: 3 dedicated cluster managers, 3 hot / 3 warm / 3 cold data nodes, 2 dedicated ingest, 2 dedicated coordinating |
| Wazuh servers | 1 master + 4 workers (+ nginx L4 balancer for agent traffic) |
| Dashboard | HTTPS on 443 (`siem.local.domain`) |
| PKI | Explicit lifecycle — **key → CSR → CA signing → import → verify → deploy** — driven by one canonical inventory (26 certs: 1 root CA + 25 identities), signed by a bundled step-ca/openssl CA or your corporate PKI (ADCS/EJBCA/…) |
| Sizing | Tuned for a single 32 GB RAM server |

## Quick start

```bash
cd multi-node

# 1. Generate credentials (passwords, bcrypt hashes, cluster key)
./generate-credentials.sh

# 2. Generate TLS private keys + CSRs (keys never leave this host)
./generate-certs.sh csr

# 3. Sign the CSRs
./generate-certs.sh sign --ca step       # Option A: bundled Step CA container
./generate-certs.sh sign --ca openssl    # Option B: bundled OpenSSL CA
# Option C: corporate CA - submit config/wazuh_indexer_ssl_certs/csr/*.csr
#           to your PKI, copy the signed certs back, then:
#           ./generate-certs.sh import

# 4. Validate certificates (deployment gate - blocks on any failure)
./generate-certs.sh verify

# 5. Start Wazuh
./deploy-certs.sh docker
docker compose up -d
```

Log in at `https://siem.local.domain` as `admin` with the password printed by
`generate-credentials.sh` (stored in `multi-node/.env`).

`./generate-certs.sh` with no arguments still runs all three PKI stages in
sequence, printing each stage explicitly.

Deploying on **VMs / bare metal** instead of Docker? The same PKI material is
packaged per node with `./deploy-certs.sh export` — see the guide.

**Read [DEPLOYMENT-GUIDE.md](DEPLOYMENT-GUIDE.md) before deploying for real** —
it covers the air-gap image transfer, DNS/hostnames (AD DNS or `/etc/hosts`),
the certificate inventory and corporate-CA workflow, memory budget, agent
enrollment, ISM data tiering, and operations.
