# Wazuh multi-node — air-gapped deployment (`airgp` branch)

This branch is a stripped-down fork of [wazuh/wazuh-docker](https://github.com/wazuh/wazuh-docker)
containing **only** a hardened multi-node stack designed for **air-gapped**
environments, published at **`https://siem.local.domain`**.

Everything else from the upstream repository (single-node, image build
tooling, upstream docs) has been removed on purpose.

| | |
|---|---|
| Wazuh version | 4.14.7 (latest published stable) |
| Topology | 2 Wazuh servers (master + worker), 4 indexer nodes (3× cluster_manager+data+ingest, 1 dedicated coordinating), dashboard, nginx TCP load balancer |
| TLS | Every certificate is signed by an external root CA (step-ca container or openssl) — nothing is self-signed per-service |
| Sizing | Tuned for a single 32 GB RAM server |

## Quick start

```bash
cd multi-node
./generate-certs.sh          # external CA + 8 leaf certificates
./generate-credentials.sh    # passwords, bcrypt hashes, cluster key
docker compose up -d
```

Then browse to `https://siem.local.domain` (admin / password printed by
`generate-credentials.sh`).

**Read [DEPLOYMENT-GUIDE.md](DEPLOYMENT-GUIDE.md) before deploying for real** —
it covers the air-gap image transfer, the certificate inventory, DNS,
memory budget, agent enrollment and operations.
