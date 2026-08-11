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

## Quick start — one CLI, four modes

```bash
cd multi-node
./wazuh-deploy.sh configure     # pick: connected|airgap × docker|baremetal × CA
```

then follow the next-steps it prints. Example (air-gapped + Docker):

```bash
./generate-credentials.sh
./wazuh-deploy.sh airgap import /media/wazuh-airgap-4.14.7   # bundle built on a connected host
./wazuh-deploy.sh pki csr
./wazuh-deploy.sh pki sign --ca step     # or: pki export-csr → corporate CA → pki import
./wazuh-deploy.sh pki verify
./wazuh-deploy.sh deploy docker
./wazuh-deploy.sh verify
```

Connected environments get a shorter path (`fetch` + one-shot
`certificates`). Log in at `https://siem.local.domain` as `admin` with the
password printed by `generate-credentials.sh` (stored in `multi-node/.env`).

| Mode | Walkthrough |
|---|---|
| Connected (Docker or VM) | [docs/CONNECTED.md](docs/CONNECTED.md) |
| Air-gapped (bundle/import) | [docs/AIRGAP.md](docs/AIRGAP.md) |
| Docker specifics | [docs/DOCKER.md](docs/DOCKER.md) |
| VM / bare-metal specifics | [docs/BAREMETAL.md](docs/BAREMETAL.md) |
| PKI deep reference | [docs/PKI.md](docs/PKI.md) |
| Long-term retention (RustFS S3 archive) | [docs/ARCHIVE.md](docs/ARCHIVE.md) |
| Rootless Podman / SELinux hosts | [docs/PODMAN.md](docs/PODMAN.md) |
| SOC tier: MISP + DFIR-IRIS (SSO) | [docs/SOC.md](docs/SOC.md) |
| Email/SMTP, alert rules, ACAS/Tenable | [docs/ALERTING.md](docs/ALERTING.md) |

Optional modules (each one command to enable): **RustFS S3 archive**
(`archive enable` — snapshots + raw-event retention), **offline maps**
(`maps enable` — self-hosted tiles, the air-gap answer to Elastic Maps
Server), **Keycloak SSO** (`sso enable` — OIDC login with
admin/analyst/readonly groups + audit trail, see
[docs/SSO.md](docs/SSO.md)), a dedicated **OpenSearch ML node**
(`COMPOSE_PROFILES=+ml`), a **host-monitoring agent container** with the
docker-listener wodle (`agent` profile), and a **SOC tier** (`soc enable` —
MISP threat intel + DFIR-IRIS case management, both behind Keycloak, with
Wazuh integrations that open IRIS alerts and enrich from MISP). External **Windows AD DNS / ADCS**
integration is built in (`dns records`, `pki export-csr`).

The single-purpose tools (`generate-certs.sh`, `generate-credentials.sh`,
`deploy-certs.sh`, `docker compose`) all remain directly usable —
`wazuh-deploy.sh` is an orchestration layer, not a replacement.

**Read [DEPLOYMENT-GUIDE.md](DEPLOYMENT-GUIDE.md) before deploying for real** —
decision tree, four quick starts, DNS/hostnames (AD DNS or `/etc/hosts`),
certificate inventory, memory budget, agent enrollment, ISM data tiering,
and operations.
