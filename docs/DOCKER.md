# Docker multi-node deployment

The shipped topology is 23 containers on one 32 GB host: 16 indexers
(3 cluster-manager, 3 hot, 3 warm, 3 cold, 2 ingest, 2 coordinating),
Wazuh master + 4 workers, dashboard, nginx L4 agent balancer. See the
[architecture section](../DEPLOYMENT-GUIDE.md#1-architecture).

## How certificates reach containers

The PKI is generated **independently of Docker**
(`./wazuh-deploy.sh pki ...` / `./generate-certs.sh`); Docker Compose only
**mounts** the validated files from `config/wazuh_indexer_ssl_certs/`:

```text
PKI (csr → sign → verify)
 │
 ▼  bind mounts (read-only material)
 ├── <node>.pem/.key + root-ca.pem  → each indexer
 ├── wazuh.master.pem (Filebeat)    → manager master
 ├── wazuh.master-api.pem           → /var/ossec/api/configuration/ssl/
 ├── wazuh.master-enrollment.pem    → sslmanager.cert (authd, 1515)
 └── wazuh.dashboard.pem            → dashboard HTTPS
```

The CA private key (`config/certs-ca/`) is **never mounted into any
container**. `docker compose up` never regenerates PKI — a missing or invalid
certificate fails the preflight instead.

## Deploying

```bash
./wazuh-deploy.sh deploy docker
```

runs, in order: `validate` (config, credentials, cluster key, full
certificate preflight, images present at the pinned version, kernel/memory/
disk) → `deploy-certs.sh docker` (every compose-mounted cert exists) →
`docker compose up -d`. Any failure blocks before the stack starts.

Watch progress with `./wazuh-deploy.sh status`; first boot takes 3–6 minutes,
then run `./wazuh-deploy.sh verify`.

## Day-2

- Memory heaps/limits: `.env` (see the
  [memory budget](../DEPLOYMENT-GUIDE.md#memory-budget-32-gb-host)).
- Apply the ISM hot/warm/cold policy once:
  [guide section 10](../DEPLOYMENT-GUIDE.md#10-hot--warm--cold-lifecycle-ism).
- Logs: `docker compose logs -f <service>`.
- The topology is pinned by design; changing node counts means editing
  `docker-compose.yml` **and** `config/certs-inventory.conf` together, then
  re-running the PKI phases for any new identities.
