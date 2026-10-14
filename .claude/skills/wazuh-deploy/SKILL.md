---
name: wazuh-deploy
description: Deploy the Wazuh stack locally with Docker Compose (single-node, multi-node, or a containerized agent). Use when asked to run, start, stand up, test, or debug a deployment in this repo, including certificate/credential generation, login, agent enrollment, or "containers won't start".
---

# Deploy Wazuh with Docker Compose

Three deployments live in this repo. Pick one and run every command **from its directory**.

| Dir | Services |
| - | - |
| `single-node/` | `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard` |
| `multi-node/` | `wazuh.master`, `wazuh.worker`, `wazuh{1,2,3}.indexer`, `wazuh.dashboard`, `nginx` (load balancer for agents on 1514/1517) |
| `wazuh-agent/` | `wazuh.agent` (enrolls with a token from a manager) |

Image tags come from the compose files and the root `.env` (`WAZUH_VERSION`, `IMAGE_TAG`, `WAZUH_REGISTRY`). Check `VERSION.json` for the current version.

## Order matters: certs, then credentials, then `up`

The stack does **not** start if either step is skipped. Docker reports a missing bind-mount or secret file.

```bash
cd single-node            # or multi-node
sudo sysctl -w vm.max_map_count=262144     # Linux, every host running an indexer; resets on reboot

# 1. Tools (match the image version; take the version from VERSION.json / .env)
curl -o wazuh-certs-tool.sh   https://packages.wazuh.com/5.0/wazuh-certs-tool-<VER>-1.sh
curl -o config.yml            https://packages.wazuh.com/5.0/config-<VER>-1.yml
curl -o wazuh-credentials.sh  https://packages.wazuh.com/5.0/wazuh-credentials-<VER>-1.sh

# 2. Edit config.yml: node names + dns for indexer/manager/dashboard (multi-node needs node_type master/worker)

# 3. Certificates (needs sudo: creates config/ as root, then --priv fixes ownership)
sudo bash ../tools/utils/deployment/certificates-conf.sh --cert --copy --priv
#   optional: --agent-san <ip|dns> (agent listener cert), --api-san <ip|dns> (API cert on 55000); repeatable

# 4. Credentials -> config/credentials/{indexer,manager,dashboard}.env
sudo bash ../tools/utils/deployment/credentials-conf.sh

# 5. Start
docker compose up -d
```

Check the exact URLs/versions against `docs/ref/getting-started/deployment/{single-node,multi-node}.md`. Those are the source of truth.

## Log in

Dashboard is on `https://<host>` (port 443 -> 5601). User `admin`; password:

```bash
grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' config/credentials/indexer.env | cut -d= -f2-
```

## Enroll an agent

Agents enroll with a token minted by the manager (no password enrollment). Follow `docs/ref/getting-started/deployment/wazuh-agent.md`: authenticate to the API on `:55000` as `wazuh` (password `WAZUH_MANAGER_API_PASSWORD` from `manager.env`), `POST /agents/enrollment-tokens`, then put the token in `wazuh-agent/docker-compose.yml` as `WAZUH_ENROLLMENT_TOKEN`. `WAZUH_MANAGER_ADDRESS` must be in the manager's agent certificate SANs (`config.yml` or `--agent-san`).

## Verify

```bash
docker compose ps                                   # all healthy
docker compose logs --tail=100 wazuh.manager
../tools/tests/check-default-credentials.sh         # see the wazuh-credentials skill
```

Healthchecks: manager runs `wazuh-manager-control status`; indexer polls `_plugins/_security/health`; dashboard hits `/app/login`. Startup takes 1-2 minutes.

## Common failures

- `secret file ... does not exist` / `bind source path does not exist`: certs or credentials step skipped.
- Manager exits at start: `wazuh.manager-remoted*.pem` / `-apid*.pem` missing. Re-run the certificate step.
- Indexer restart-loops: `vm.max_map_count` too low, or `OPENSEARCH_JAVA_OPTS` heap too large for the host.
- `credentials: this container has to start as root`: do not set `user:` on indexer/dashboard.
- `credentials: MISSING <KEY>`: fix the `.env` file, then `docker compose up -d --force-recreate <service>`.
- Editing `config/credentials/*.env` after the first start has **no effect**; use `password-tool.sh`.
- `docker compose down -v` wipes the stores, so the next start re-reads the env files.

## Do not commit

`config/`, `wazuh-certificates/`, `wazuh-certs-tool*.sh`, `wazuh-credentials*.sh`, `config*.yml`, and `docker-compose.override.yml` under `single-node/` and `multi-node/` are gitignored. The credentials are plaintext secrets, so keep them out of commits and chat.
