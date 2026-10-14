---
name: wazuh-credentials
description: Create, rotate, validate, or audit Wazuh deployment passwords (indexer admin/kibanaserver/wazuh-manager, Wazuh API wazuh/wazuh-internal-client). Use for password-tool.sh, credentials-conf.sh, check-default-credentials.sh, credentials.env secrets, or "login fails after changing a password".
---

# Wazuh credentials

The images ship **no passwords**. `tools/utils/deployment/credentials-conf.sh` generates them once, before the first start, into `config/credentials/{indexer,manager,dashboard}.env`. Compose mounts each file as the secret `wazuh-credentials`. On first start each component stores the values (indexer security config, manager API DB + keystore, dashboard keystore) and then deletes its copy. Full reference: `docs/ref/credentials.md`.

## Accounts

| Account | Key | File(s) | Used by |
| - | - | - | - |
| `admin` | `WAZUH_INDEXER_ADMIN_PASSWORD` | indexer.env | humans; dashboard login |
| `kibanaserver` | `WAZUH_INDEXER_KIBANASERVER_PASSWORD` | indexer.env, dashboard.env | dashboard to indexer |
| `wazuh-manager` | `WAZUH_INDEXER_MANAGER_PASSWORD` | indexer.env, manager.env | manager to indexer |
| `wazuh` | `WAZUH_MANAGER_API_PASSWORD` | manager.env | API superuser, enrollment tokens |
| `wazuh-internal-client` | `WAZUH_MANAGER_WUI_PASSWORD` | manager.env, dashboard.env | dashboard to API |

`wazuh-internal-client` was `wazuh-wui` before 5.0.0. A pre-release API DB keeps the old name, so set `API_USERNAME=wazuh-wui` on the dashboard in that case.

## Create

```bash
cd single-node   # or multi-node
sudo bash ../tools/utils/deployment/credentials-conf.sh                       # generate 32-char passwords
sudo WAZUH_INDEXER_ADMIN_PASSWORD='<pw>' bash ../tools/utils/deployment/credentials-conf.sh   # choose one
```

It never overwrites existing files. `--force` is only for a deployment that has never started. Requires `wazuh-credentials.sh` (the library) in the same directory.

## Rotate (running deployment)

**Editing the `.env` files after first start does nothing.** Use `password-tool.sh` inside the container, from the compose directory:

```bash
docker compose exec wazuh.indexer /password-tool.sh --user kibanaserver     # or admin, wazuh-manager
docker compose exec wazuh.manager /password-tool.sh --user wazuh-internal-client   # or wazuh
#   --all for every account of that component
printf '%s\n' '<pw>' | docker compose exec -T wazuh.indexer /password-tool.sh --user admin --stdin
```

The tool changes the account and then **prints follow-up commands** (sed on the env files, keystore updates, service restart). Those commands must be run, because the consumers keep the value they stored. Do not skip them.

- Multi-node: API accounts only on `wazuh.master` (the worker has no API DB, and its tool refuses). Indexer accounts on `wazuh1.indexer`. The `wazuh-manager` keystore command must be run on both master and worker. The printed commands use single-node service names, so adapt them.
- The manager tool refuses to run before the manager's first start.
- Never run `/securityadmin.sh` with no arguments to change a password. It replaces the live security config and reverts rotations.

## Password rules

12-64 chars from `A-Z a-z 0-9 . , _ + : @ % ^ = ~ -`, with at least one lowercase, one uppercase, one digit and one symbol. Invalid input makes the container stop and name the key, without printing the value.

## Audit

```bash
cd single-node   # or multi-node
../tools/tests/check-default-credentials.sh [-f compose.yml] [-i indexer-service] [-a https://localhost:55000]
```

Asserts that the indexer image has none of the OpenSearch demo users (`anomalyadmin kibanaro logstash readall snapshotrestore`) and that no indexer or API account authenticates with its username as its password. It checks the API over HTTP and every manager node's RBAC DB. Exit is non-zero on failure.

## Handling

`config/credentials/*.env` hold plaintext secrets and are gitignored. Never print them into chat or commit them, and read only the single key you need (`grep '^KEY=' file | cut -d= -f2-`).
