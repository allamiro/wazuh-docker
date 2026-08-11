# Long-term retention with RustFS (optional archive module)

Multi-year retention does not belong on ever-larger indexer disks. This
module adds **RustFS** — an S3-compatible object store — as the archive tier:
the indexer cluster stays sized for *active investigation*, and history
becomes cheap, durable objects that restore on demand.

```text
        Wazuh Manager cluster                Wazuh Indexer cluster
              |                                   |
              | archives.json (raw events)        | ISM: hot 7d -> warm 30d -> cold 90d
              v                                   v
        siem-archiver  ── hourly sync ──►   snapshot before delete
              |                                   |
              +──────────────► RustFS ◄───────────+
                          (S3, TLS, one cert)
                        /                  \
             wazuh-raw-archives     wazuh-index-snapshots
             (compliance/forensics)  (restore into cluster)
```

## Retention model

| Tier | Age | Where | Searchable |
|---|---|---|---|
| Hot | 0–7 d | `hot1-3.indexer` (SSD) | yes |
| Warm | 7–30 d | `warm1-3.indexer` | yes |
| Cold | 30–90 d | `cold1-3.indexer` (read-only) | yes |
| **Archive** | 90 d → 1/3/5/7 y | **RustFS `wazuh-index-snapshots`** | restore on demand |
| **Raw events** | continuous | **RustFS `wazuh-raw-archives`** | forensics/compliance |

Retention beyond 90 days is enforced by *bucket* lifecycle (delete old
snapshots per your compliance policy), not by indexer disks. Adjust the ISM
ages in `config/ism/wazuh-hot-warm-cold-archive-policy.json` before `init`.

## Why these two buckets

- **`wazuh-index-snapshots`** — OpenSearch snapshots taken by ISM right
  before local deletion (and manually via `archive snapshot`). Restoring
  brings the exact indices back into the cluster for investigations.
- **`wazuh-raw-archives`** — the master's `archives.json` (every event,
  alerted or not, once `<logall_json>` is on — the module enables it).
  Wazuh has no built-in S3 shipper for this, so the **`siem-archiver`**
  sidecar (rclone) syncs the rotated archives hourly. That is its entire
  job; without it the raw events would only accumulate on the manager disk.

## Security model — deliberately simple

**One new certificate, zero per-indexer client certs.** RustFS gets a single
HTTPS server identity (`rustfs`, SANs `s3.<domain>`/`archive.<domain>`)
signed by the same deployment CA. The indexers verify it through the JVM
truststore (the init wrapper imports `root-ca.pem`) and authenticate with
**S3 access/secret keys stored in the OpenSearch keystore** — never in
`opensearch.yml`. The keys are generated into `.env` by `archive enable`.

## Enabling (all four deployment modes)

```bash
./wazuh-deploy.sh archive enable       # keys, TLS dir, logall_json, profile
docker compose up -d                   # recreates indexers, starts rustfs + archiver
docker compose up -d --force-recreate wazuh.master   # applies logall_json (recreation, not restart)
./wazuh-deploy.sh archive init         # buckets, snapshot repo, ISM policy
```

Air-gapped hosts need the `repository-s3` plugin zip and the
`rustfs`/`rclone` images — both are included in any `airgap bundle` built
after this feature. Connected hosts fetch them automatically.

Under the hood the indexer init wrapper (`scripts/indexer-init.sh`) installs
the `repository-s3` plugin offline, trusts the CA in the JVM, loads the S3
keys into the keystore, and appends the S3 client settings to the node
config — only when the module is enabled; otherwise it is inert.

## Day-2 operations

```bash
./wazuh-deploy.sh archive status       # containers, buckets, latest snapshots
./wazuh-deploy.sh archive snapshot     # manual snapshot of wazuh-alerts-*
```

**Restore an archived index** (rename avoids clashing with live indices):

```bash
source .env
docker exec master1.indexer curl -s \
  --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
  -u "admin:$INDEXER_PASSWORD" -X POST \
  "https://master1.indexer:9200/_snapshot/wazuh-index-snapshots/<SNAPSHOT>/_restore?wait_for_completion=true" \
  -H 'Content-Type: application/json' -d '{
    "indices": "wazuh-alerts-*",
    "rename_pattern": "wazuh-alerts-(.+)",
    "rename_replacement": "restored-alerts-$1"
  }'
# investigate restored-alerts-*, then delete it when done
```

**Browse the raw archives**: `./wazuh-deploy.sh archive status` lists
buckets; `docker exec siem-archiver rclone ls archive:wazuh-raw-archives`
lists shipped files.

## Scaling & roadmap notes

- On real hardware, move RustFS to its own storage server: same certificate
  (its SANs already carry `s3.<domain>`), same S3 keys, set
  `ARCHIVE_S3_ENDPOINT=https://s3.<domain>:9000` in `.env`.
- A second RustFS/site for disaster recovery = replicate the buckets
  (rclone sync between endpoints).
- **Searchable snapshots** (data stays in S3, queried on demand) exist in
  OpenSearch but add an operational layer — start with snapshot/restore and
  revisit if years-old data must stay queryable continuously.
