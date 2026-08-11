# Air-gap deployment, step by step

For someone doing this for the first time. Follow it top to bottom. Every
command is copy-paste; nothing assumes prior knowledge of Wazuh, PKI or
OpenSearch.

You need **two machines**:

| | |
|---|---|
| **Staging machine** | has internet, Docker installed. Used once, to collect everything. |
| **Target machine** | the air-gapped server. Docker installed. 32 GB RAM minimum, 48 GB comfortable. |

…and a way to move a folder between them (USB drive, approved media, one-way
transfer). Nothing else — no internet, no proxy, no package repo.

---

## PART 1 — On the staging machine (internet side)

### 1.1 Get the code

```bash
git clone -b airgp https://github.com/allamiro/wazuh-docker.git
cd wazuh-docker/multi-node
```

### 1.2 Decide what you want

The core Wazuh stack always installs. These are optional and can be added
later just as easily:

| Module | What it gives you | Extra RAM |
|---|---|---|
| `archive` | Long-term retention: index snapshots + raw events in RustFS (S3) | ~1.5 GB |
| `maps` | Offline map tiles so dashboards with maps work without internet | ~0.5 GB |
| `sso` | Keycloak single sign-on with admin/analyst/read-only groups | ~1 GB |
| `soc` | MISP (threat intel) + DFIR-IRIS (case management) | ~5 GB |
| `ml` | Dedicated machine-learning indexer node | ~3 GB |
| `agent` | A Wazuh agent that monitors the Docker host itself | ~0.5 GB |

You do **not** have to choose now — collecting everything costs only disk
space on the USB drive.

### 1.3 Collect the images

```bash
./export-images.sh                 # everything (recommended)
# or, if you are certain you want only the core stack:
./export-images.sh --core-only
```

This writes `images-export/` containing `wazuh-images.tar`, `SHA256SUMS`
and `MANIFEST.txt`. Expect roughly 8–10 GB and 10–20 minutes.

### 1.4 Collect the data files (optional modules)

```bash
./wazuh-deploy.sh configure --non-interactive --environment airgap --platform docker
./wazuh-deploy.sh fetch
```

This downloads the CVE feed for vulnerability detection (~271 MB), the map
tiles (~225 MB) and the S3 plugin into `airgap-cache/`.

### 1.5 Pack it all up

```bash
cd ..
tar czf wazuh-airgap.tar.gz wazuh-docker/
```

Copy `wazuh-airgap.tar.gz` to your transfer media. **That single file is
everything.**

---

## PART 2 — On the air-gapped target machine

### 2.1 Unpack and prepare the host

```bash
tar xzf wazuh-airgap.tar.gz
cd wazuh-docker/multi-node

# OpenSearch requires this kernel setting (Linux hosts)
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf
```

### 2.2 Load the images

```bash
cd images-export
shasum -a 256 -c SHA256SUMS      # on Linux: sha256sum -c SHA256SUMS
docker load -i wazuh-images.tar
cd ..
```

### 2.3 Make the name resolve

Everything is published as `siem.local.domain`. Pick one:

**Option A — no DNS server (fastest, fine for a lab).** On the target host
and on every machine that will open the dashboard:

```bash
echo "10.0.0.50  siem.local.domain dashboard.siem.local.domain manager.siem.local.domain \
sso.siem.local.domain misp.siem.local.domain iris.siem.local.domain \
indexer.siem.local.domain s3.siem.local.domain" | sudo tee -a /etc/hosts
```

Replace `10.0.0.50` with the target machine's IP. On Windows the file is
`C:\Windows\System32\drivers\etc\hosts` (edit as Administrator).

**Option B — Windows AD DNS (production).** After step 2.4 run
`./wazuh-deploy.sh dns records`; it writes `config/dns/add-dns-records.ps1`,
which you run once on your DNS server to create the zone and every record.

### 2.4 Configure

```bash
./wazuh-deploy.sh configure
```

It asks a handful of questions — press Enter to accept the defaults if you
are unsure. The important ones:

- *Deployment environment* → **2) Air-gapped**
- *Deployment platform* → **1) Docker multi-node**
- *SIEM domain* → `siem.local.domain` (or your own; certificates follow it)
- *Certificate authority* → **1) Bundled Step CA** (it creates its own CA for
  you). Choose *3) Corporate CA* only if your organisation must sign the
  certificates — see [PKI.md](PKI.md).
- *IP of this Wazuh host* → the target machine's IP

### 2.5 Create passwords

```bash
./generate-credentials.sh
```

Prints the admin password and writes everything to `.env`. **Keep that file;
it is the only copy.** Look up any password later with:

```bash
grep PASSWORD .env
```

### 2.6 Create the TLS certificates

Three commands. The first makes private keys and requests, the second signs
them, the third proves they are all valid:

```bash
./wazuh-deploy.sh pki csr
./wazuh-deploy.sh pki sign
./wazuh-deploy.sh pki verify        # must end with "TLS certificate validation PASSED"
```

If verify fails it tells you exactly which certificate and why — fix that
before continuing; the deployment is blocked on purpose.

### 2.7 Start Wazuh

```bash
./wazuh-deploy.sh deploy docker
```

First boot takes 3–6 minutes (databases initialise). Watch it with
`./wazuh-deploy.sh status`, then confirm everything is healthy:

```bash
./wazuh-deploy.sh verify
```

Open **https://siem.local.domain** and log in as `admin` with the password
from step 2.5. Your browser will warn about the certificate until you import
`config/certs-ca/root-ca.pem` into its trust store (on macOS: Keychain Access
→ System → drag the file in → double-click → Trust → Always Trust).

**At this point you have a working SIEM.** Everything below is optional.

---

## PART 3 — Optional modules (add any time)

Each is independent. Run the block you want, skip the rest.

### Long-term retention (archive)

```bash
./wazuh-deploy.sh archive enable
docker compose up -d
docker compose up -d --force-recreate wazuh.master
./wazuh-deploy.sh archive init
./wazuh-deploy.sh archive status
```

### Offline maps

```bash
./wazuh-deploy.sh maps enable
docker compose up -d
./wazuh-deploy.sh maps init
```

### Single sign-on (Keycloak)

```bash
./wazuh-deploy.sh sso enable
./wazuh-deploy.sh pki csr && ./wazuh-deploy.sh pki sign   # certificate for Keycloak
docker compose up -d
docker compose up -d --force-recreate wazuh.dashboard
./wazuh-deploy.sh sso init
./wazuh-deploy.sh sso status
```

Login page then offers a **Keycloak SSO** button. Test users `ssoadmin` and
`analyst1` (passwords in `.env`). Who-can-do-what is one file:
[`config/sso-groups.conf`](../multi-node/config/sso-groups.conf) — see
[SSO.md](SSO.md).

### SOC tools: MISP + DFIR-IRIS

Requires SSO first (they share the Keycloak realm).

```bash
./wazuh-deploy.sh soc enable
./wazuh-deploy.sh pki csr && ./wazuh-deploy.sh pki sign
docker compose up -d
./wazuh-deploy.sh soc init
```

- MISP: `https://misp.siem.local.domain:8081` (`MISP_ADMIN_EMAIL` /
  `MISP_ADMIN_PASSWORD` in `.env`)
- IRIS: `https://iris.siem.local.domain:8082` (`administrator` /
  `IRIS_ADMIN_PASSWORD` in `.env`)

Wazuh alerts at level ≥ 10 now open **IRIS alerts** you can promote to cases,
and observables are enriched from MISP. Details: [SOC.md](SOC.md).

### Machine-learning node / host agent

```bash
# add either name to COMPOSE_PROFILES in .env, e.g. archive,sso,ml,agent
docker compose up -d
```

---

## PART 4 — Everyday tasks

| Task | Command |
|---|---|
| Is everything healthy? | `./wazuh-deploy.sh verify` |
| What is running? | `./wazuh-deploy.sh status` |
| Look up a password | `grep PASSWORD .env` |
| Logs for one service | `docker compose logs -f wazuh.master` |
| Restart one service | `docker compose up -d --force-recreate wazuh.master` |
| Stop everything | `docker compose stop` |
| Add agents | [DEPLOYMENT-GUIDE.md §15](../DEPLOYMENT-GUIDE.md) (Linux + Windows) |
| Email alerts | [ALERTING.md](ALERTING.md) |
| Import ACAS/Tenable scans | `python3 scripts/acas-import.py scan.nessus` |
| Refresh the CVE feed | re-run `fetch` on the staging machine, copy `airgap-cache/cti/`, recreate the master |

### Two rules that save time

1. **Config changes need a recreate, not a restart.** Files under
   `config/wazuh_cluster/` are copied into the container only when it is
   created: use `docker compose up -d --force-recreate <service>`.
2. **Permission changes need a re-login.** Roles are written into the session
   token when you log in, so log out and back in after changing groups.

---

## If something goes wrong

| Symptom | Do this |
|---|---|
| `pki verify` fails | Read the reason it prints — usually a missing SAN or the wrong CA. Re-run `pki sign`, or re-import the corporate certs. |
| A container restarts in a loop | `docker compose logs --tail 50 <name>` — the reason is almost always in the last few lines. |
| Dashboard shows "no permissions" for a module | Log out and back in. If it persists, re-run `./wazuh-deploy.sh sso init`. |
| Browser cannot find `siem.local.domain` | The hosts/DNS entry from step 2.3 is missing on *that* machine. |
| Cluster health is yellow after a restart | Normal while replicas re-sync; it goes green on its own. |
| Cluster health is red | A node holding data is gone. Bring it back rather than deleting indices. |

Full reference: [DEPLOYMENT-GUIDE.md](../DEPLOYMENT-GUIDE.md).
