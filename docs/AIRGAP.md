# Air-gapped deployment

Two hosts are involved: a **connected staging machine** (builds the bundle)
and the **air-gapped target** (imports it). No step ever needs internet on
the target.

## Stage 1 — connected staging machine

```bash
git clone -b airgp https://github.com/allamiro/wazuh-docker.git
cd wazuh-docker/multi-node
./wazuh-deploy.sh configure --non-interactive \
    --environment airgap --platform docker          # or baremetal
./wazuh-deploy.sh fetch                              # images (docker) / packages (baremetal)
./wazuh-deploy.sh airgap bundle
```

Produces:

```text
wazuh-airgap-4.14.7/
├── images/wazuh-images.tar        docker images (manager, indexer, dashboard,
│                                  nginx, step-ca) - only when built for docker
├── packages/deb|rpm/              native packages - when fetched for baremetal
├── repository/wazuh-docker-airgp.tar.gz   this repo snapshot
├── scripts/wazuh-deploy.sh
├── checksums/SHA256SUMS           sha256 of every payload file
└── MANIFEST.json
```

Transfer the directory across the air gap on approved media.

## Stage 2 — air-gapped target

```bash
# unpack repository/wazuh-docker-airgp.tar.gz if the repo isn't there yet
cd multi-node
./wazuh-deploy.sh configure            # airgap + docker (or baremetal)
./wazuh-deploy.sh airgap import /media/wazuh-airgap-4.14.7
```

`import` **verifies every checksum first and refuses the bundle on any
mismatch**, then loads images / caches packages.

## Stage 3 — explicit PKI (Quick Starts C & D)

Air-gap always uses the staged lifecycle
(details: [PKI.md](PKI.md)):

```bash
./generate-credentials.sh
./wazuh-deploy.sh pki csr                      # keys + CSRs (keys never leave)
./wazuh-deploy.sh pki sign --ca step           # or --ca openssl
#   corporate offline CA instead:
#   ./wazuh-deploy.sh pki export-csr  →  sign externally  →  pki import <dir>
./wazuh-deploy.sh pki verify                   # deployment gate
```

## Stage 4 — deploy

```bash
./wazuh-deploy.sh validate
./wazuh-deploy.sh deploy docker      # Quick Start C
./wazuh-deploy.sh deploy baremetal   # Quick Start D → dist/<node>/ packages
./wazuh-deploy.sh verify
```

Notes specific to air gap: vulnerability detection stays disabled (needs the
online CTI feed); agents install from `packages/` in the bundle; move
`config/certs-ca/` (bundled-CA private key) to offline storage after signing.
