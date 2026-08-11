# VM / bare-metal deployment

The same PKI material and node inventory drive a fleet of VMs or physical
servers. There are no Docker mounts — each node receives a distribution
package.

## Inventory

`./wazuh-deploy.sh configure` (platform: baremetal) generates
`config/nodes.yml` from the canonical certificate inventory — **edit the `ip:`
fields** and make sure DNS (or `/etc/hosts` on every node) resolves every
hostname. Generate CSRs with your real zone:
`SIEM_DOMAIN=siem.internal ./wazuh-deploy.sh pki csr` — the `<node>.<domain>`
FQDNs are then in every certificate's SANs.

## Per-node packages

```bash
./wazuh-deploy.sh deploy baremetal      # = validate + deploy-certs.sh export
```

```text
dist/hot1.indexer/
├── hot1.indexer.pem          own certificate
├── hot1.indexer-key.pem      own PRIVATE KEY - only this server gets it
├── root-ca.pem               trust chain
├── install.sh                installs into official Wazuh paths + permissions
├── verify.sh                 local post-install verification
├── INSTALL.txt               human instructions
└── SHA256SUMS
```

**A node receives only its own key.** Transfer each package over your
controlled administrative channel (never automatic SSH), then on the node:

```bash
sudo ./install.sh && ./verify.sh
```

Install paths used: `/etc/wazuh-indexer/certs`, `/etc/filebeat/certs`,
`/etc/wazuh-dashboard/certs`, `/var/ossec/api/configuration/ssl/`
(`server.crt`/`server.key`), `/var/ossec/etc/sslmanager.*` — with `400`/`500`
permissions and service ownership.

## Native packages

Connected: `./wazuh-deploy.sh fetch` downloads the pinned deb+rpm set into
`airgap-cache/packages/`. Air-gapped: they arrive via `airgap import`.
Install per role following the official offline installation order
(indexers → cluster init → managers+filebeat → dashboard), using the shipped
`config/wazuh_indexer/*.yml` and `config/wazuh_cluster/*.conf` as the node
configurations (adjust paths/hostnames for your zone).

## Higher-security key generation

For maximum assurance, generate each node's key + CSR **on that node** (copy
its `csr/<name>.cnf` there; `openssl genrsa` + `openssl req -config`), send
only the CSR to the CA, and install the returned certificate locally — the
private key then never exists off the node. See
[PKI.md](PKI.md).

## Verification — twice

1. Centrally before export: `./wazuh-deploy.sh pki verify` (automatic inside
   `deploy baremetal`).
2. Locally on each node after install: `./verify.sh` in the package.
3. Fleet reachability from the admin host: `./wazuh-deploy.sh verify`
   (TCP/TLS checks against `config/nodes.yml` hostnames).
