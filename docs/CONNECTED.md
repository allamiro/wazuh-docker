# Connected / commercial deployment

For networks with internet access. Acquisition is automated and the PKI can
run as one command — no air-gap ceremony.

## Docker (Quick Start A)

```bash
cd multi-node
./wazuh-deploy.sh configure          # pick: connected + docker + bundled CA
./generate-credentials.sh
./wazuh-deploy.sh fetch              # pulls the pinned images
./wazuh-deploy.sh certificates      # one-shot PKI: csr + sign + verify
./wazuh-deploy.sh deploy docker      # preflight gate, then compose up
./wazuh-deploy.sh verify
```

Browse to `https://siem.local.domain` (see [DNS](../DEPLOYMENT-GUIDE.md#3-dns-and-hostnames)).

## VM / bare metal (Quick Start B)

```bash
cd multi-node
./wazuh-deploy.sh configure          # connected + baremetal; then set IPs in config/nodes.yml
./generate-credentials.sh
./wazuh-deploy.sh fetch              # downloads pinned deb/rpm packages into airgap-cache/
./wazuh-deploy.sh certificates
./wazuh-deploy.sh deploy baremetal   # builds dist/<node>/ packages
```

Then per node: install the native Wazuh package for its role
([BAREMETAL.md](BAREMETAL.md)), transfer `dist/<node>/`, run `./install.sh`
and `./verify.sh` there.

## Corporate CA instead of the bundled CA

Choose "Corporate/external CA" in `configure`, then use the staged workflow:

```bash
./wazuh-deploy.sh pki csr
./wazuh-deploy.sh pki export-csr     # hand csr-bundle-*.tar.gz to your PKI
# ... CA signs (see PKI.md) ...
./wazuh-deploy.sh pki import /path/to/signed-certs
./wazuh-deploy.sh pki verify
```

## Version pinning

`fetch` and the compose file are pinned to `wazuh.version` in
`config/deployment.yml` (default 4.14.7). Nothing installs "latest".
