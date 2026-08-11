# PKI reference — certificate lifecycle in depth

```text
                  CERTIFICATE WORKFLOW

   Wazuh deployment host
            |
            | ./wazuh-deploy.sh pki csr
            | (generate keys, generate CSRs)
            v
   config/wazuh_indexer_ssl_certs/csr/*.csr
            |
            +----------------------------+
            |                            |
            v                            v
       Local CA                      Corporate CA
    Step / OpenSSL               ADCS / EJBCA / Step / ...
   pki sign --ca step|openssl     (transfer .csr files ONLY)
            |                            |
            | sign CSR                   | sign CSR
            +-------------+--------------+
                          |
                          v
                Signed certificates
                          |
                          | pki import
                          v
             Wazuh deployment host
                          |
                  install CA chain (root-ca.pem)
                          |
                 pki verify   ← deployment gate
                          |
                          v
              deploy docker | baremetal
```

**Private keys never leave the deployment host. The CA only ever sees CSRs.
The CSR is an issuance artifact — nothing consumes it at runtime; each service
runs on `<name>.pem` + `<name>-key.pem` + `root-ca.pem` only.** CSRs are kept
under `csr/` for audit and renewal.

`./wazuh-deploy.sh pki ...` wraps `./generate-certs.sh` — both accept the
same phases; use whichever entry point you prefer.

## The canonical inventory

Every identity is defined **once**, in
[`multi-node/config/certs-inventory.conf`](../multi-node/config/certs-inventory.conf)
(`name|role|sans|required_ekus`). CSR generation, both bundled CAs, the
verifier, the deployment adapters and `config/nodes.yml` all derive from it.

**26 certificates total: 1 root CA + 25 leaf identities:**

| # | Identity (CN) | Role | Service / purpose | Required EKUs |
|---|---|---|---|---|
| 1 | `SIEM Root CA` | trust anchor | signs everything; key kept offline | — |
| 2–17 | `master1-3 / hot1-3 / warm1-3 / cold1-3 / ingest1-2 / coord1-2 .indexer` | indexer | node identity for mutual-TLS transport (9300) + HTTPS REST (9200) | serverAuth + clientAuth |
| 18 | `admin` | admin-client | securityadmin client identity (`authcz.admin_dn`); one per deployment, not per indexer | clientAuth |
| 19–23 | `wazuh.master`, `wazuh.worker1-4` | filebeat | Filebeat **client** identity → indexers | clientAuth |
| 24 | `wazuh.master-api` | wazuh-api | Wazuh API server cert on 55000 (replaces the self-signed one the API otherwise generates) | serverAuth |
| 25 | `wazuh.master-enrollment` | authd | agent-enrollment server cert on 1515 (`sslmanager.cert`) | serverAuth |
| 26 | `wazuh.dashboard` | dashboard | HTTPS cert browsers see on 443 | serverAuth |

Not X.509 by design: the Wazuh manager cluster (1516) uses the shared 32-char
cluster key; agent events (1514) use the Wazuh agent protocol.

Indexer/admin certificates must have subject exactly `CN=<name>` — pinned
verbatim in `plugins.security.nodes_dn` / `authcz.admin_dn`.

## Phase 1 — keys and CSRs

```bash
./wazuh-deploy.sh pki csr        # add SIEM_DOMAIN=... for a different zone
```

Writes per identity: `<name>-key.pem` (private key, stays here),
`csr/<name>.csr`, and `csr/<name>.cnf` — the auditable openssl request
config, e.g.:

```ini
[req]
default_md = sha256
prompt = no
distinguished_name = dn
req_extensions = ext
[dn]
CN = hot1.indexer
[ext]
basicConstraints = CA:FALSE
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName   = DNS:hot1.indexer,DNS:hot1.siem.local.domain
```

Never creates leaf certs; never overwrites existing keys/CSRs without
`--force`.

## Phase 2A / 2B — bundled CA

```bash
./wazuh-deploy.sh pki sign --ca step      # step-ca container, offline
./wazuh-deploy.sh pki sign --ca openssl   # pure host openssl
```

Creates the root CA in `config/certs-ca/` on first run (RSA-4096, 10 y),
signs **the existing CSRs** (refuses if missing; `[SKIP]`s existing certs),
preserves CN/SANs, issues serverAuth+clientAuth.

## Phase 2C — corporate CA (ADCS, EJBCA, external step-ca, openssl ca)

```bash
./wazuh-deploy.sh pki export-csr     # csr-bundle-*.tar.gz (CSRs only, no keys)
```

Requirements for the CA profile/template: **preserve CN and SANs**, issue
**both serverAuth and clientAuth** for indexer/filebeat identities
(server-only certs break the indexer transport).

```bash
# external step-ca
step ca sign hot1.indexer.csr hot1.indexer.pem
```
```powershell
# Microsoft ADCS
certreq -submit -attrib "CertificateTemplate:WazuhNode" hot1.indexer.csr
```
```bash
# standalone OpenSSL CA - ready config: multi-node/config/templates/openssl-ca.cnf
openssl ca -config openssl-ca.cnf -extensions server_client_ext \
  -in hot1.indexer.csr -out hot1.indexer.pem -batch -notext
```

Return certs named exactly `<name>.pem`, plus the chain as `root-ca.pem`:

```text
root-ca.pem  = intermediate.pem + root.pem      (that order)
<name>.pem   = leaf + intermediate               (that order; no root)
```

```bash
./wazuh-deploy.sh pki import /path/to/signed-certs
```

## Phase 3 — verify (the deployment gate)

```bash
./wazuh-deploy.sh pki verify
```

Needs **no CA key**. Per identity: file present · key present · key matches
cert (pubkey SHA-256) · chains to `root-ca.pem` (wrong CA / expired /
not-yet-valid, intermediates supported) · subject/CN pinning · every required
SAN · every required EKU · key strength (RSA ≥ 2048 / EC ≥ 256) · 30-day
expiry warning. Any failure prints the exact reason and exits non-zero:

```text
[FAIL] hot2.indexer
       Certificate SAN does not contain: hot2.siem.local.domain

DEPLOYMENT BLOCKED.
```

`./wazuh-deploy.sh validate` runs this as part of the full preflight, and
`deploy` refuses to start the stack when it fails.

Manual equivalents (also in every `dist/<node>/verify.sh`):

```bash
openssl verify -CAfile root-ca.pem hot1.indexer.pem
openssl pkey -in hot1.indexer-key.pem -pubout -outform DER | openssl dgst -sha256
openssl x509 -in hot1.indexer.pem -pubkey -noout | openssl pkey -pubin -pubout -outform DER | openssl dgst -sha256
```

## CA key protection

`config/certs-ca/root-ca.key` exists only for the bundled CA modes, is used
only by `sign`, is never mounted into containers, and is not needed at
runtime. **Move `config/certs-ca/` to offline protected storage after
issuance.** With a corporate CA no CA key ever exists on this host.

## Renewal

Delete the expiring `<name>.pem` → re-run `pki sign` (bundled) or re-submit
the retained CSR (corporate) → `pki verify` → restart the affected service.
One indexer at a time keeps the cluster green. Keys/CSRs are reused unless
`pki csr --force`.
