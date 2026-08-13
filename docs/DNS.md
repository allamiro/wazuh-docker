# DNS reference — one host IP, many hostnames

```text
                     NAME RESOLUTION, TWO WORLDS

   Browsers / agents                        Containers
   (outside the VM)                         (inside the siem bridge)
          |                                        |
          | Windows AD DNS                         | Docker/Podman embedded DNS
          | 6 A records -> one host IP             | container_name / hostname
          v                                        v
   siem.local.domain      :443   dashboard    hot1.indexer, wazuh.master,
   dashboard.<domain>     :443   dashboard    coord1.indexer, rustfs, misp, ...
   sso.<domain>           :8443  keycloak              (24 names)
   misp.<domain>          :8081  nginx -> misp                 |
   iris.<domain>          :8082  nginx -> iris                 |
   manager.<domain>       :1514/1515 nginx -> master    never in AD DNS
```

**The certificate inventory is not a DNS work list.** 30 leaf identities exist,
but only the SANs a browser or an agent *outside* the VM dials need to exist in
AD. Everything else is a container network name or a client-auth DN.

| Population | Count | Resolved by | AD record? |
|---|---|---|---|
| Container-internal (`*.indexer`, `wazuh.master`, `wazuh.worker1-4`, `rustfs`, `keycloak`, `misp`, `iris`, `wazuh.dashboard`) | 24 | container DNS on the `siem` bridge | **No** |
| Browser/agent-facing (apex, `dashboard.`, `sso.`, `misp.`, `iris.`, `manager.`) | 6 names | external AD DNS → host IP → published port | **Yes** |
| `admin` client cert | 1 | never resolved; `CN=admin` pinned in `authcz.admin_dn` | **No** |

## What actually listens on the host IP

Published ports are the entire externally reachable surface. Anything bound to
`127.0.0.1` is unreachable through a DNS record pointing at the host IP.

| URL | Host port | Backend | Cert served |
|---|---|---|---|
| `https://<domain>/` | 443 → 5601 | `wazuh.dashboard` | `wazuh.dashboard.pem` |
| `https://<domain>:8080/` (offline maps) | 8080 | nginx → `maps-server` | `wazuh.dashboard.pem`, mounted as `maps.pem` |
| `https://misp.<domain>:8081/` | 8081 | nginx → `misp:80` | `misp.pem` |
| `https://iris.<domain>:8082/` | 8082 | nginx → `iris-app:8000` | `iris.pem` |
| `https://sso.<domain>:8443/` | 8443 | Keycloak directly | `keycloak.pem` |
| agent events / enrollment | 1514, 1515 | nginx `stream` → `wazuh.master` | 1514 uses the Wazuh AES protocol (no TLS cert); 1515 presents `wazuh.master-enrollment.pem` |
| Wazuh API | **`127.0.0.1:55000` only** | `wazuh.master` | not reachable via an AD record |
| Indexer REST | **`127.0.0.1:9200` only** | `coord1.indexer` | not reachable via an AD record |
| RustFS S3 | **not published at all** | internal `https://rustfs:9000` | `s3.` / `archive.` records are dead records |

## The records to create

Minimum viable set for the Docker single-host deployment — six A records, all
pointing at the same host IP:

| Owner name | Type | Data | Serves |
|---|---|---|---|
| `@` | A | *host IP* | dashboard (443), maps (8080), agents (1514/1515) |
| `dashboard` | A | *host IP* | second dashboard URL |
| `sso` | A | *host IP* | Keycloak 8443 — required for OIDC browser redirects |
| `misp` | A | *host IP* | MISP via nginx 8081 |
| `iris` | A | *host IP* | DFIR-IRIS via nginx 8082 |
| `manager` | A | *host IP* | agents/API addressed by name |

Generate them rather than typing them:

```bash
./wazuh-deploy.sh dns records
# -> config/dns/add-dns-records.ps1   run ON the Windows DNS server
# -> config/dns/hosts.snippet         hosts-file fallback for clients without DNS
```

Inputs are `wazuh.domain` and `dns.host_ip` from `config/deployment.yml`.

The PowerShell script is a **dry run by default** — it prints every change it
would make and writes nothing until you pass `-Apply`:

```powershell
.\add-dns-records.ps1                                     # preview
.\add-dns-records.ps1 -Apply                              # apply, on the DNS server
.\add-dns-records.ps1 -Apply -DnsServer dc1.corp.example.com
```

It creates the zone if absent (`Add-DnsServerPrimaryZone -ReplicationScope
"Forest"`), skips records that already hold the right address, and replaces
stale ones **matched on record data** — so an unrelated A record at the same
owner name is never collaterally deleted. Re-running after an IP change is
safe.

**A records only** — no CNAME, no PTR, no SRV, no TTL override. If your tooling
needs reverse lookups, create the `in-addr.arpa` zone and PTR records by hand.

The generator also emits ~18 records that do nothing in Docker mode
(`indexer`, `s3`, `archive`, and one per indexer node such as `hot1`, `ml1`).
They point at loopback-bound or unpublished ports, or at names nothing dials —
the cluster talks to `hot1.indexer`, not `hot1.<domain>`. Harmless, but do not
mistake them for required. On bare metal they become the real records.

## One IP, different URLs

Today the stack separates services **by port, not by hostname**. All three
nginx HTTP vhosts declare `server_name _;` — pure catch-alls — so SNI is never
consulted; each port terminates TLS with exactly one certificate. That is why
the correct cert is served despite the catch-all.

This already gives different URLs on one IP; they are simply port-qualified.
Every hostname resolves to the same A record and the port picks the backend.

To drop the ports and serve `https://dashboard.<domain>/`,
`https://sso.<domain>/`, `https://misp.<domain>/`, `https://iris.<domain>/` all
on 443, nginx must own 443 and branch on SNI:

1. Remove `443:5601` from `wazuh.dashboard`; it stays internal on 5601.
2. Publish `443` on nginx.
3. Mount the certs nginx does not have yet: `keycloak.pem`, the dashboard pair
   under its own name, and `root-ca.pem` for `proxy_ssl_trusted_certificate`.
4. Replace `server_name _` with one `listen 443 ssl` block per hostname, each
   with its own `ssl_certificate`, plus a `default_server` for unmatched SNI.
   Dashboard and Keycloak backends are HTTPS, so they need `proxy_pass https://`
   with `proxy_ssl_verify on`; MISP and IRIS stay plaintext internally.
5. **No certificate re-issue is needed** — `dashboard.`, `sso.`, `misp.` and
   `iris.` are already SANs. A brand-new hostname does require re-issue.
6. **Fix every hardcoded public URL that embeds a port**, or SSO breaks with
   redirect-URI mismatches: Keycloak's `--hostname`, MISP's `BASE_URL`, IRIS's
   `OIDC_ISSUER`, `config/sso-clients.conf` (then run `./wazuh-deploy.sh sso
   clients`), and the redirect URIs in `config/templates/keycloak-realm.json.tpl`.
7. **Maps cannot move off 8080** — `maps-server` appends its listen port when
   building manifest URLs, so it emits `:8080` links regardless of nginx.
8. Agent traffic on 1514/1515 is unaffected — it is `stream`, not HTTP, and
   carries no SNI.

A lower-risk variant keeps TLS end-to-end: use `stream` with `ssl_preread` and
map `$ssl_preread_server_name` to backends. No certs in nginx, no header
rewriting — but step 6 still applies, because the applications pin their own
public URLs.

## Windows AD: what to create on each side

### On the DNS server

1. Set `wazuh.domain`, `dns.host_ip`, `dns.mode: ad` and `dns.server` in
   `config/deployment.yml`, then run `./wazuh-deploy.sh dns records`.
2. Copy `config/dns/add-dns-records.ps1` **to the DNS server** and run it
   elevated *there* — no cmdlet in it carries `-ComputerName`, so it always
   targets the local machine.
3. It creates a new AD-integrated, forest-replicated forward zone if the zone
   does not exist, then the A records above.
4. Reverse/PTR records are not generated. Create them by hand if needed.
5. Every alias is an independent A record, not a CNAME. An IP change rewrites
   all of them, at the zone default TTL — lower the TTL manually before a
   planned cutover.

### On the VM

| Item | Detail |
|---|---|
| Firewall | open inbound TCP **443, 1514, 1515, 8080** always; **8443** with the `sso` profile; **8081, 8082** with the `soc` profile. Do **not** open 55000/9200 (loopback-bound) or 9000 (unpublished). |
| Resolver | point the VM at `dns.server`; it must resolve its own zone before deployment. |
| `/etc/hosts` | add `127.0.0.1 manager.<domain> indexer.<domain>` if you want to reach the API/indexer REST by name *from the host* — AD returns the host IP, where nothing listens on those ports. The scripts sidestep this with `curl --resolve`. |
| Container aliases | the `siem` bridge is `10.77.0.0/24` with static manager IPs. Container names are the internal DNS; add `networks.siem.aliases` for another internal name. |
| Client trust | distribute `root-ca.pem` to every browser and agent trust store — SANs are worthless without the chain. |
| After any IP or zone change | re-run `configure` (regenerates `config/nodes.yml`), then `dns records`, then re-run the PS1. |

## When the corporate AD zone is not `SIEM_DOMAIN`

`SIEM_DOMAIN` defaults to `siem.local.domain` and is baked into every SAN at
CSR time. Three postures:

| Option | What to do | Cost |
|---|---|---|
| **A. Dedicated zone** (recommended) | keep `wazuh.domain: siem.local.domain`; the script creates it as a new forest-replicated primary zone. Domain-joined clients resolve it because their DC is authoritative. | none; the AD domain zone is untouched |
| **B. Delegated child zone** | set `wazuh.domain: siem.corp.example.com`, re-run `configure` → `pki csr` → `sign` → `verify` | full certificate re-issue (SANs change) + update `sso-clients.conf` |
| **C. Records inside the live AD domain zone** | create the six names **by hand** | see the warning below |

> **Preview before applying inside a live AD domain zone.** The script matches
> on record data and skips already-correct entries, so it will not collaterally
> delete unrelated records — but `Name = "@"` in a domain zone is still the
> apex your domain controllers publish. Run it without `-Apply` first and read
> the `[DEL ]` lines; if any of them name an address you did not expect, create
> the six records by hand instead.

Related pitfalls:

- `./generate-certs.sh csr` invoked **directly** ignores `deployment.yml` and
  silently uses `siem.local.domain`. Always go through `./wazuh-deploy.sh pki
  ...`, which reads and exports the configured zone.
- A stray `DOMAIN` environment variable overrides the zone for every SAN.
- `config/templates/keycloak-realm.json.tpl` hardcodes `siem.local.domain` in
  redirect URIs; run `./wazuh-deploy.sh sso clients` after any domain change.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `DNS_PROBE_FINISHED_NXDOMAIN` for `sso.<domain>` | the name is missing from DNS or the client hosts file |
| Browser trusts nothing / `ERR_CERT_AUTHORITY_INVALID` | `root-ca.pem` is not in the client trust store |
| Certificate name mismatch when dialing the **IP** | there are no IP SANs anywhere in this stack, and none can be added through the inventory — always connect by name |
| `curl https://manager.<domain>:55000` from the VM fails | the API is loopback-bound; AD resolves the name to the host IP. Use `--resolve` or a hosts entry |
| `no config/nodes.yml` when running `dns records` | run `./wazuh-deploy.sh configure` first — it writes `nodes.yml` alongside `deployment.yml` |
| `[WARN] N node(s) had no ip` on bare metal | those nodes still carry `ip: REPLACE_ME` in `config/nodes.yml`. They are skipped rather than emitted as broken records — fill the addresses in and re-run |
| Nothing changed after running the PS1 | it is a dry run until you pass `-Apply` |

## Notes on the generator

- `dns.mode` is not read back after `configure`, and `dns.server` is
  informational only — pass `-DnsServer` to the PowerShell script to target a
  remote DNS server, otherwise it acts on the machine it runs on.
- Node records whose `ip:` is unset are skipped with a warning, so a
  partly-filled `nodes.yml` produces a valid script covering the rest.
- Public aliases win over per-node entries that resolve to the same short name,
  so `indexer` is emitted once even though both coordinators carry
  `indexer.<domain>` as a SAN.
