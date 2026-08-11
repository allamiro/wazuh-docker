# Alerting: email (SMTP), rules, and ACAS/Tenable vulnerability data

## Email notifications (SMTP)

Off by default. Everything below goes in
`multi-node/config/templates/wazuh_manager.conf.tpl` (the template — so the
setting survives credential regeneration), then re-render and recreate the
master.

```xml
<global>
  <email_notification>yes</email_notification>
  <smtp_server>smtp.siem.local.domain</smtp_server>   <!-- internal relay -->
  <email_from>wazuh@siem.local.domain</email_from>
  <email_to>soc@your.org</email_to>
  <email_maxperhour>12</email_maxperhour>
  <email_log_source>alerts.log</email_log_source>
</global>

<alerts>
  <log_alert_level>3</log_alert_level>     <!-- what gets indexed -->
  <email_alert_level>12</email_alert_level><!-- what gets emailed -->
</alerts>
```

Per-recipient routing — the part most people actually want:

```xml
<email_alerts>
  <email_to>ir-team@your.org</email_to>
  <level>12</level>                 <!-- or <rule_id>, <group>, <event_location> -->
  <do_not_delay />                  <!-- send immediately instead of batching -->
  <do_not_group />                  <!-- one mail per alert -->
</email_alerts>

<email_alerts>
  <email_to>windows-admins@your.org</email_to>
  <group>authentication_failed</group>
  <event_location>docker-host</event_location>
</email_alerts>
```

Apply:

```bash
cd multi-node
# re-render the manager config from the template (keeps the cluster key)
./generate-credentials.sh --force   # or hand-edit config/wazuh_cluster/wazuh_manager.conf
docker compose up -d --force-recreate wazuh.master   # RECREATE, not restart
```

**Air-gap notes.** Wazuh speaks plain SMTP on port 25 and has no auth/TLS
options of its own — point `smtp_server` at an internal relay (Postfix,
Exchange connector) that handles authentication and any TLS hop. Test the path
from inside the container: `docker exec wazuh.master sh -c 'echo test | sendmail -v soc@your.org'`.
For chat/webhook targets instead of mail, Wazuh ships `<integration>` support
(Slack, PagerDuty, Shuffle) — same block shape as the SOC integrations in
[SOC.md](SOC.md).

## Alert rules

An event becomes an alert when a decoder extracts fields and a rule matches
with `level >= log_alert_level`. Levels: 0–3 informational, 4–7 low, 8–11
medium, 12–14 high, 15 critical.

Custom rules go in `/var/ossec/etc/rules/local_rules.xml` on the **master**
(the cluster syncs them to workers). IDs **100000+** are reserved for you:

```xml
<group name="local,docker,">
  <!-- escalate: container destroyed outside a maintenance window -->
  <rule id="100100" level="10">
    <if_sid>87901</if_sid>
    <field name="docker.Action">^destroy$</field>
    <description>Container destroyed: $(docker.Actor.Attributes.name)</description>
    <mitre><id>T1489</id></mitre>
  </rule>

  <!-- correlation: 5 failed logins in 2 minutes from one source -->
  <rule id="100110" level="12" frequency="5" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>Possible brute force from $(srcip)</description>
  </rule>
</group>
```

Workflow that avoids surprises:

1. Write the rule, test it before deploying — **Ruleset Test** in the
   dashboard (Server management → Ruleset Test) or
   `docker exec -it wazuh.master /var/ossec/bin/wazuh-logtest`.
2. Install it: `docker cp local_rules.xml wazuh.master:/var/ossec/etc/rules/`
   then `docker exec wazuh.master /var/ossec/bin/wazuh-control restart`.
3. Confirm it fires: search `rule.id:100100` in Threat Hunting.

To silence noise instead of adding it, raise the level to 0 with an override
rule, or use `<if_sid>` + `<field>` to scope tightly rather than disabling a
whole group.

## ACAS / Tenable vulnerability data

There is **no official Wazuh–Tenable integration**. Three approaches; the
first is implemented here and is the one to use in an air gap.

### Option 1 (recommended, implemented) — index the scans alongside Wazuh

Export from ACAS/Tenable.sc as `.nessus` (XML) or CSV, carry it across the
gap, and load it into its own indices:

```bash
cd multi-node
python3 scripts/acas-import.py --dry-run /media/scans/weekly.nessus   # preview
python3 scripts/acas-import.py /media/scans/            # whole directory
```

- Creates `acas-vulns-YYYY.MM.DD` with a typed index template (severity,
  CVSS score, host.ip as `ip`).
- Document `_id` is a hash of host+plugin+port, so **re-importing the same
  scan updates rather than duplicates**.
- Nothing touches Wazuh internals — a malformed or huge import cannot disturb
  alert processing.

Then create the index pattern `acas-vulns-*` in the dashboard and correlate
with Wazuh's own findings on `host.name` / `agent.name`.

**Why this is best for an air gap:** the transfer is a file (fits the media
workflow), the blast radius is one index, and both vulnerability views live
side by side. Wazuh's own detection is *inventory-based* (syscollector
packages matched against the CVE feed) while ACAS is *credentialed network
scanning* — they are complementary, not duplicates, which is exactly why DoD
environments run both.

### Option 2 — feed scans as Wazuh events

Drop exports on the manager, ingest with `<localfile>`, and write custom
decoders + rules so findings become alerts you can route by email. Gives
correlation and alerting, at the cost of decoder maintenance and alert volume.

### Option 3 — API pull from Tenable.sc

Only where the enclave allows a connected relay: pull via the Tenable.sc API
on the relay, then media-transfer the JSON and load it with option 1's
importer. Avoid pointing the air-gapped stack at the API directly.

## Wazuh's own vulnerability feed (offline)

Vulnerability detection runs on the master against an **offline CTI snapshot**
so it never needs internet:

```bash
./wazuh-deploy.sh fetch    # downloads airgap-cache/cti/cves.zip (~271 MB)
# ...carried in the air-gap bundle; mounted read-only at /cti/cves.zip
```

The manager config sets `<offline-url>file:///cti/cves.zip</offline-url>`.
Refresh on your media-transfer cadence: re-run `fetch` on the connected side,
ship the new snapshot, then
`docker compose up -d --force-recreate wazuh.master`. Findings land in
`wazuh-states-vulnerabilities-*` and the dashboard's Vulnerability Detection
module.
