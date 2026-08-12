# SOC architecture: current state, gaps, and the road to a modern SOC

What this deployment is today, measured against the operating models it is
built on, what is genuinely missing, and the order in which to close it.

Frameworks used as the yardstick:

| Framework | Used for |
|---|---|
| **NCSC — Building a SOC** | operating model: Inform / Develop / Respond over Support and Governance |
| **NIST SP 800-61r2** | incident handling lifecycle (prepare → detect/analyse → contain/eradicate/recover → post-incident) |
| **NIST CSF 2.0** | function coverage: Govern, Identify, Protect, Detect, Respond, Recover |
| **MITRE ATT&CK** | detection coverage and threat modelling |
| **SOC-CMM** | maturity scoring across people / process / technology / services |

Companions: [SOC-OPERATIONS.md](SOC-OPERATIONS.md) (roles and the six-stage
workflow), [SOC.md](SOC.md) (how MISP/IRIS are deployed),
[ALERTING.md](ALERTING.md) (email, rules, ACAS).

---

## 1. What exists today

```text
                         ENDPOINTS / SOURCES
    ┌──────────────┬───────────────┬───────────────┬──────────────┐
    │ Linux agents │ Windows agents│ Docker host   │ ACAS/Tenable │
    │ (syscheck,   │ (eventchannel,│ (docker-      │ (.nessus /   │
    │  journald)   │  Sysmon)      │  listener)    │  CSV export) │
    └──────┬───────┴───────┬───────┴───────┬───────┴──────┬───────┘
           │ 1514/tcp agent protocol       │              │ media
           ▼                               ▼              ▼ transfer
    ┌─────────────────────────────────────────┐   ┌──────────────────┐
    │  nginx  (L4 stream, single entry point) │   │ acas-import.py   │
    └──────┬──────────────────────────────────┘   └────────┬─────────┘
           ▼                                               │
    ┌─────────────────────────────────────────┐            │
    │  Wazuh server cluster                   │            │
    │  master + worker1..4   (rules/decoders) │            │
    └──────┬──────────────────────────────────┘            │
           │ Filebeat, mTLS                                │ bulk
           ▼                                               ▼
    ┌──────────────────────────────────────────────────────────────┐
    │  Wazuh indexer (OpenSearch) 17 nodes                         │
    │  ingest1-2 → hot1-3 (7d) → warm1-3 (30d) → cold1-3 (90d)     │
    │  master1-3 (quorum)  coord1-2 (queries)  ml1 (ml-commons)    │
    │  indices: wazuh-alerts-*, wazuh-states-*, acas-vulns-*,       │
    │           security-auditlog-*                                 │
    └──────┬──────────────────────────────┬────────────────────────┘
           │ ISM: snapshot before delete  │ queries
           ▼                              ▼
    ┌──────────────────┐        ┌──────────────────────────────────┐
    │ RustFS (S3)      │        │ Wazuh dashboard (443)            │
    │ index-snapshots  │        │ tenants: Global/soc/ir/intel/... │
    │ raw-archives     │        └───────────┬──────────────────────┘
    │ 1-7 year retention│                   │
    └──────────────────┘                    │ level >= 10 (custom-iris)
                                            ▼
    ┌──────────────────────┐      ┌──────────────────────────────┐
    │ MISP (8081)          │◄────►│ DFIR-IRIS (8082)             │
    │ IoCs, feeds, galaxies│ IrisMISP│ alerts → cases → timeline │
    └──────────────────────┘      └──────────────────────────────┘
                    ▲                          ▲
                    └──────── Keycloak ────────┘
                       one realm, 3 clients, 14 groups
```

**Covered well:** collection, tiered retention with archive, PKI, SSO with
role separation, case management, threat-intel store, offline vulnerability
feed, ACAS ingestion.

---

## 2. Gap analysis

Scored against the frameworks above. "Effort" assumes an engineer who knows
this stack.

| # | Gap | Why it matters | Framework | Effort | Priority |
|---|---|---|---|---|---|
| 1 | **No detection-content lifecycle** — rules are edited in place, not version-controlled, tested or peer-reviewed | a bad rule reaches production with no rollback and no record of who changed what | NCSC Develop; CSF PR.PS | M | **P1** |
| 2 | **No ATT&CK coverage baseline** — nobody can say which techniques are detectable | you cannot prioritise detection work or answer "are we covered for X" | ATT&CK; SOC-CMM | M | **P1** |
| 3 | **No SOAR / response automation** — every containment action is manual | MTTR stays human-speed; Tier 1 burns on repetitive triage | NCSC Develop; CSF RS.MA | L | **P1** |
| 4 | **Agent coverage unknown** — no inventory reconciliation between "assets that exist" and "assets sending telemetry" | blind spots are invisible; a decommissioned agent looks the same as a silenced one | CSF ID.AM | S | **P1** |
| 5 | **No alert triage SLAs measured** — targets documented, never reported | you cannot show the SOC is keeping up, or justify headcount | SOC-CMM services | S | P2 |
| 6 | **Threat intel is a store, not a loop** — MISP is populated manually; hunt/IR findings do not flow back | intel decays; the same IoC is re-investigated repeatedly | NCSC Inform | M | P2 |
| 7 | **No purple-team / detection validation** — detections are never adversarially tested | rules that silently stopped working are found during an incident | ATT&CK; CSF ID.IM | M | P2 |
| 8 | **Single-site deployment** — one host, no DR for the SIEM itself | the SOC is a single point of failure in its own incident | CSF RC.RP | L | P2 |
| 9 | **No case metrics / reporting pack** — IRIS holds the data, nothing summarises it | no MTTD/MTTR trend, no board-level reporting | SOC-CMM | S | P3 |
| 10 | **Insider-threat monitoring not segregated** — analysts can see all data including their own team's | NCSC calls for segregation when monitoring staff | NCSC | M | P3 |
| 11 | **No log-source health monitoring** — a source that stops sending is not alerted on | silent collection failure = undetected blind spot | CSF DE.CM | S | P2 |
| 12 | **Backup/restore never rehearsed** — snapshots exist, restore is untested | an untested backup is a hypothesis | CSF RC.RP | S | **P1** |

---

## 3. Remediation roadmap

### Phase 1 — make the current stack trustworthy (weeks 1–4)

```text
  gap 4  ──► asset ↔ agent reconciliation report      (soc-onboarding)
  gap 11 ──► log-source health alerting               (soc-onboarding, soc-detection)
  gap 12 ──► restore rehearsal from RustFS snapshot   (soc-engineer)
  gap 1  ──► rules into git + logtest in CI           (soc-detection, soc-engineer)
```

**Gap 1 concretely:** move `local_rules.xml` and custom decoders into the
repository, and make the pipeline `wazuh-logtest` every rule against a corpus
of saved events before `soc-engineer` deploys. Nothing about the deployment
changes — but the ruleset gains history, review, and rollback.

**Gap 12 concretely:** restore one archived index from
`wazuh-index-snapshots` into `restored-*`, confirm the document count matches,
delete it. Quarterly. Write the date in the runbook.

### Phase 2 — measure and close detection gaps (weeks 4–12)

```text
  gap 2  ──► ATT&CK coverage map from the active ruleset
  gap 5  ──► triage SLA reporting from IRIS alert timestamps
  gap 7  ──► atomic tests per technique → confirm the rule fires
  gap 6  ──► hunt/IR findings pushed back into MISP as events
```

Coverage map method: export enabled rules, extract their `<mitre><id>` tags,
join against the ATT&CK matrix, and publish a heat map. The honest output is
usually "we cover a third of what we assumed" — that list *is* the detection
backlog, owned by `soc-detection`.

### Phase 3 — automate and scale (quarter 2+)

```text
  gap 3  ──► SOAR (Shuffle) for enrichment + guided containment
  gap 8  ──► second site / DR replica of indexer + RustFS
  gap 9  ──► scheduled metrics pack from IRIS + indexer
  gap 10 ──► segregated insider-threat tenant with restricted membership
```

Automate in this order — it is the order of safety: **enrich** (no side
effects) → **decide** (analyst approves) → **act** (isolate a host). Never
start with automated containment.

---

## 4. Data flows

### 4.1 Detection lifecycle — the Inform → Develop → Respond loop

```text
      ┌──────────────────────── INFORM ────────────────────────┐
      │  threat intel (MISP)      hunting (soc-hunt)           │
      │  vuln findings            onboarding: new log source   │
      └───────────────┬───────────────────────────────────────-┘
                      │ "we should be able to see X"
                      ▼
      ┌──────────────────────── DEVELOP ───────────────────────┐
      │  soc-detection: write rule/decoder                     │
      │        │                                               │
      │        ├─► wazuh-logtest against saved events          │
      │        ├─► peer review (git PR)                        │
      │        └─► soc-engineer deploys → cluster syncs        │
      └───────────────┬────────────────────────────────────────┘
                      │ rule live
                      ▼
      ┌──────────────────────── RESPOND ───────────────────────┐
      │  alert → triage → case → containment → closure         │
      └───────────────┬────────────────────────────────────────┘
                      │ what did we learn?
                      ▼
              new IoCs → MISP        tuning → back to DEVELOP
              new hunt hypothesis → back to INFORM
```

The loop is the point. A SOC that only runs the Respond box gets louder every
month; one that closes the loop gets quieter.

### 4.2 Alert → case escalation with decision points

```text
   Wazuh alert
       │
       ├─ level < 7 ─────────────────► indexed only, no alert
       │
       ├─ level 7-9 ─────────────────► dashboard queue, batch review (T1)
       │
       └─ level >= 10 ──► custom-iris ──► IRIS ALERT
                                             │
                            ┌────────────────┴───────────────┐
                            ▼         TIER 1 TRIAGE          ▼
                    false positive?                     real / unclear?
                            │                                │
              close + tuning ticket ──► soc-detection        │
                                                             ▼
                                                    ESCALATE TO CASE
                                                    (owner = Tier 2)
                                                             │
                       ┌─────────────────────────────────────┤
                       ▼                                     ▼
              contained locally?                    needs containment?
                       │                                     │
                       │                            Tier 3 (agents_admin)
                       │                            isolate / active response
                       │                                     │
                       └──────────────┬──────────────────────┘
                                      ▼
                            eradication + recovery tasks
                                      ▼
                         SOC Manager: outcome + reviewer
                                      ▼
                     closed ──► metrics ──► lessons ──► DEVELOP
```

**Escalation triggers** — write these into the runbook so they are not
judgement calls at 3am:

| Trigger | Escalate to | Also notify |
|---|---|---|
| Confirmed execution on an endpoint | Tier 3 | SOC Manager |
| Any domain-controller / identity-system alert | Tier 3 | Manager + IT lead |
| Data movement to an external/unknown destination | Tier 3 | Manager + Legal |
| Alert on a SOC system itself (indexer, Keycloak, IRIS) | `soc-engineer` | Manager — treat as potential adversary action |
| > 3 related alerts on one asset within 1h | Tier 2 | — |
| Anything unresolved at shift end | next shift Tier 2 | handover note in the case |

### 4.3 Threat-intelligence loop

```text
   external feeds (media)          internal findings
        │  offline import               │  hunt / IR / case IOCs
        ▼                               ▼
   ┌──────────────────────────────────────────┐
   │                 MISP                     │
   │  events, attributes, galaxies, tags      │
   └───────┬──────────────────────┬───────────┘
           │ IrisMISP enrichment  │ export as CDB list
           ▼                      ▼
   ┌───────────────┐      ┌─────────────────────────┐
   │ DFIR-IRIS     │      │ Wazuh CDB lists         │
   │ IOC context   │      │ rules match on IoC hit  │
   │ on every case │      │ → new alerts            │
   └───────────────┘      └─────────────────────────┘
```

Today the left path (enrichment) is live; the right path (MISP → CDB list →
Wazuh rule) is **gap 6** and is what turns intel into detection rather than
reference material.

### 4.4 Vulnerability management — two complementary sources

```text
   Wazuh syscollector            ACAS / Tenable credentialed scan
   (what is installed)           (what is exposed and exploitable)
        │                                 │
        ▼                                 ▼
   offline CVE feed                acas-import.py
   (/cti/cves.zip)                       │
        │                                 │
        ▼                                 ▼
   wazuh-states-vulnerabilities-*    acas-vulns-*
        └───────────────┬─────────────────┘
                        ▼  correlate on host.name / agent.name
              soc-vuln: prioritised remediation
                        │
        ┌───────────────┴───────────────┐
        ▼                               ▼
   patch (IT)                    compensating detection
                                 (soc-detection: rule for
                                  exploitation attempts)
```

Inventory-based and scan-based findings disagree constantly — that
disagreement is the signal. A package Wazuh sees but ACAS does not usually
means an unscanned host; the reverse usually means an unmanaged install.

### 4.5 Incident severity and response clock

```text
  SEV1 Critical   confirmed compromise, active attacker, or data loss
       ├─ response: immediate, page on-call, Tier 3 leads
       ├─ comms: Manager → leadership within 1h
       └─ IRIS: severity Critical, reviewer mandatory

  SEV2 High       likely intrusion attempt, single asset impact
       ├─ response: within 1 hour, Tier 2 owns, Tier 3 on standby
       └─ comms: Manager informed same day

  SEV3 Medium     suspicious, needs analysis, no confirmed impact
       └─ response: same shift, Tier 1 → Tier 2 as needed

  SEV4 Low        policy violation, anomaly, batched
       └─ response: next business day
```

Map these to Wazuh rule levels (15 → SEV1, 12–14 → SEV2, 10–11 → SEV3,
7–9 → SEV4) so severity is assigned by the detection, not by whoever picks
up the alert.

---

## 5. Threat modelling — deciding what to detect

NCSC's attack-tree method, applied to this estate. Work backwards from the
thing you cannot afford to lose:

```text
                 GOAL: exfiltrate the case/alert data
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
   compromise an          compromise the           abuse a valid
   analyst account        indexer directly         SOC integration
        │                       │                       │
   ┌────┴────┐            ┌─────┴─────┐           ┌─────┴─────┐
   ▼         ▼            ▼           ▼           ▼           ▼
 phish    steal         exploit     stolen      IRIS API    S3 keys
 SSO      session       9200        admin cert   key        from .env
   │         │            │           │           │           │
   ▼         ▼            ▼           ▼           ▼           ▼
 DETECT?  DETECT?     DETECT?     DETECT?     DETECT?     DETECT?
 Keycloak  session    9200 is     cert use    IRIS       no alert
 auth logs  reuse     localhost   audit       activity   on key use
 ✓ audited  ✗ GAP     ✓ closed    ~ partial   ✓ logged   ✗ GAP
```

Each leaf becomes one of: **prevent** (already done — 9200 bound to
localhost), **detect** (a rule to write — hand it to `soc-detection`), or
**accept** (documented, with a compensating control). The two ✗ leaves above
are real work items for this deployment, and they came from one 10-minute
exercise on one asset.

Run this per crown-jewel asset. Then tag every resulting detection with its
ATT&CK technique so gap 2's coverage map builds itself.

---

## 6. What each group actually does, day to day

| Group | A normal day | Produces | Consumes |
|---|---|---|---|
| `soc-tier1` | works the IRIS alert queue front to back | dispositions, escalations, tuning tickets | alerts, MISP context |
| `soc-tier2` | owns cases, investigates, writes the timeline | cases, IOCs, containment requests | Tier 1 escalations, Wazuh hunting |
| `soc-tier3` | contains, does forensics, leads SEV1/2 | response actions, root cause | Tier 2 escalations |
| `soc-hunt` | tests hypotheses against the data | hunt findings → detections + IoCs | intel, ATT&CK gaps |
| `soc-intel` | curates MISP, tracks actors relevant to the estate | IoCs, actor context, priorities | feeds (offline), case findings |
| `soc-detection` | writes/tunes rules, measures coverage | tested detection content | tuning tickets, hunt output, intel |
| `soc-engineer` | keeps the platform healthy, deploys content | working stack, deployed rules | everything's complaints |
| `soc-onboarding` | brings new sources/agents in, watches source health | coverage, log-source inventory | asset inventory |
| `soc-vuln` | reconciles Wazuh VD with ACAS, drives remediation | prioritised vuln list | both scan sources |
| `soc-manager` | reviews cases, reports metrics, owns process | metrics, outcomes, improvements | closed cases |
| `soc-audit` | samples cases and access, checks the trail | assurance findings | audit logs, activities |

---

## 7. Maturity checkpoints

Judge progress by outcomes, not tool count:

- **Level 1 — Reactive.** Alerts are worked; no measurement. *(this deployment
  as delivered)*
- **Level 2 — Managed.** Triage SLAs measured; detection content in version
  control; backups rehearsed. *(Phase 1 + 5)*
- **Level 3 — Defined.** ATT&CK coverage known and tracked; hunting produces
  detections; intel loop closed. *(Phase 2)*
- **Level 4 — Measured.** Automation handles enrichment and routine
  containment; MTTD/MTTR trended; purple-team validation routine. *(Phase 3)*
- **Level 5 — Optimising.** Detection engineering driven by measured gaps;
  the SOC changes the estate's design, not just its alerts.

The jump that matters most is **1 → 2**, and none of it needs new products —
it needs version control, a measurement, and a rehearsed restore.
