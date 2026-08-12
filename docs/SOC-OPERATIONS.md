# SOC operations: roles, groups, and the incident workflow

How to run this stack as a real Security Operations Centre in a production
air-gapped enclave: who gets which permissions in each tool, how those are
provisioned from one identity source, and how an alert becomes a closed case.

Companion documents: [SSO.md](SSO.md) (how the group map is applied),
[SOC.md](SOC.md) (how MISP/IRIS are deployed), [ALERTING.md](ALERTING.md)
(email, rules, ACAS).

---

## 1. One identity source, three consumers

```text
                        Keycloak realm "siem"
                     (groups = the only thing you manage)
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        ▼                         ▼                         ▼
   Wazuh dashboard             MISP                    DFIR-IRIS
   client: wazuh-dashboard     client: misp            client: iris
   → indexer roles (data)      → MISP role id          → IRIS groups
   → Wazuh API roles           (admin/user/read-only)     (permissions + case ACL)
   → tenant (workspace)
   → DLS (data scope)
```

Every service has **its own confidential client with its own secret** — a
leaked secret costs you one application, never the estate. Clients are
declared in [`config/sso-clients.conf`](../multi-node/config/sso-clients.conf)
and applied with:

```bash
./wazuh-deploy.sh sso clients          # create/update all clients
python3 scripts/apply-sso-clients.py --dry-run   # preview
python3 scripts/apply-sso-clients.py --rotate    # rotate every secret
```

Moving to production means editing that one file (domain, ports, which
services exist) — not hunting through compose files.

---

## 2. SOC roles → Keycloak groups

A realistic small-to-mid SOC. Create these groups in Keycloak; everything
else follows from them.

| Keycloak group | Who | Typical headcount |
|---|---|---|
| `soc-tier1` | Alert triage / monitoring analysts | 4–8 |
| `soc-tier2` | Investigators, case owners | 2–4 |
| `soc-tier3` | IR / forensics / threat hunting | 1–3 |
| `soc-intel` | Threat-intel analysts (MISP owners) | 1–2 |
| `soc-manager` | SOC lead, metrics, case review | 1–2 |
| `soc-engineer` | Platform/detection engineering (admins) | 1–2 |
| `soc-audit` | Compliance, internal audit — read-only | as needed |

### What each group gets

| Group | Wazuh (data) | Wazuh (modules) | Workspace | MISP | IRIS |
|---|---|---|---|---|---|
| `soc-tier1` | `kibana_user`, `readall` | `readonly`, `agents_readonly` | `soc` RW | read-only (6) | alerts_read/write, cases read-only |
| `soc-tier2` | `kibana_user`, `readall` | `readonly`, `agents_readonly`, `cluster_readonly` | `soc` RW | user (3) | standard_user + alerts_*, full access on own cases |
| `soc-tier3` | `kibana_user`, `readall` | `agents_admin`, `cluster_readonly` | `ir` RW | user (3) | standard_user, alerts_delete, search across cases |
| `soc-intel` | `kibana_user`, `readall` | `readonly` | `intel` RW | org admin (2) | standard_user, customers_read |
| `soc-manager` | `kibana_user`, `readall` | `readonly`, `cluster_readonly` | `soc` RW | read-only (6) | all_activities_read, case_templates_write, reviewer |
| `soc-engineer` | `all_access` | `administrator` | `Global` RW | admin (1) | server_administrator |
| `soc-audit` | `kibana_user`, `readall` | `readonly` | `soc` R | read-only (6) | activities_read, cases read-only |

Put that into [`config/sso-groups.conf`](../multi-node/config/sso-groups.conf)
(Wazuh side, applied automatically):

```text
soc-tier1|kibana_user,readall|readonly,agents_readonly|soc:RW
soc-tier2|kibana_user,readall|readonly,agents_readonly,cluster_readonly|soc:RW
soc-tier3|kibana_user,readall|agents_admin,cluster_readonly|ir:RW
soc-intel|kibana_user,readall|readonly|intel:RW
soc-manager|kibana_user,readall|readonly,cluster_readonly|soc:RW
soc-engineer|all_access|administrator|global_tenant:RW
soc-audit|kibana_user,readall|readonly|soc:R
```

then `./wazuh-deploy.sh sso init`. Members log out and back in.

### Applying it to IRIS

IRIS groups, their permission masks and their default case access are
declared in
[`config/iris-groups.conf`](../multi-node/config/iris-groups.conf) — the same
pattern as the Wazuh group map:

```bash
python3 scripts/iris-sync-groups.py --dry-run   # preview
python3 scripts/iris-sync-groups.py             # create/update the groups
python3 scripts/iris-sync-users.py              # map users + refresh case access
```

Shipped groups (permission bitmask in brackets — IRIS stores it as an int):
Administrators (65535), Analysts (1133), Read Only (5189), SOC Tier 1 (5197),
SOC Tier 2 (5485), SOC Tier 3 (7549), Threat Intel (5221), SOC Manager
(65381), Audit (7173). Reorganise the file and re-run; nothing else changes.

Note the two IRIS layers stay in step: the script sets **group permissions**
*and* **group case access**, then `iris-sync-users.py` recomputes
`user_case_effective_access` — miss that second step and users hold every
permission yet are refused every case.

### Principles worth keeping

- **Only `soc-engineer` gets `all_access` / `administrator`.** Analysts never
  need cluster admin to do analysis; separating this is what makes the audit
  trail meaningful.
- **Tier 3 gets `agents_admin`** (isolate a host, run active response) but not
  security-config rights.
- **Everything else is read + case work.** Write access to detections belongs
  to detection engineering, through change control.
- **Multi-tenant/MSSP:** add a `data_scope` column so a customer's analysts
  only query their own agents — see [SSO.md](SSO.md#permissions-one-file-three-layers).

---

## 3. Per-tool detail

### Wazuh

Three layers, all driven by the group map: **indexer roles** (which indices),
**Wazuh API roles** (which modules — MITRE, agents, rules), **tenant**
(which dashboards), plus optional **DLS** (which alerts). A group missing the
API-role mapping logs in fine and then sees *"You have no permissions"* on
every module — that is the single most common misconfiguration.

### MISP

Role ids used by the OIDC mapping (`OIDC_ROLES_MAPPING`):

| id | Role | Give to |
|---|---|---|
| 1 | admin | `soc-engineer` |
| 2 | Org Admin | `soc-intel` |
| 3 | User | `soc-tier2`, `soc-tier3` |
| 4 | Publisher | intel lead, if you publish events onward |
| 6 | Read Only | `soc-tier1`, `soc-manager`, `soc-audit` |

Air-gapped feeds: **Sync Actions → Feeds → Add** with a `local` input pointing
at a directory you drop files into — never a remote URL.

### DFIR-IRIS

IRIS has **two independent controls** (see its Access control docs):

**Permissions (RBAC)** — what platform features you can use:
`standard_user`, `server_administrator`, `alerts_read`, `alerts_write`,
`alerts_delete`, `search_across_cases`, `customers_read/write`,
`case_templates_read/write`, `activities_read`, `all_activities_read`.

**Case access (ACL)** — per case: `deny_all`, `read_only`, `full_access`.
Since v2.4.0 the default is **deny_all**, and precedence is
**customer → group → user**, with the atomic user setting winning. Use
IRIS *groups* mirroring the Keycloak groups above, and IRIS *customers* to
segregate business units or clients.

Suggested IRIS groups:

| IRIS group | Permissions | Default case access |
|---|---|---|
| `SOC Tier 1` | standard_user, alerts_read, alerts_write | read_only |
| `SOC Tier 2` | + search_across_cases | full_access |
| `SOC Tier 3` | + alerts_delete, all_activities_read | full_access |
| `SOC Manager` | + case_templates_write, activities_read | read_only |
| `Administrators` | server_administrator | full_access |

**Users must exist in IRIS** — for local, LDAP *and* OIDC, IRIS authenticates
by looking the account up, it does not create it on the fly. Provision with
`python3 scripts/iris-sync-users.py` (idempotent; re-run after adding people
to Keycloak).

---

## 4. Incident management workflow

```text
   Endpoint/agent            Wazuh rules              Analyst
        │                        │                       │
   event ├──► ingest ──► alert ──┤                       │
        │                        ├──► level >= 10 ───────┼──► IRIS ALERT
        │                        │    (custom-iris)      │    (auto)
        │                        └──► IoC lookup ────────┼──► MISP context
        │                             (custom-misp)      │
        ▼                                                ▼
   ACAS/Tenable scans ──► acas-vulns-* ──► correlation ──► IRIS CASE
                                                          │
                              ┌───────────────────────────┤
                              ▼                           ▼
                        containment                  evidence/timeline
                     (agents_admin, AR)             (notes, IOCs, tasks)
                              │                           │
                              └──────────► closure ◄──────┘
                                        (outcome, review)
```

### The six stages, mapped to the tools

**1. Detection (automatic).** Wazuh rules fire; alerts land in
`wazuh-alerts-*`. Anything at **level ≥ 10** is pushed into IRIS as an alert
by the `custom-iris` integration; observables are enriched from MISP by
`custom-misp`. Nothing needs a human yet.

**2. Triage — Tier 1.** Work the IRIS **Alerts** queue, not raw Wazuh.
For each alert decide: false positive (close with outcome), duplicate (merge),
or real (**escalate to a case**). Tier 1 has `alerts_read`/`alerts_write` and
read-only case access, so triage never mutates evidence. Target: every alert
dispositioned within the shift.

**3. Investigation — Tier 2 owns the case.** Escalation creates an IRIS case
with a **case template** (see below). The analyst pivots back into Wazuh
Threat Hunting for context, records IOCs in the case, and checks each one
against MISP (right-click → *Get MISP insight* via `IrisMispModule`). Findings
that are new intel get pushed *into* MISP so the next detection is automatic.

**4. Containment — Tier 3.** Isolation and active response need
`agents_admin` in the Wazuh API — deliberately restricted to Tier 3. Record
every action as an IRIS **task** with a timestamp; that list becomes the
response timeline.

**5. Eradication & recovery.** Track remediation as tasks with owners.
Cross-check ACAS/Tenable findings for the affected hosts
(`acas-vulns-*`, correlate on `host.name`) so you close the vulnerability that
allowed the incident, not just the symptom.

**6. Closure & review — Manager.** Set **case outcome** (true/false positive),
assign a **reviewer**, close the case. Weekly: review closed cases, convert
recurring findings into new Wazuh rules (detection engineering backlog) and
new MISP indicators. This loop is what makes the SOC improve.

### Severity → response expectations

| Wazuh level | IRIS severity | Meaning | Target response |
|---|---|---|---|
| 15 | Critical | Confirmed compromise/active attack | immediate, page on-call |
| 12–14 | High | Likely intrusion attempt | within 1 hour |
| 10–11 | Medium | Suspicious, needs analysis | same shift |
| 7–9 | Low | Policy/anomaly, batched review | next business day |
| < 7 | Informational | Context only, no alert created | none |

Wire the top two to email (or a webhook) via `<email_alerts>` —
see [ALERTING.md](ALERTING.md).

### Case templates worth creating

Create these once under **Advanced → Case templates** so every incident of a
type is worked the same way: **Malware/ransomware**, **Phishing**,
**Unauthorized access / account compromise**, **Data exfiltration**,
**Insider / policy violation**, **Vulnerability exploitation**. Each should
carry a task list matching the six stages and the note structure your
reporting requires.

---

## 5. Production checklist

Before go-live in the enclave:

- [ ] `config/sso-clients.conf` reflects the production domain/ports; run
      `sso clients` and confirm one distinct secret per service in `.env`
- [ ] `config/sso-groups.conf` reflects the SOC groups above; run `sso init`
- [ ] Keycloak groups created and populated (or federated from AD)
- [ ] IRIS users provisioned (`scripts/iris-sync-users.py`), IRIS groups and
      customers created, default case access confirmed as `deny_all`
- [ ] MISP roles verified by logging in as one member of each group
- [ ] MFA enforced in Keycloak for `soc-engineer` and `soc-manager` at minimum
      (IRIS can additionally enforce its own MFA under Server settings)
- [ ] Audit logging on: indexer `security-auditlog-*` (180 d retention),
      IRIS activities, MISP audit
- [ ] Email/webhook alerting tested end to end for level ≥ 12
- [ ] Break-glass local accounts documented and sealed: Wazuh `admin`,
      MISP admin, IRIS `administrator`, Keycloak `admin` — these are your way
      back in if the IdP is unavailable
- [ ] Backups cover: indexer data volumes, `misp-*` and `iris-*` volumes,
      Keycloak realm export, `.env`, `config/` and the offline CA
- [ ] Runbook printed/offline: how to rotate a client secret, re-issue a
      certificate, and restore a case from snapshot

### Break-glass

SSO is a single point of failure by design. Keep the local admin accounts
(listed above, passwords in `.env`) sealed in your credential vault and test
them quarterly — if Keycloak is down, they are the only way into Wazuh, MISP
and IRIS.
