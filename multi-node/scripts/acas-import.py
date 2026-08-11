#!/usr/bin/env python3
"""Import ACAS / Tenable (Nessus) scan results into the Wazuh indexer.

This is the recommended air-gap integration: scan results are exported from
ACAS/Tenable.sc, carried across the gap like any other artefact, and indexed
into their own `acas-vulns-*` indices. Nothing is injected into Wazuh's
internals, so a bad or huge import can never disturb alert processing - and
you can correlate ACAS findings with Wazuh's own inventory-based vulnerability
data by host in the dashboard.

    python3 scripts/acas-import.py scan.nessus [more.nessus|dir/]
    python3 scripts/acas-import.py --dry-run scan.nessus

Accepts .nessus (XML) and Tenable CSV exports. Idempotent: the document _id is
a hash of (host, plugin id, port), so re-importing the same scan updates rather
than duplicates.
"""
import argparse
import csv
import glob
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDX_NODE = "master1.indexer"
INDEX_PREFIX = "acas-vulns"

SEVERITY = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}


def env(key):
    with open(os.path.join(ROOT, ".env")) as fh:
        for line in fh:
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
    sys.exit(f"[FAIL] {key} missing from .env")


def doc_id(host, plugin, port):
    return hashlib.sha256(f"{host}|{plugin}|{port}".encode()).hexdigest()[:32]


def parse_nessus(path):
    """Yield one document per reported finding in a .nessus XML export."""
    tree = ET.parse(path)
    for host in tree.getroot().iter("ReportHost"):
        name = host.get("name")
        props = {t.get("name"): t.text for t in host.iter("tag")}
        for item in host.iter("ReportItem"):
            sev = item.get("severity", "0")
            yield {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "scanner": "ACAS/Tenable",
                "host": {
                    "name": props.get("host-fqdn") or name,
                    "ip": props.get("host-ip") or name,
                    "os": props.get("operating-system"),
                },
                "vulnerability": {
                    "id": (item.findtext("cve") or ""),
                    "plugin_id": item.get("pluginID"),
                    "plugin_name": item.get("pluginName"),
                    "family": item.get("pluginFamily"),
                    "severity": SEVERITY.get(sev, "info"),
                    "severity_id": int(sev),
                    "cvss3_base_score": _float(item.findtext("cvss3_base_score")),
                    "description": (item.findtext("description") or "")[:4000],
                    "solution": (item.findtext("solution") or "")[:2000],
                },
                "network": {"port": item.get("port"), "protocol": item.get("protocol")},
                "_id": doc_id(name, item.get("pluginID"), item.get("port")),
            }


def parse_csv(path):
    """Yield documents from a Tenable CSV export (column names vary a little)."""
    def pick(row, *names):
        for n in names:
            if n in row and row[n]:
                return row[n]
        return None

    with open(path, newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            host = pick(row, "Host", "DNS Name", "IP Address", "asset.name") or "unknown"
            plugin = pick(row, "Plugin ID", "Plugin", "plugin.id") or "0"
            port = pick(row, "Port", "port") or "0"
            sev_name = (pick(row, "Severity", "severity") or "info").lower()
            yield {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "scanner": "ACAS/Tenable",
                "host": {"name": host, "ip": pick(row, "IP Address", "ip"),
                         "os": pick(row, "OS", "operating-system")},
                "vulnerability": {
                    "id": pick(row, "CVE", "cve") or "",
                    "plugin_id": plugin,
                    "plugin_name": pick(row, "Name", "Plugin Name", "plugin.name"),
                    "family": pick(row, "Family", "Plugin Family"),
                    "severity": sev_name,
                    "severity_id": {"info": 0, "low": 1, "medium": 2,
                                    "high": 3, "critical": 4}.get(sev_name, 0),
                    "cvss3_base_score": _float(pick(row, "CVSS V3 Base Score", "CVSS3 Base Score")),
                    "description": (pick(row, "Description", "Synopsis") or "")[:4000],
                    "solution": (pick(row, "Solution") or "")[:2000],
                },
                "network": {"port": port, "protocol": pick(row, "Protocol", "protocol")},
                "_id": doc_id(host, plugin, port),
            }


def _float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def bulk(docs, index, dry_run):
    """Send a bulk request from inside the trust domain (TLS verified)."""
    lines = []
    for d in docs:
        _id = d.pop("_id")
        lines.append(json.dumps({"index": {"_index": index, "_id": _id}}))
        lines.append(json.dumps(d))
    if not lines:
        return 0, 0
    if dry_run:
        return len(lines) // 2, 0
    payload = "\n".join(lines) + "\n"
    proc = subprocess.run(
        ["docker", "exec", "-i", IDX_NODE, "curl", "-s",
         "--cacert", "/usr/share/wazuh-indexer/config/certs/root-ca.pem",
         "-u", f"admin:{env('INDEXER_PASSWORD')}",
         "-H", "Content-Type: application/x-ndjson",
         "-X", "POST", f"https://{IDX_NODE}:9200/_bulk", "--data-binary", "@-"],
        input=payload, capture_output=True, text=True)
    try:
        res = json.loads(proc.stdout)
    except json.JSONDecodeError:
        sys.exit(f"[FAIL] bulk request failed: {proc.stdout[:200]}{proc.stderr[:200]}")
    errors = sum(1 for i in res.get("items", []) if i.get("index", {}).get("error"))
    return len(res.get("items", [])), errors


def ensure_template(dry_run):
    """Index template so severity/score/date fields are typed correctly."""
    if dry_run:
        return
    body = {
        "index_patterns": [f"{INDEX_PREFIX}-*"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 1},
            "mappings": {"properties": {
                "@timestamp": {"type": "date"},
                "scanner": {"type": "keyword"},
                "host": {"properties": {"name": {"type": "keyword"},
                                        "ip": {"type": "ip", "ignore_malformed": True},
                                        "os": {"type": "keyword"}}},
                "vulnerability": {"properties": {
                    "id": {"type": "keyword"}, "plugin_id": {"type": "keyword"},
                    "plugin_name": {"type": "text"}, "family": {"type": "keyword"},
                    "severity": {"type": "keyword"}, "severity_id": {"type": "integer"},
                    "cvss3_base_score": {"type": "float"},
                    "description": {"type": "text"}, "solution": {"type": "text"}}},
                "network": {"properties": {"port": {"type": "keyword"},
                                           "protocol": {"type": "keyword"}}},
            }},
        },
    }
    subprocess.run(
        ["docker", "exec", "-i", IDX_NODE, "curl", "-s", "-o", "/dev/null",
         "--cacert", "/usr/share/wazuh-indexer/config/certs/root-ca.pem",
         "-u", f"admin:{env('INDEXER_PASSWORD')}",
         "-H", "Content-Type: application/json",
         "-X", "PUT", f"https://{IDX_NODE}:9200/_index_template/{INDEX_PREFIX}",
         "-d", json.dumps(body)], capture_output=True, text=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help=".nessus / .csv files or directories")
    ap.add_argument("--dry-run", action="store_true", help="parse only, index nothing")
    ap.add_argument("--index", default=None,
                    help=f"target index (default {INDEX_PREFIX}-YYYY.MM.DD)")
    args = ap.parse_args()

    files = []
    for p in args.paths:
        files.extend(sorted(glob.glob(os.path.join(p, "*")))
                     if os.path.isdir(p) else [p])
    files = [f for f in files if f.lower().endswith((".nessus", ".xml", ".csv"))]
    if not files:
        sys.exit("[FAIL] no .nessus/.csv files found")

    index = args.index or f"{INDEX_PREFIX}-{datetime.now(timezone.utc):%Y.%m.%d}"
    ensure_template(args.dry_run)

    total = errors = 0
    for path in files:
        parser = parse_csv if path.lower().endswith(".csv") else parse_nessus
        docs = list(parser(path))
        n, e = bulk(docs, index, args.dry_run)
        total += n
        errors += e
        print(f"  {os.path.basename(path):<40} {n:>6} findings"
              + (f"  ({e} errors)" if e else ""))

    print(f"\n{'[DRY RUN] would index' if args.dry_run else 'Indexed'} "
          f"{total} findings into {index}"
          + (f" ({errors} errors)" if errors else ""))
    if not args.dry_run:
        print("Create the index pattern 'acas-vulns-*' in the dashboard to explore,")
        print("then correlate with Wazuh's own findings on host.name.")


if __name__ == "__main__":
    main()
