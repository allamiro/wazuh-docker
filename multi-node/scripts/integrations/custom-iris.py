#!/var/ossec/framework/python/bin/python3
"""Wazuh -> DFIR-IRIS: open a case alert for high-severity Wazuh alerts.

Wired by an <integration> block in the manager config; Wazuh calls the shell
wrapper with (alert_file, api_key, hook_url). Everything stays inside the
siem network - no internet.
"""
import json
import sys
import ssl
import urllib.request

CA = "/etc/ssl/root-ca.pem"          # deployment root CA (already mounted)
SEVERITY = {0: 1, 7: 2, 10: 3, 13: 4}   # wazuh rule level -> IRIS severity id


def iris_severity(level):
    sev = 1
    for threshold, value in sorted(SEVERITY.items()):
        if level >= threshold:
            sev = value
    return sev


def main(alert_path, api_key, hook_url):
    with open(alert_path) as fh:
        alert = json.load(fh)

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    payload = {
        "alert_title": rule.get("description", "Wazuh alert"),
        "alert_description": json.dumps(alert, indent=2)[:8000],
        "alert_source": "Wazuh",
        "alert_source_ref": alert.get("id", ""),
        "alert_source_link": "https://siem.local.domain/app/wz-home",
        "alert_severity_id": iris_severity(int(rule.get("level", 0))),
        "alert_status_id": 2,               # New
        "alert_source_event_time": alert.get("timestamp", ""),
        "alert_note": f"rule {rule.get('id')} level {rule.get('level')}",
        "alert_tags": ",".join(rule.get("groups", []))[:200],
        "alert_customer_id": 1,
        "alert_source_content": alert,
        "alert_iocs": [
            {"ioc_value": v, "ioc_tlp_id": 2, "ioc_type_id": t}
            for v, t in filter(None, [
                (alert.get("data", {}).get("srcip"), 76),   # ip-src
                (agent.get("ip"), 76),
            ]) if v
        ],
    }

    ctx = ssl.create_default_context(cafile=CA)
    req = urllib.request.Request(
        hook_url.rstrip("/") + "/alerts/add",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {api_key}"},
        method="POST")
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        resp.read()


if __name__ == "__main__":
    # argv: 1=alert file, 2=api key, 3=hook url
    if len(sys.argv) < 4:
        sys.exit("usage: custom-iris.py <alert_file> <api_key> <hook_url>")
    try:
        main(sys.argv[1], sys.argv[2], sys.argv[3])
    except Exception as exc:                       # never break the manager
        with open("/var/ossec/logs/integrations.log", "a") as log:
            log.write(f"custom-iris error: {exc}\n")
