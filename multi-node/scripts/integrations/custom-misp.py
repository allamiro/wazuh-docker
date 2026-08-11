#!/var/ossec/framework/python/bin/python3
"""Wazuh -> MISP: enrich alerts by looking up observables in MISP.

If MISP knows the IoC (ip/domain/hash) the script emits a new Wazuh event
(rule group misp_alert) so it is indexed and alertable like any other.
Air-gapped: talks only to the local MISP instance.
"""
import json
import re
import socket
import ssl
import sys
import urllib.request

CA = "/etc/ssl/root-ca.pem"
SOCKET_ADDR = "/var/ossec/queue/sockets/queue"
IOC_FIELDS = ("srcip", "dstip", "md5", "sha1", "sha256", "hostname", "url")


def send_event(msg):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.connect(SOCKET_ADDR)
    sock.send(f"1:misp:{json.dumps(msg)}".encode())
    sock.close()


def lookup(value, api_key, base_url, ctx):
    req = urllib.request.Request(
        base_url.rstrip("/") + "/attributes/restSearch",
        data=json.dumps({"value": value, "limit": 1}).encode(),
        headers={"Authorization": api_key, "Accept": "application/json",
                 "Content-Type": "application/json"},
        method="POST")
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        data = json.loads(resp.read() or b"{}")
    return data.get("response", {}).get("Attribute", [])


def main(alert_path, api_key, base_url):
    with open(alert_path) as fh:
        alert = json.load(fh)
    data = alert.get("data", {})
    ctx = ssl.create_default_context(cafile=CA)

    for field in IOC_FIELDS:
        value = data.get(field)
        if not value or not re.match(r"^[\w\.\-:/]{4,255}$", str(value)):
            continue
        hits = lookup(value, api_key, base_url, ctx)
        if hits:
            hit = hits[0]
            send_event({
                "misp": {
                    "source": {"rule_id": alert.get("rule", {}).get("id"),
                               "alert_id": alert.get("id"),
                               "agent": alert.get("agent", {}).get("name")},
                    "ioc": value, "field": field,
                    "category": hit.get("category"),
                    "type": hit.get("type"),
                    "event_id": hit.get("event_id"),
                    "comment": hit.get("comment", "")[:200],
                }
            })


if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.exit("usage: custom-misp.py <alert_file> <api_key> <misp_url>")
    try:
        main(sys.argv[1], sys.argv[2], sys.argv[3])
    except Exception as exc:
        with open("/var/ossec/logs/integrations.log", "a") as log:
            log.write(f"custom-misp error: {exc}\n")
