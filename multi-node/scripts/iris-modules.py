#!/usr/bin/env python3
"""Enable and configure DFIR-IRIS modules - offline friendly.

Every module IRIS ships with is already baked into the container image
(iris_misp_module, iris_webhooks_module, iris_vt_module, iris_check_module,
iris_intelowl_module), so an air-gapped deployment needs no downloads at all:
the modules only have to be ENABLED and CONFIGURED. This script does that
against the IRIS database, which is where the module registry and each
module's JSON configuration live.

    python3 scripts/iris-modules.py list
    python3 scripts/iris-modules.py enable  iris_misp_module
    python3 scripts/iris-modules.py disable iris_webhooks_module
    python3 scripts/iris-modules.py configure-misp     # point it at our MISP
    python3 scripts/iris-modules.py configure-webhook <url>

Adding a module that is NOT in the image (air gap):
    # on the connected staging host
    git clone https://github.com/dfir-iris/<module>.git && cd <module>
    python3 setup.py bdist_wheel
    cp dist/*.whl <repo>/multi-node/airgap-cache/iris-modules/
    # ...ships inside the air-gap bundle; then on the target:
    python3 scripts/iris-modules.py install airgap-cache/iris-modules/<file>.whl
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / ".env"
DB = "iris-db"
APP = "iris-app"
DBUSER = "raccoon_admin"
DBNAME = "iris_db"


def env(key, default=None):
    for line in ENV.read_text().splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    if default is not None:
        return default
    sys.exit(f"[FAIL] {key} missing from .env")


def sql(query, quiet=False):
    out = subprocess.run(["docker", "exec", DB, "psql", "-U", DBUSER, "-d", DBNAME,
                          "-tAc", query], capture_output=True, text=True)
    if out.returncode != 0 and not quiet:
        sys.exit(f"[FAIL] {out.stderr.strip()[:200]}")
    return out.stdout.strip()


def cmd_list():
    rows = sql("select id, module_name, module_version, is_active from iris_module order by id")
    print(f"{'id':<4}{'module':<26}{'version':<10}enabled")
    for line in rows.splitlines():
        mid, name, ver, active = (line.split("|") + ["", "", ""])[:4]
        print(f"{mid:<4}{name:<26}{ver:<10}{'yes' if active == 't' else 'no'}")
    print("\nAll of the above ship inside the image - no downloads needed.")


def set_active(name, active):
    state = "true" if active else "false"
    sql(f"update iris_module set is_active = {state} where module_name = '{name}'")
    print(f"[OK] {name} {'enabled' if active else 'disabled'}")
    print("     restart to apply:  docker compose restart iris-app iris-worker")


def cmd_configure_misp():
    """Point IrisMISP at the MISP deployed in this stack."""
    misp_key = env("MISP_API_KEY", "SET_ME_IN_MISP_UI")
    domain = env("SIEM_DOMAIN", "siem.local.domain")
    misp_cfg = {
        "name": "SIEM_MISP",
        "type": "private",
        # internal service name: the module talks to MISP over the siem network
        "url": ["https://misp"],
        "key": [misp_key],
        # our MISP presents a certificate signed by the deployment CA, which
        # the container trusts (see scripts/iris-init.sh)
        "ssl": [True],
    }
    current = sql("select module_config from iris_module where module_name = 'iris_misp_module'")
    try:
        cfg = json.loads(current) if current else []
    except json.JSONDecodeError:
        cfg = []

    def put(param, value):
        for item in cfg:
            if item.get("param_name") == param:
                item["value"] = value
                return
        cfg.append({"param_name": param, "value": value})

    put("misp_config", json.dumps(misp_cfg))
    put("misp_report_as_attribute", True)
    put("misp_on_create_hook_enabled", True)   # enrich new IOCs automatically
    put("misp_on_update_hook_enabled", True)
    put("misp_manual_hook_enabled", True)      # right-click "Get MISP insight"

    payload = json.dumps(cfg).replace("'", "''")
    sql(f"update iris_module set module_config = '{payload}' where module_name = 'iris_misp_module'")
    set_active("iris_misp_module", True)
    if misp_key == "SET_ME_IN_MISP_UI":
        print("[WARN] MISP_API_KEY is not in .env yet - create an API key in MISP")
        print("       (Administration -> List Auth Keys -> Add), then:")
        print("       echo 'MISP_API_KEY=<key>' >> .env && re-run this command")


def cmd_configure_webhook(url):
    cfg_body = {
        "instance_url": f"https://iris.{env('SIEM_DOMAIN', 'siem.local.domain')}:8082",
        "webhooks": [{
            "name": "soc-notifications",
            "active": True,
            "trigger_on": ["on_postload_alert_create", "on_postload_case_create"],
            "request_url": url,
            "use_rendering": True,
            "request_rendering": "markdown",
            "request_body": {"text": "%TITLE% - %DESCRIPTION%"},
        }],
    }
    current = sql("select module_config from iris_module where module_name = 'iris_webhooks_module'")
    try:
        cfg = json.loads(current) if current else []
    except json.JSONDecodeError:
        cfg = []
    for item in cfg:
        if item.get("param_name") == "webhooks_config":
            item["value"] = json.dumps(cfg_body)
            break
    else:
        cfg.append({"param_name": "webhooks_config", "value": json.dumps(cfg_body)})
    payload = json.dumps(cfg).replace("'", "''")
    sql(f"update iris_module set module_config = '{payload}' where module_name = 'iris_webhooks_module'")
    set_active("iris_webhooks_module", True)


def cmd_install(wheel):
    """Install a module wheel that was built on the connected side."""
    path = Path(wheel)
    if not path.exists():
        sys.exit(f"[FAIL] {wheel} not found")
    for container in (APP, "iris-worker"):
        subprocess.run(["docker", "cp", str(path), f"{container}:/iriswebapp/dependencies/"],
                       check=True)
        subprocess.run(["docker", "exec", container, "pip3", "install", "--no-index",
                        f"/iriswebapp/dependencies/{path.name}"], check=False)
    print(f"[OK] installed {path.name} into iris-app and iris-worker")
    print("     restart to register: docker compose restart iris-app iris-worker")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "list":
        cmd_list()
    elif cmd == "enable" and len(sys.argv) > 2:
        set_active(sys.argv[2], True)
    elif cmd == "disable" and len(sys.argv) > 2:
        set_active(sys.argv[2], False)
    elif cmd == "configure-misp":
        cmd_configure_misp()
    elif cmd == "configure-webhook" and len(sys.argv) > 2:
        cmd_configure_webhook(sys.argv[2])
    elif cmd == "install" and len(sys.argv) > 2:
        cmd_install(sys.argv[2])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
