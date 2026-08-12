#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Download / build every DFIR-IRIS module wheel on a CONNECTED machine so the
# air-gapped side can install or upgrade modules without an index.
#
#   ./scripts/iris-modules-fetch.sh                 # all known modules
#   ./scripts/iris-modules-fetch.sh iris-misp-module
#   ./scripts/iris-modules-fetch.sh --list
#
# Wheels land in airgap-cache/iris-modules/ and travel inside
# './wazuh-deploy.sh airgap bundle'. On the target:
#
#   python3 scripts/iris-modules.py install airgap-cache/iris-modules/<file>.whl
#   python3 scripts/iris-modules.py upgrade-all          # install every cached wheel
#
# Modules already inside the IRIS image do NOT need this - use it to pick up a
# newer module version than the image ships, or to add a module that is not
# bundled at all.
# -----------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="airgap-cache/iris-modules"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# module repositories published by the DFIR-IRIS project
MODULES="
iris-misp-module https://github.com/dfir-iris/iris-misp-module.git
iris-webhooks-module https://github.com/dfir-iris/iris-webhooks-module.git
iris-vt-module https://github.com/dfir-iris/iris-vt-module.git
iris-check-module https://github.com/dfir-iris/iris-check-module.git
iris-evtx-module https://github.com/dfir-iris/iris-evtx-module.git
iris-intelowl-module https://github.com/dfir-iris/iris-intelowl-module.git
"

if [[ "${1:-}" == "--list" ]]; then
  echo "Known modules:"
  echo "$MODULES" | awk 'NF {printf "  %-24s %s\n", $1, $2}'
  exit 0
fi

command -v git >/dev/null || { echo "[!] git is required on this (connected) host" >&2; exit 1; }
python3 -c "import wheel, setuptools" 2>/dev/null || {
  echo "[*] installing build deps (python3 -m pip install --user wheel setuptools)"
  python3 -m pip install --user --quiet wheel setuptools
}

mkdir -p "$OUT"
wanted="${*:-}"
built=0 failed=0

echo "$MODULES" | while read -r name url; do
  [[ -z "$name" ]] && continue
  if [[ -n "$wanted" ]] && ! grep -qw "$name" <<< "$wanted"; then continue; fi

  echo "[*] $name"
  if ! git clone --depth 1 -q "$url" "$WORK/$name" 2>/dev/null; then
    echo "    [FAIL] clone failed - skipping"
    failed=$((failed+1)); continue
  fi
  (
    cd "$WORK/$name"
    # newer modules use pyproject/build, older ones setup.py
    if python3 -m build --wheel --outdir dist >/dev/null 2>&1 \
       || python3 setup.py -q bdist_wheel >/dev/null 2>&1; then
      cp dist/*.whl "$OLDPWD/$OUT/" 2>/dev/null
    else
      exit 1
    fi
  ) && { echo "    [OK] $(ls -1 "$OUT" | grep -i "${name//-/_}" | tail -1)"; built=$((built+1)); } \
    || echo "    [FAIL] wheel build failed"
done

echo
echo "Wheels in $OUT:"
ls -1sh "$OUT"/*.whl 2>/dev/null | sed 's/^/  /' || echo "  (none)"
cat <<EOF

These travel inside the air-gap bundle:
  ./wazuh-deploy.sh airgap bundle

On the air-gapped host, after 'airgap import':
  python3 scripts/iris-modules.py upgrade-all
  docker compose restart iris-app iris-worker
EOF
