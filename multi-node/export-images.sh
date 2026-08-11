#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Export every container image this deployment can use into ONE tar file, ready
# to carry across the air gap.
#
# Run this on a CONNECTED machine. It pulls what is missing, saves everything,
# and writes a checksum + manifest next to the tar.
#
#   ./export-images.sh                  # core + all optional modules (default)
#   ./export-images.sh --core-only      # just the Wazuh stack, no modules
#   ./export-images.sh --output /media/usb/wazuh-images
#
# On the air-gapped side:
#   docker load -i wazuh-images.tar
# ...or simply use the full bundle instead, which also carries the repository,
# the CVE feed and the map tiles:
#   ./wazuh-deploy.sh airgap bundle
# -----------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

WAZUH_VERSION="${WAZUH_VERSION:-4.14.7}"
OUT_DIR="images-export"
CORE_ONLY=no

while [[ $# -gt 0 ]]; do
  case "$1" in
    --core-only) CORE_ONLY=yes ;;
    --output)    OUT_DIR="$2"; shift ;;
    --version)   WAZUH_VERSION="$2"; shift ;;
    -h|--help)   sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "[!] unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

core_images() {
  cat <<EOF
wazuh/wazuh-manager:$WAZUH_VERSION
wazuh/wazuh-indexer:$WAZUH_VERSION
wazuh/wazuh-dashboard:$WAZUH_VERSION
nginx:1.29-alpine
smallstep/step-ca:latest
EOF
}

module_images() {
  cat <<EOF
rustfs/rustfs:${RUSTFS_VERSION:-1.0.0-rc.1}
rclone/rclone:${RCLONE_VERSION:-1.68}
opensearchproject/opensearch-maps-server:${MAPS_VERSION:-1.0.0}
quay.io/keycloak/keycloak:${KEYCLOAK_VERSION:-26.0}
ghcr.io/misp/misp-docker/misp-core:${MISP_VERSION:-v2.5.1}
ghcr.io/misp/misp-docker/misp-modules:${MISP_MODULES_VERSION:-latest}
ghcr.io/dfir-iris/iriswebapp_app:${IRIS_VERSION:-v2.4.20}
ghcr.io/dfir-iris/iriswebapp_db:${IRIS_VERSION:-v2.4.20}
mariadb:${MARIADB_VERSION:-10.11}
valkey/valkey:${VALKEY_VERSION:-7.2}
rabbitmq:${RABBITMQ_VERSION:-3-management}
EOF
}

mkdir -p "$OUT_DIR"

# The agent image is BUILT locally (stock image lacks the Docker SDK the
# docker-listener wodle needs), so build it before saving.
if [[ "$CORE_ONLY" == "no" ]]; then
  echo "[*] Building the agent image (adds the Python Docker SDK)..."
  docker build -q -t "wazuh-agent-docker:$WAZUH_VERSION" \
    --build-arg "WAZUH_VERSION=$WAZUH_VERSION" build/wazuh-agent-docker >/dev/null
fi

IMAGES=$(core_images)
if [[ "$CORE_ONLY" == "no" ]]; then
  IMAGES="$IMAGES
$(module_images)
wazuh-agent-docker:$WAZUH_VERSION"
fi

echo "[*] Ensuring every image is present locally..."
while read -r img; do
  [[ -z "$img" ]] && continue
  if docker image inspect "$img" >/dev/null 2>&1; then
    echo "    have  $img"
  else
    echo "    pull  $img"
    # wazuh-agent-docker is local-only; never try to pull it
    [[ "$img" == wazuh-agent-docker:* ]] || docker pull -q "$img" >/dev/null
  fi
done <<< "$IMAGES"

TAR="$OUT_DIR/wazuh-images.tar"
echo "[*] Saving $(grep -c . <<< "$IMAGES") images -> $TAR (this takes a few minutes)"
# shellcheck disable=SC2046
docker save -o "$TAR" $(tr '\n' ' ' <<< "$IMAGES")

echo "[*] Writing checksum + manifest"
( cd "$OUT_DIR" && openssl dgst -sha256 -r wazuh-images.tar > SHA256SUMS )
{
  echo "# Wazuh air-gap image set"
  echo "# created:       $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# wazuh version: $WAZUH_VERSION"
  echo "# scope:         $([[ "$CORE_ONLY" == yes ]] && echo 'core only' || echo 'core + all optional modules')"
  echo
  echo "$IMAGES" | grep -c . | xargs -I{} echo "{} images:"
  echo "$IMAGES" | grep . | sed 's/^/  /'
} > "$OUT_DIR/MANIFEST.txt"

SIZE=$(du -h "$TAR" | cut -f1)
cat <<EOF

Done. $SIZE written to $OUT_DIR/

  wazuh-images.tar   the images
  SHA256SUMS         verify after the transfer:  shasum -a 256 -c SHA256SUMS
  MANIFEST.txt       what is inside

Copy the directory to the air-gapped host, then:

  shasum -a 256 -c SHA256SUMS      # or: sha256sum -c SHA256SUMS
  docker load -i wazuh-images.tar
EOF
