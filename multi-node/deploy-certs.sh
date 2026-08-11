#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Deployment adapters for the validated PKI material.
#
# The PKI layer (generate-certs.sh: csr -> sign -> import -> verify) is
# deployment-agnostic. This script is the consumer side:
#
#   ./deploy-certs.sh docker              Validate certs + check every file
#                                         docker-compose.yml mounts exists.
#                                         Compose only MOUNTS certificates -
#                                         it never creates identities.
#
#   ./deploy-certs.sh export              Build per-node distribution packages
#                                         under dist/ for VM / bare-metal
#                                         installs (each node gets ONLY its own
#                                         key, its cert, and root-ca.pem).
#
#   ./deploy-certs.sh vm --node <name>    Package a single node, e.g.
#                                         ./deploy-certs.sh vm --node master1.indexer
#
# Nothing is ever copied to remote machines automatically - in air-gapped
# environments certificate material moves through controlled administrative
# channels. Transfer dist/<node>/ yourself, then run the local verification
# printed in each package's INSTALL.txt on the target server.
# -----------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

SIEM_DOMAIN="${SIEM_DOMAIN:-${DOMAIN:-siem.local.domain}}"
OUT_DIR="${OUT_DIR:-config/wazuh_indexer_ssl_certs}"
INVENTORY="${INVENTORY:-config/certs-inventory.conf}"
DIST_DIR="${DIST_DIR:-dist}"

inventory() {
  grep -Ev '^\s*(#|$)' "$INVENTORY" | sed "s/@DOMAIN@/$SIEM_DOMAIN/g"
}

preflight() {
  echo "[*] Running certificate preflight first..."
  OUT_DIR="$OUT_DIR" SIEM_DOMAIN="$SIEM_DOMAIN" ./generate-certs.sh verify
  echo
}

install_notes() {
  # role-specific install instructions (paths from the official Wazuh
  # bare-metal/offline installation layout)
  local name="$1" role="$2"
  case "$role" in
    indexer) cat <<EOF
Target files on the indexer server:
  /etc/wazuh-indexer/certs/$name.pem
  /etc/wazuh-indexer/certs/$name-key.pem
  /etc/wazuh-indexer/certs/root-ca.pem
Ownership/permissions:
  chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
  chmod 500 /etc/wazuh-indexer/certs && chmod 400 /etc/wazuh-indexer/certs/*
opensearch.yml must reference these paths (see the ssl.http/ssl.transport
sections shipped in config/wazuh_indexer/$name.yml).
EOF
      ;;
    filebeat) cat <<EOF
Target files on the Wazuh server:
  /etc/filebeat/certs/$name.pem
  /etc/filebeat/certs/$name-key.pem
  /etc/filebeat/certs/root-ca.pem
Ownership/permissions:
  chmod 500 /etc/filebeat/certs && chmod 400 /etc/filebeat/certs/*
filebeat.yml: output.elasticsearch.ssl.certificate/key/certificate_authorities.
EOF
      ;;
    wazuh-api) cat <<EOF
Target files on the Wazuh master:
  /var/ossec/api/configuration/ssl/server.crt   <- $name.pem
  /var/ossec/api/configuration/ssl/server.key   <- $name-key.pem
Restart wazuh-manager afterwards. Without this the API serves a
self-signed auto-generated certificate.
EOF
      ;;
    authd) cat <<EOF
Target files on the Wazuh master (agent enrollment, port 1515):
  /var/ossec/etc/sslmanager.cert   <- $name.pem
  /var/ossec/etc/sslmanager.key    <- $name-key.pem
Agents that should verify the manager also need root-ca.pem and
<server-ca-path> in their ossec.conf.
EOF
      ;;
    dashboard) cat <<EOF
Target files on the dashboard server:
  /etc/wazuh-dashboard/certs/$name.pem
  /etc/wazuh-dashboard/certs/$name-key.pem
  /etc/wazuh-dashboard/certs/root-ca.pem
opensearch_dashboards.yml: server.ssl.certificate/key +
opensearch.ssl.certificateAuthorities.
EOF
      ;;
    admin-client) cat <<EOF
This is the securityadmin CLIENT identity, not a service certificate.
Keep it on a protected administrative workstation; copy it to an indexer
node only for the duration of securityadmin.sh runs.
EOF
      ;;
  esac
}

package_node() {
  local name="$1" role="$2"
  local pkg="$DIST_DIR/$name"
  mkdir -p "$pkg"
  cp "$OUT_DIR/$name.pem" "$OUT_DIR/$name-key.pem" "$OUT_DIR/root-ca.pem" "$pkg/"
  chmod 600 "$pkg/$name-key.pem"

  {
    echo "Certificate package: $name  (role: $role)"
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "Contents:"
    echo "  $name.pem        signed certificate (leaf first, then any intermediate)"
    echo "  $name-key.pem    PRIVATE KEY - only this server may hold it"
    echo "  root-ca.pem      trust chain (intermediate(s) then root)"
    echo
    install_notes "$name" "$role"
    cat <<'EOF'

Local verification AFTER installing on the target server:
  openssl verify -CAfile root-ca.pem <name>.pem
  # key <-> certificate match (the two hashes must be identical):
  openssl pkey -in <name>-key.pem -pubout -outform DER | openssl dgst -sha256
  openssl x509 -in <name>.pem -pubkey -noout | openssl pkey -pubin -pubout -outform DER | openssl dgst -sha256

SECURITY: this package contains a private key. Transfer it only over your
controlled administrative channel, directly to the server that owns this
identity, and wipe intermediate copies.
EOF
  } > "$pkg/INSTALL.txt"

  # role-specific install.sh (run as root on the target server)
  local dest owner=""
  case "$role" in
    indexer)   dest=/etc/wazuh-indexer/certs;   owner=wazuh-indexer:wazuh-indexer ;;
    filebeat)  dest=/etc/filebeat/certs ;;
    dashboard) dest=/etc/wazuh-dashboard/certs; owner=wazuh-dashboard:wazuh-dashboard ;;
    wazuh-api) dest=/var/ossec/api/configuration/ssl ;;
    authd)     dest=/var/ossec/etc ;;
    *)         dest="" ;;
  esac
  if [[ -n "$dest" ]]; then
    {
      echo '#!/usr/bin/env bash'
      echo '# Installs this node'"'"'s certificate material into the official Wazuh paths.'
      echo '# Run as root on the target server, from inside this directory.'
      echo 'set -euo pipefail'
      echo 'cd "$(dirname "$0")"'
      echo "mkdir -p $dest"
      case "$role" in
        wazuh-api)
          echo "install -m 400 $name.pem $dest/server.crt"
          echo "install -m 400 $name-key.pem $dest/server.key"
          echo "chown root:wazuh $dest/server.crt $dest/server.key 2>/dev/null || true" ;;
        authd)
          echo "install -m 400 $name.pem $dest/sslmanager.cert"
          echo "install -m 400 $name-key.pem $dest/sslmanager.key" ;;
        *)
          echo "install -m 400 $name.pem $name-key.pem root-ca.pem $dest/"
          [[ -n "$owner" ]] && echo "chown -R $owner $dest"
          echo "chmod 500 $dest" ;;
      esac
      echo 'echo "installed - now run ./verify.sh, then restart the service"'
    } > "$pkg/install.sh"
    chmod +x "$pkg/install.sh"
  fi

  # local post-install verification (no CA key needed)
  cat > "$pkg/verify.sh" <<EOF
#!/usr/bin/env bash
# Local verification for the '$name' certificate package.
set -euo pipefail
cd "\$(dirname "\$0")"
openssl verify -CAfile root-ca.pem -untrusted $name.pem $name.pem
kh=\$(openssl pkey -in $name-key.pem -pubout -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1)
ch=\$(openssl x509 -in $name.pem -pubkey -noout | openssl pkey -pubin -pubout -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1)
[[ "\$kh" == "\$ch" ]] && echo "key matches certificate" || { echo "KEY/CERT MISMATCH"; exit 1; }
openssl x509 -in $name.pem -noout -checkend 2592000 >/dev/null \\
  && echo "validity: >30 days remaining" || echo "WARNING: expires within 30 days"
echo "PASS: $name"
EOF
  chmod +x "$pkg/verify.sh"

  ( cd "$pkg" && openssl dgst -sha256 -r ./*.pem > SHA256SUMS )
  echo "[PKG ] $pkg/"
}

cmd_docker() {
  preflight
  echo "[*] Cross-checking docker-compose.yml certificate mounts..."
  local missing=0 f
  while read -r f; do
    if [[ ! -f "$f" ]]; then
      echo "[FAIL] mounted in compose but missing on disk: $f"
      missing=$((missing+1))
    fi
  done < <(grep -oE '\./config/wazuh_indexer_ssl_certs/[^:]+' docker-compose.yml | sort -u | sed 's|^\./||')
  if (( missing > 0 )); then
    echo
    echo "DEPLOYMENT BLOCKED."
    exit 1
  fi
  echo "[OK] every certificate referenced by docker-compose.yml exists"
  echo
  echo "Ready. Start the stack with:"
  echo "  docker compose up -d"
}

cmd_export() {
  preflight
  mkdir -p "$DIST_DIR"
  while IFS='|' read -r name role _; do
    package_node "$name" "$role"
  done < <(inventory)
  echo
  echo "Packages ready under $DIST_DIR/ - one directory per identity."
  echo "Distribute each ONLY to the server that owns it (see INSTALL.txt inside)."
}

cmd_vm() {
  local node=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --node)   node="$2"; shift ;;
      --node=*) node="${1#--node=}" ;;
      *) echo "[!] Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
  done
  [[ -n "$node" ]] || { echo "Usage: $0 vm --node <name>" >&2; exit 1; }
  local line
  line=$(inventory | grep -E "^$node\|" || true)
  [[ -n "$line" ]] || { echo "[!] '$node' is not in $INVENTORY" >&2; exit 1; }
  preflight
  mkdir -p "$DIST_DIR"
  package_node "$node" "$(echo "$line" | cut -d'|' -f2)"
}

case "${1:-}" in
  docker) shift; cmd_docker "$@" ;;
  export) shift; cmd_export "$@" ;;
  vm)     shift; cmd_vm "$@" ;;
  *) echo "Usage: $0 {docker|export|vm --node <name>}" >&2; exit 1 ;;
esac
