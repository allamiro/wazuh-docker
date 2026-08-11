#!/usr/bin/env bash
# =============================================================================
# wazuh-deploy.sh - unified deployment CLI for the airgp Wazuh stack.
#
# One framework, four modes:
#   connected + docker      connected + baremetal
#   air-gapped + docker     air-gapped + baremetal
#
# This is an ORCHESTRATION layer over the proven single-purpose tools:
#   generate-credentials.sh   credentials / cluster key
#   generate-certs.sh         PKI lifecycle (csr / sign / import / verify)
#   deploy-certs.sh           deployment adapters (docker mounts / VM packages)
#   docker-compose.yml        the pinned enterprise topology
#
# Commands:
#   configure                 interactive (or flag-driven) setup -> config/deployment.yml
#   validate                  preflight gate - blocks deployment on failure
#   fetch                     connected: pull images / download packages
#   airgap bundle             connected staging host: build transfer bundle
#   airgap import <dir>       air-gapped host: checksum-verify + import bundle
#   pki csr|export-csr|sign|import <dir>|verify
#   deploy docker|baremetal
#   verify                    runtime verification of a deployed stack
#   status                    quick container status
#
# The shipped Docker topology (23 containers) is pinned; deployment.yml selects
# HOW it is deployed, not an arbitrary re-shape of the cluster.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

CONFIG=config/deployment.yml
NODES=config/nodes.yml
INVENTORY=config/certs-inventory.conf
CACHE=airgap-cache

# ----------------------------------------------------------------- helpers ---
say()  { printf '%s\n' "$*"; }
ok()   { printf '[OK]   %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; }
failm(){ printf '[FAIL] %s\n' "$*"; }

# Minimal reader for our two-level YAML ("section:" then "  key: value").
cfg() { # cfg <section> <key> [default]
  local v
  v=$(awk -v s="$1:" -v k="$2:" '
    $0 ~ "^"s"$" {insec=1; next}
    /^[^ ]/ {insec=0}
    insec && $1 == k {sub(/^[^:]*:[ ]*/, ""); print; exit}' "$CONFIG" 2>/dev/null)
  printf '%s' "${v:-${3:-}}"
}

require_config() {
  [[ -f "$CONFIG" ]] || { failm "no $CONFIG - run: ./wazuh-deploy.sh configure"; exit 1; }
  PLATFORM=$(cfg deployment platform)
  ENVIRONMENT=$(cfg deployment environment)
  WAZUH_VERSION=$(cfg wazuh version 4.14.7)
  SIEM_DOMAIN=$(cfg wazuh domain siem.local.domain)
  PKI_CA=$(cfg pki ca step)
  export SIEM_DOMAIN WAZUH_VERSION
}

IMAGES() {
  cat <<EOF
wazuh/wazuh-manager:$WAZUH_VERSION
wazuh/wazuh-indexer:$WAZUH_VERSION
wazuh/wazuh-dashboard:$WAZUH_VERSION
nginx:1.29-alpine
smallstep/step-ca:latest
EOF
}

inventory() {
  grep -Ev '^\s*(#|$)' "$INVENTORY" | sed "s/@DOMAIN@/$SIEM_DOMAIN/g"
}

# =============================================================== configure ===
ask() { # ask <prompt> <default>
  local a
  read -r -p "$1 [$2]: " a || true
  printf '%s' "${a:-$2}"
}

cmd_configure() {
  local platform="" environment="" version="4.14.7" domain="siem.local.domain"
  local ca="" lb="yes" interactive=yes

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --non-interactive) interactive=no ;;
      --platform)    platform="$2"; shift ;;
      --environment) environment="$2"; shift ;;
      --version)     version="$2"; shift ;;
      --domain)      domain="$2"; shift ;;
      --ca)          ca="$2"; shift ;;
      --lb)          lb="$2"; shift ;;
      *) failm "unknown option: $1"; exit 1 ;;
    esac
    shift
  done

  if [[ "$interactive" == "yes" ]]; then
    say "Wazuh Deployment Setup"
    say "======================"
    say ""
    say "Deployment environment:"
    say "  1) Connected / commercial"
    say "  2) Air-gapped"
    case "$(ask "Select" "${environment:-2}")" in
      1|connected) environment=connected ;;
      *)           environment=airgap ;;
    esac
    say ""
    say "Deployment platform:"
    say "  1) Docker multi-node"
    say "  2) VM / bare-metal"
    case "$(ask "Select" "${platform:-1}")" in
      2|baremetal) platform=baremetal ;;
      *)           platform=docker ;;
    esac
    version=$(ask "Wazuh version" "$version")
    domain=$(ask "SIEM domain" "$domain")
    say ""
    say "Certificate authority:"
    say "  1) Bundled Step CA (automatic in connected mode)"
    say "  2) Bundled OpenSSL CA"
    say "  3) Corporate / external CA (staged CSR workflow)"
    case "$(ask "Select" "${ca:-1}")" in
      2|openssl)  ca=openssl ;;
      3|external) ca=external ;;
      *)          ca=step ;;
    esac
    lb=$(ask "Use nginx load balancer for agent traffic? (yes/no)" "$lb")
  else
    platform="${platform:-docker}"
    environment="${environment:-airgap}"
    ca="${ca:-step}"
  fi

  case "$platform"    in docker|baremetal) ;; *) failm "platform must be docker|baremetal"; exit 1 ;; esac
  case "$environment" in connected|airgap) ;; *) failm "environment must be connected|airgap"; exit 1 ;; esac
  case "$ca"          in step|openssl|external) ;; *) failm "ca must be step|openssl|external"; exit 1 ;; esac

  local pki_mode=automatic
  [[ "$environment" == "airgap" || "$ca" == "external" ]] && pki_mode=staged

  cat > "$CONFIG" <<EOF
# Generated by ./wazuh-deploy.sh configure - $(date -u +%Y-%m-%dT%H:%M:%SZ)
deployment:
  platform: $platform
  environment: $environment

wazuh:
  version: $version
  domain: $domain

# The shipped topology is pinned (see docker-compose.yml / config/certs-inventory.conf):
# 16 indexers (3 cluster-manager, 3 hot, 3 warm, 3 cold, 2 ingest, 2 coordinating),
# 1 Wazuh master + 4 workers, 1 dashboard, nginx LB. Changing counts means editing
# docker-compose.yml and certs-inventory.conf together - see docs/BAREMETAL.md.
topology:
  managers:
    master: 1
    workers: 4
  indexers:
    cluster_managers: 3
    hot: 3
    warm: 3
    cold: 3
    ingest: 2
    coordinating: 2
  dashboard:
    count: 1

load_balancer:
  enabled: $lb
  type: nginx

pki:
  mode: $pki_mode
  ca: $ca
EOF

  # Node inventory derived from the canonical certificate inventory - one
  # identity source. IPs matter only for bare-metal; fill them in there.
  {
    echo "# Generated from config/certs-inventory.conf - names/roles are canonical there."
    echo "# For baremetal: set each ip; ensure DNS (or /etc/hosts on every node)"
    echo "# resolves every hostname below. For docker: names resolve via the"
    echo "# container network automatically."
    echo "nodes:"
    SIEM_DOMAIN="$domain" grep -Ev '^\s*(#|$)' "$INVENTORY" | sed "s/@DOMAIN@/$domain/g" | \
    while IFS='|' read -r name role sans _; do
      case "$role" in admin-client|wazuh-api|authd) continue ;; esac  # not host-shaped identities
      local fqdn
      fqdn=$(printf '%s' "$sans" | tr ',' '\n' | grep -m1 "\.$domain$" || printf '%s' "$name")
      printf '  - name: %s\n    role: %s\n    hostname: %s\n    ip: %s\n' \
        "$name" "$role" "$fqdn" "$([[ "$platform" == docker ]] && echo docker-internal || echo REPLACE_ME)"
    done
  } > "$NODES"

  ok "wrote $CONFIG"
  ok "wrote $NODES ($(grep -c "^  - name:" "$NODES") nodes)"
  say ""
  say "Next steps for $environment + $platform:"
  if [[ "$environment" == "connected" ]]; then
    say "  ./wazuh-deploy.sh fetch"
    if [[ "$pki_mode" == "automatic" ]]; then
      say "  ./wazuh-deploy.sh certificates     # one-shot PKI (csr+sign+verify)"
    else
      say "  ./wazuh-deploy.sh pki csr && ./wazuh-deploy.sh pki export-csr   # corporate CA"
    fi
  else
    say "  (on a connected host)  ./wazuh-deploy.sh fetch && ./wazuh-deploy.sh airgap bundle"
    say "  (on this host)         ./wazuh-deploy.sh airgap import <bundle-dir>"
    say "  ./wazuh-deploy.sh pki csr"
    [[ "$ca" == "external" ]] \
      && say "  ./wazuh-deploy.sh pki export-csr   # sign with your corporate CA, then: pki import <dir>" \
      || say "  ./wazuh-deploy.sh pki sign --ca $ca"
    say "  ./wazuh-deploy.sh pki verify"
  fi
  say "  ./wazuh-deploy.sh validate"
  say "  ./wazuh-deploy.sh deploy $platform"
  say "  ./wazuh-deploy.sh verify"
}

# ================================================================ validate ===
cmd_validate() {
  require_config
  local fails=0 warns=0

  say "Preflight checks ($ENVIRONMENT + $PLATFORM, Wazuh $WAZUH_VERSION)"
  say "=================================================="

  # configuration + inventories
  ok "configuration ($CONFIG)"
  if [[ -f "$NODES" ]]; then
    local ninv nnod
    ninv=$(inventory | awk -F'|' '$2!="admin-client" && $2!="wazuh-api" && $2!="authd"' | wc -l | tr -d ' ')
    nnod=$(grep -c '^  - name:' "$NODES" || true)
    if [[ "$ninv" == "$nnod" ]]; then ok "node inventory consistent with certificate inventory ($nnod nodes)"
    else failm "node inventory ($nnod) != certificate inventory ($ninv) - re-run configure"; fails=$((fails+1)); fi
  else
    warn "no $NODES (run configure)"; warns=$((warns+1))
  fi

  # credentials + cluster key
  if [[ -f .env ]]; then ok "credentials (.env present)"
  else failm "credentials missing - run ./generate-credentials.sh"; fails=$((fails+1)); fi
  if [[ -f config/wazuh_cluster/wazuh_manager.conf ]]; then
    local keys
    keys=$(grep -h "<key>" config/wazuh_cluster/wazuh_manager.conf config/wazuh_cluster/wazuh_worker*.conf 2>/dev/null \
           | grep -v filebeat | sort -u | wc -l | tr -d ' ')
    if grep -q "REPLACE_WITH_CLUSTER_KEY" config/wazuh_cluster/wazuh_manager.conf; then
      failm "Wazuh cluster key is still the placeholder - run ./generate-credentials.sh"; fails=$((fails+1))
    elif [[ "$keys" != "1" ]]; then
      failm "Wazuh cluster key differs between manager configs ($keys distinct keys)"; fails=$((fails+1))
    else ok "Wazuh cluster key (shared across master + workers)"; fi
  else
    failm "manager configs not rendered - run ./generate-credentials.sh"; fails=$((fails+1))
  fi

  # certificates - full preflight via the PKI tool
  if ./generate-certs.sh verify >/tmp/wazuh-preflight-certs.$$ 2>&1; then
    ok "certificates ($(grep -c '^\[OK\]' /tmp/wazuh-preflight-certs.$$) identities: key match, chain, SANs, EKUs, validity)"
  else
    failm "certificate preflight failed:"
    grep -A1 '^\[FAIL\]' /tmp/wazuh-preflight-certs.$$ | sed 's/^/       /'
    fails=$((fails+1))
  fi
  rm -f /tmp/wazuh-preflight-certs.$$

  # images / packages
  if [[ "$PLATFORM" == "docker" ]]; then
    local img missing=0
    while read -r img; do
      docker image inspect "$img" >/dev/null 2>&1 || { failm "docker image missing: $img"; missing=1; }
    done < <(IMAGES)
    if (( missing )); then
      fails=$((fails+1))
      [[ "$ENVIRONMENT" == "connected" ]] \
        && say "       fix: ./wazuh-deploy.sh fetch" \
        || say "       fix: ./wazuh-deploy.sh airgap import <bundle-dir>"
    else ok "docker images (all $(IMAGES | wc -l | tr -d ' ') present, pinned to $WAZUH_VERSION)"; fi
  else
    if ls "$CACHE"/packages/*/*."deb" >/dev/null 2>&1 || ls "$CACHE"/packages/*/*."rpm" >/dev/null 2>&1; then
      ok "native packages cached in $CACHE/packages"
    elif [[ "$ENVIRONMENT" == "connected" ]]; then
      warn "no cached packages - ./wazuh-deploy.sh fetch (or install from your repo mirror)"; warns=$((warns+1))
    else
      failm "no cached packages and no internet - ./wazuh-deploy.sh airgap import <bundle-dir>"; fails=$((fails+1))
    fi
  fi

  # hostname resolution
  if getent hosts "$SIEM_DOMAIN" >/dev/null 2>&1 || dscacheutil -q host -a name "$SIEM_DOMAIN" 2>/dev/null | grep -q ip_address; then
    ok "hostname resolution: $SIEM_DOMAIN"
  else
    if [[ "$PLATFORM" == "docker" ]]; then
      warn "$SIEM_DOMAIN does not resolve on this host (agents/browsers need it - see docs, section DNS)"
      warns=$((warns+1))
    else
      failm "$SIEM_DOMAIN does not resolve - baremetal nodes require working DNS/hosts entries"
      fails=$((fails+1))
    fi
  fi

  # kernel / resources
  if [[ "$(uname -s)" == "Linux" ]]; then
    local mm
    mm=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
    if (( mm >= 262144 )); then ok "vm.max_map_count=$mm"
    else failm "vm.max_map_count=$mm (<262144) - sysctl -w vm.max_map_count=262144"; fails=$((fails+1)); fi
  else
    ok "vm.max_map_count (managed inside Docker Desktop VM on $(uname -s))"
  fi
  if [[ "$PLATFORM" == "docker" ]]; then
    local mem
    mem=$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)
    if (( mem >= 24000000000 )); then ok "memory: $((mem/1024/1024/1024)) GiB available to Docker"
    else warn "memory: $((mem/1024/1024/1024)) GiB (<24 GiB) - reduce heaps in .env"; warns=$((warns+1)); fi
  fi
  local disk
  disk=$(df -g . 2>/dev/null | awk 'NR==2{print $4}' || df -BG . | awk 'NR==2{print $4}' | tr -d G)
  if (( ${disk:-0} >= 50 )); then ok "disk: ${disk} GiB free"
  else warn "disk: ${disk:-?} GiB free (<50 GiB) - indexer tiers live on this disk"; warns=$((warns+1)); fi

  say ""
  if (( fails > 0 )); then
    say "DEPLOYMENT BLOCKED ($fails failure(s), $warns warning(s))."
    exit 1
  fi
  say "PREFLIGHT PASSED ($warns warning(s))."
}

# ================================================================== fetch ====
cmd_fetch() {
  require_config
  [[ "$ENVIRONMENT" == "connected" ]] || {
    failm "fetch is for connected environments - use 'airgap import' here"; exit 1; }

  if [[ "$PLATFORM" == "docker" ]]; then
    say "[*] Pulling pinned images..."
    local img
    while read -r img; do
      say "    $img"
      docker pull -q "$img" >/dev/null
    done < <(IMAGES)
    ok "images ready ($(IMAGES | wc -l | tr -d ' ') pulled, version pinned $WAZUH_VERSION)"
  else
    say "[*] Downloading native packages (pinned $WAZUH_VERSION) into $CACHE/packages ..."
    mkdir -p "$CACHE/packages/deb" "$CACHE/packages/rpm"
    local base_deb="https://packages.wazuh.com/4.x/apt/pool/main"
    local base_rpm="https://packages.wazuh.com/4.x/yum"
    local rel=1
    local u fails=0
    for u in \
      "$base_deb/w/wazuh-manager/wazuh-manager_${WAZUH_VERSION}-${rel}_amd64.deb" \
      "$base_deb/w/wazuh-indexer/wazuh-indexer_${WAZUH_VERSION}-${rel}_amd64.deb" \
      "$base_deb/w/wazuh-dashboard/wazuh-dashboard_${WAZUH_VERSION}-${rel}_amd64.deb" \
      "$base_deb/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}-${rel}_amd64.deb"; do
      say "    $(basename "$u")"
      curl -fSL --retry 3 -o "$CACHE/packages/deb/$(basename "$u")" "$u" || { failm "download failed: $u"; fails=1; }
    done
    for u in \
      "$base_rpm/wazuh-manager-${WAZUH_VERSION}-${rel}.x86_64.rpm" \
      "$base_rpm/wazuh-indexer-${WAZUH_VERSION}-${rel}.x86_64.rpm" \
      "$base_rpm/wazuh-dashboard-${WAZUH_VERSION}-${rel}.x86_64.rpm" \
      "$base_rpm/wazuh-agent-${WAZUH_VERSION}-${rel}.x86_64.rpm"; do
      say "    $(basename "$u")"
      curl -fSL --retry 3 -o "$CACHE/packages/rpm/$(basename "$u")" "$u" || { failm "download failed: $u"; fails=1; }
    done
    (( fails == 0 )) || exit 1
    ( cd "$CACHE/packages" && find . -type f \( -name '*.deb' -o -name '*.rpm' \) -exec openssl dgst -sha256 -r {} \; > SHA256SUMS )
    ok "packages cached + SHA256SUMS written"
  fi
}

# ================================================================= airgap ====
cmd_airgap_bundle() {
  require_config
  local out="wazuh-airgap-$WAZUH_VERSION"
  while [[ $# -gt 0 ]]; do
    case "$1" in --output) out="$2"; shift ;; *) failm "unknown option: $1"; exit 1 ;; esac; shift
  done
  say "[*] Building air-gap bundle in $out/ ..."
  mkdir -p "$out/images" "$out/checksums" "$out/repository" "$out/scripts"

  # 1. docker images
  local img missing=0
  while read -r img; do
    docker image inspect "$img" >/dev/null 2>&1 || { failm "image not present locally: $img (run fetch first)"; missing=1; }
  done < <(IMAGES)
  (( missing == 0 )) || exit 1
  say "    saving images -> images/wazuh-images.tar (several GB, takes a few minutes)"
  # shellcheck disable=SC2046
  docker save -o "$out/images/wazuh-images.tar" $(IMAGES | tr '\n' ' ')

  # 2. native packages if cached (baremetal targets)
  if [[ -d "$CACHE/packages" ]]; then
    cp -R "$CACHE/packages" "$out/packages"
    say "    included native packages from $CACHE/packages"
  fi

  # 3. this repository (branch snapshot) so the target needs no git access
  git -C .. archive --format=tar.gz -o "$PWD/$out/repository/wazuh-docker-airgp.tar.gz" HEAD 2>/dev/null \
    || tar czf "$out/repository/wazuh-docker-airgp.tar.gz" --exclude "$out" --exclude "$CACHE" -C .. .

  # 4. deployment helper for the target side
  cp wazuh-deploy.sh "$out/scripts/"

  # 5. checksums + manifest
  ( cd "$out"
    dirs=""
    for d in images packages repository scripts; do [[ -d "$d" ]] && dirs="$dirs $d"; done
    # shellcheck disable=SC2086
    find $dirs -type f -exec openssl dgst -sha256 -r {} \; > checksums/SHA256SUMS )
  cat > "$out/MANIFEST.json" <<EOF
{
  "bundle": "wazuh-airgap",
  "wazuh_version": "$WAZUH_VERSION",
  "created_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "platforms": ["docker"$( [[ -d "$out/packages" ]] && printf ', "baremetal"')],
  "images": [$(IMAGES | sed 's/^/"/; s/$/"/' | paste -sd, -)],
  "contents": {
    "images/wazuh-images.tar": "docker images (docker load)",
    "packages/": "native deb/rpm packages (if built with fetch on a baremetal config)",
    "repository/wazuh-docker-airgp.tar.gz": "this repository snapshot",
    "checksums/SHA256SUMS": "sha256 for every payload file"
  }
}
EOF
  ok "bundle ready: $out/"
  say "    Transfer the whole directory across the air gap, then on the target:"
  say "      ./wazuh-deploy.sh airgap import /media/$out"
}

cmd_airgap_import() {
  local dir="${1:-}"
  [[ -n "$dir" && -d "$dir" ]] || { failm "usage: wazuh-deploy.sh airgap import <bundle-dir>"; exit 1; }
  require_config

  say "[*] Verifying bundle checksums (mandatory) ..."
  [[ -f "$dir/checksums/SHA256SUMS" ]] || { failm "no checksums/SHA256SUMS - refusing to import"; exit 1; }
  local f h calc bad=0 n=0
  while read -r h f; do
    f="${f#\*}"
    calc=$(cd "$dir" && openssl dgst -sha256 -r "$f" 2>/dev/null | cut -d' ' -f1)
    n=$((n+1))
    [[ "$calc" == "$h" ]] || { failm "checksum mismatch: $f"; bad=1; }
  done < "$dir/checksums/SHA256SUMS"
  (( bad == 0 )) || { say ""; say "IMPORT BLOCKED - bundle integrity check failed."; exit 1; }
  ok "checksums verified ($n files)"

  if [[ -f "$dir/images/wazuh-images.tar" ]]; then
    say "[*] Loading docker images (takes a few minutes) ..."
    docker load -i "$dir/images/wazuh-images.tar" | sed 's/^/    /'
  fi
  if [[ -d "$dir/packages" ]]; then
    mkdir -p "$CACHE"
    cp -R "$dir/packages" "$CACHE/"
    ok "native packages copied to $CACHE/packages"
  fi
  ok "import complete"
  say "    next: ./wazuh-deploy.sh pki csr   (then sign/import + verify + deploy)"
}

# =================================================================== pki =====
cmd_pki() {
  require_config
  local sub="${1:-}"; shift || true
  case "$sub" in
    csr)        ./generate-certs.sh csr "$@" ;;
    sign)       if [[ $# -gt 0 ]]; then
                  ./generate-certs.sh sign "$@"
                elif [[ "$PKI_CA" == "external" ]]; then
                  failm "pki.ca=external - sign CSRs with your corporate CA, then: pki import <dir>"; exit 1
                else
                  ./generate-certs.sh sign --ca "$PKI_CA"
                fi ;;
    import)     local src="${1:-}"
                if [[ -n "$src" && -d "$src" ]]; then
                  say "[*] Copying signed certificates from $src ..."
                  cp "$src"/*.pem config/wazuh_indexer_ssl_certs/ 2>/dev/null || true
                fi
                ./generate-certs.sh import ;;
    verify)     ./generate-certs.sh verify ;;
    export-csr) local tarball="csr-bundle-$(date -u +%Y%m%d).tar.gz"
                tar czf "$tarball" -C config/wazuh_indexer_ssl_certs csr
                ok "CSRs exported: $tarball (contains ONLY .csr/.cnf - no private keys)"
                say "    Sign with your CA (see docs/PKI.md), return the certs, then: pki import <dir>" ;;
    *) failm "usage: wazuh-deploy.sh pki {csr|sign [--ca step|openssl]|import [dir]|verify|export-csr}"; exit 1 ;;
  esac
}

# one-shot for connected/automatic mode
cmd_certificates() {
  require_config
  if [[ "$(cfg pki mode automatic)" == "staged" ]]; then
    failm "pki.mode=staged - use the explicit workflow: pki csr / pki sign / pki verify"
    exit 1
  fi
  CA_MODE="$PKI_CA" ./generate-certs.sh
}

# ================================================================= deploy ====
cmd_deploy() {
  require_config
  local target="${1:-$PLATFORM}"
  case "$target" in
    docker)
      [[ "$PLATFORM" == "docker" ]] || warn "deployment.yml says platform=$PLATFORM"
      cmd_validate
      say ""
      ./deploy-certs.sh docker
      say ""
      say "[*] Starting the stack ..."
      docker compose up -d
      say ""
      ok "stack starting (first boot takes 3-6 minutes)"
      say "    watch:  ./wazuh-deploy.sh status"
      say "    then:   ./wazuh-deploy.sh verify"
      ;;
    baremetal)
      [[ "$PLATFORM" == "baremetal" ]] || warn "deployment.yml says platform=$PLATFORM"
      cmd_validate
      say ""
      ./deploy-certs.sh export
      say ""
      ok "per-node packages in dist/ - transfer each to its server and run install.sh there"
      say "    Native package install order per node type: docs/BAREMETAL.md"
      ;;
    *) failm "usage: wazuh-deploy.sh deploy {docker|baremetal}"; exit 1 ;;
  esac
}

# ================================================================= verify ====
tls_check() { # tls_check <host-header> <port> <expect-cn>
  local subj
  subj=$(echo | openssl s_client -connect "127.0.0.1:$2" -servername "$1" 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null)
  [[ "$subj" == *"CN=$3"* ]]
}

cmd_verify() {
  require_config
  local fails=0
  say "Wazuh deployment verification"
  say "============================="
  say ""

  if [[ "$PLATFORM" == "baremetal" ]]; then
    say "Central endpoint checks against $NODES hostnames:"
    local name role host
    while read -r name role host; do
      local port=""
      case "$role" in
        indexer) port=9200 ;;
        dashboard) port=443 ;;
        manager-*|filebeat) port=1514 ;;
      esac
      [[ -n "$port" ]] || continue
      if nc -z -w3 "$host" "$port" 2>/dev/null; then ok "$name ($host:$port reachable)"
      else failm "$name ($host:$port unreachable)"; fails=$((fails+1)); fi
    done < <(awk '/- name:/{n=$3}/role:/{r=$2}/hostname:/{print n, r, $2}' "$NODES")
    say ""
    say "Run each node's dist/<node>/verify.sh locally for certificate checks."
    (( fails == 0 )) && say "Deployment healthy (reachable)." || { say "DEPLOYMENT ISSUES ($fails)."; exit 1; }
    return
  fi

  # --- docker ---
  local up
  up=$(docker compose ps --format '{{.Name}}' 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$up" == "23" ]]; then ok "containers: 23/23 running"
  else failm "containers: $up/23 running"; fails=$((fails+1)); fi

  # Wazuh server cluster
  local cl
  cl=$(docker exec wazuh.master /var/ossec/bin/cluster_control -l 2>/dev/null | grep -c worker || true)
  if [[ "$cl" == "4" ]]; then ok "Wazuh master + 4 workers joined"
  else failm "Wazuh cluster: only $cl/4 workers joined"; fails=$((fails+1)); fi

  # indexer cluster - full TLS verification from inside the trust domain
  local health
  health=$(docker exec master1.indexer curl -s \
    --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
    -u "admin:$(grep '^INDEXER_PASSWORD=' .env | cut -d= -f2)" \
    "https://master1.indexer:9200/_cluster/health" 2>/dev/null || true)
  if echo "$health" | grep -q '"number_of_nodes":16' && echo "$health" | grep -q '"status":"green"'; then
    ok "indexer cluster: 16 nodes, health green (TLS verified against root CA)"
  else
    failm "indexer cluster unhealthy: $(echo "$health" | head -c 120)"; fails=$((fails+1))
  fi

  # filebeat
  local fb
  fb=$(docker exec wazuh.master filebeat test output 2>/dev/null | grep -c "talk to server... OK" || true)
  if [[ "$fb" == "2" ]]; then ok "Filebeat -> both ingest nodes (TLS full verification)"
  else failm "Filebeat output test: $fb/2 endpoints OK"; fails=$((fails+1)); fi

  # API + dashboard + enrollment: certificate identity + issuer + expiry
  local exp
  for spec in "wazuh.master:55000:wazuh.master-api:Wazuh API" \
              "$SIEM_DOMAIN:443:wazuh.dashboard:Dashboard" \
              "$SIEM_DOMAIN:1515:wazuh.master-enrollment:Enrollment (authd)"; do
    local hostn port cn label
    IFS=':' read -r hostn port cn label <<< "$spec"
    if tls_check "$hostn" "$port" "$cn"; then
      exp=$(echo | openssl s_client -connect "127.0.0.1:$port" 2>/dev/null \
            | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
      ok "$label: serving CN=$cn (expires $exp)"
    else
      failm "$label on :$port not serving expected certificate CN=$cn"; fails=$((fails+1))
    fi
  done

  # API auth round-trip with CA verification (no -k)
  local code
  code=$(curl -s --cacert config/wazuh_indexer_ssl_certs/root-ca.pem \
    --resolve "wazuh.master:55000:127.0.0.1" \
    -u "wazuh-wui:$(grep '^API_PASSWORD=' .env | cut -d= -f2)" \
    -X POST "https://wazuh.master:55000/security/user/authenticate" \
    -o /dev/null -w '%{http_code}' || true)
  if [[ "$code" == "200" ]]; then ok "Wazuh API authentication (chain-verified TLS)"
  else failm "Wazuh API auth returned: $code"; fails=$((fails+1)); fi

  # agent ports
  local p
  for p in 1514 1515; do
    nc -z -w3 127.0.0.1 $p 2>/dev/null && ok "agent port $p reachable" \
      || { failm "agent port $p unreachable"; fails=$((fails+1)); }
  done

  say ""
  if (( fails == 0 )); then say "Deployment healthy."
  else say "DEPLOYMENT ISSUES ($fails check(s) failed)."; exit 1; fi
}

cmd_status() {
  docker compose ps --format 'table {{.Name}}\t{{.Status}}' 2>/dev/null || say "stack not running"
}

# ==================================================================== main ===
CMD="${1:-}"; shift || true
case "$CMD" in
  configure)    cmd_configure "$@" ;;
  validate)     cmd_validate "$@" ;;
  fetch)        cmd_fetch "$@" ;;
  airgap)       sub="${1:-}"; shift || true
                case "$sub" in
                  bundle) cmd_airgap_bundle "$@" ;;
                  import) cmd_airgap_import "$@" ;;
                  *) failm "usage: wazuh-deploy.sh airgap {bundle|import <dir>}"; exit 1 ;;
                esac ;;
  pki)          cmd_pki "$@" ;;
  certificates) cmd_certificates "$@" ;;
  deploy)       cmd_deploy "$@" ;;
  verify)       cmd_verify "$@" ;;
  status)       cmd_status "$@" ;;
  *)
    cat <<'EOF'
wazuh-deploy.sh - unified deployment CLI

  configure [--non-interactive --platform docker|baremetal --environment connected|airgap
             --version V --domain D --ca step|openssl|external --lb yes|no]
  validate                     preflight gate (blocks deploy on failure)
  fetch                        connected: pull images / download packages
  airgap bundle [--output DIR] connected staging host: build transfer bundle
  airgap import <dir>          air-gapped host: checksum-verify + import
  certificates                 connected one-shot PKI (csr+sign+verify)
  pki csr|export-csr|sign [--ca ...]|import [dir]|verify
  deploy docker|baremetal
  verify                       runtime verification
  status
EOF
    exit 1 ;;
esac
