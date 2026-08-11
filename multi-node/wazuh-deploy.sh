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
    insec && $1 == k {sub(/^[^:]*:[ ]*/, ""); sub(/[ \t]*#.*$/, ""); sub(/[ \t]+$/, ""); print; exit}' "$CONFIG" 2>/dev/null)
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

# OpenSearch version bundled in wazuh-indexer (drives the repository-s3 zip)
OPENSEARCH_VERSION="${OPENSEARCH_VERSION:-2.19.5}"

CORE_IMAGES() {
  cat <<EOF
wazuh/wazuh-manager:$WAZUH_VERSION
wazuh/wazuh-indexer:$WAZUH_VERSION
wazuh/wazuh-dashboard:$WAZUH_VERSION
nginx:1.29-alpine
smallstep/step-ca:latest
EOF
}

ARCHIVE_IMAGES() {
  cat <<EOF
rustfs/rustfs:${RUSTFS_VERSION:-1.0.0-rc.1}
rclone/rclone:${RCLONE_VERSION:-1.68}
EOF
}

MAPS_IMAGES() { echo "opensearchproject/opensearch-maps-server:${MAPS_VERSION:-1.0.0}"; }
SOC_IMAGES() {
  cat <<EOF
ghcr.io/misp/misp-docker/misp-core:${MISP_VERSION:-v2.5.1}
ghcr.io/misp/misp-docker/misp-modules:${MISP_MODULES_VERSION:-latest}
ghcr.io/dfir-iris/iriswebapp_app:${IRIS_VERSION:-v2.4.20}
ghcr.io/dfir-iris/iriswebapp_db:${IRIS_VERSION:-v2.4.20}
ghcr.io/dfir-iris/iriswebapp_nginx:${IRIS_VERSION:-v2.4.20}
mariadb:${MARIADB_VERSION:-10.11}
valkey/valkey:${VALKEY_VERSION:-7.2}
rabbitmq:${RABBITMQ_VERSION:-3-management}
EOF
}
AGENT_IMAGES() { echo "wazuh/wazuh-agent:$WAZUH_VERSION"; }
TILES_URL="${TILES_URL:-https://maps.opensearch.org/offline/planet-osm-default-z0-z8.tar.gz}"

archive_enabled() { grep -qs '^COMPOSE_PROFILES=.*archive' .env; }
maps_enabled()    { grep -qs '^COMPOSE_PROFILES=.*maps'    .env; }
agent_enabled()   { grep -qs '^COMPOSE_PROFILES=.*agent'   .env; }
soc_enabled()     { grep -qs '^COMPOSE_PROFILES=.*soc'     .env; }

# add <profile> to COMPOSE_PROFILES in .env (creating the line if needed)
enable_profile() {
  [[ -f .env ]] || { failm "run ./generate-credentials.sh first"; exit 1; }
  if grep -q '^COMPOSE_PROFILES=' .env; then
    grep -q "^COMPOSE_PROFILES=.*$1" .env || \
      sed -i.bak "s/^COMPOSE_PROFILES=.*/&,$1/" .env && rm -f .env.bak
  else
    echo "COMPOSE_PROFILES=$1" >> .env
  fi
  ok "profile '$1' enabled ($(grep '^COMPOSE_PROFILES=' .env))"
}

IMAGES() {
  CORE_IMAGES
  archive_enabled && ARCHIVE_IMAGES || true
  maps_enabled && MAPS_IMAGES || true
  agent_enabled && AGENT_IMAGES || true
  soc_enabled && SOC_IMAGES || true
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
  local host_ip="" dns_mode="" dns_server="" adcs_template="WazuhNode"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --non-interactive) interactive=no ;;
      --platform)    platform="$2"; shift ;;
      --environment) environment="$2"; shift ;;
      --version)     version="$2"; shift ;;
      --domain)      domain="$2"; shift ;;
      --ca)          ca="$2"; shift ;;
      --lb)          lb="$2"; shift ;;
      --host-ip)     host_ip="$2"; shift ;;
      --dns)         dns_mode="$2"; shift ;;
      --dns-server)  dns_server="$2"; shift ;;
      --adcs-template) adcs_template="$2"; shift ;;
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
    say ""
    say "DNS (how clients/agents resolve $domain):"
    say "  1) Windows AD DNS zone (domain-joined environment)"
    say "  2) hosts files on every client"
    case "$(ask "Select" "${dns_mode:-1}")" in
      2|hosts) dns_mode=hosts ;;
      *)       dns_mode=ad ;;
    esac
    host_ip=$(ask "IP of this Wazuh host (all service hostnames resolve to it)" "${host_ip:-10.0.0.50}")
    [[ "$dns_mode" == "ad" ]] && dns_server=$(ask "AD DNS server (hostname/IP, for the ops runbook)" "${dns_server:-}")
    [[ "$ca" == "external" ]] && adcs_template=$(ask "ADCS certificate template name" "$adcs_template")
  else
    platform="${platform:-docker}"
    environment="${environment:-airgap}"
    ca="${ca:-step}"
    dns_mode="${dns_mode:-ad}"
    host_ip="${host_ip:-10.0.0.50}"
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

# External infrastructure this deployment depends on (updatable any time;
# re-run './wazuh-deploy.sh dns records' after changing).
dns:
  mode: $dns_mode          # ad = Windows AD DNS zone | hosts = client hosts files
  server: ${dns_server:-}
  host_ip: $host_ip        # single IP every service hostname resolves to (docker)

pki:
  mode: $pki_mode
  ca: $ca                  # step | openssl | external (e.g. Windows ADCS)
  adcs_template: $adcs_template
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
  say "  ./generate-credentials.sh          # passwords, hashes, cluster key (once)"
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

  # archive module (optional)
  if archive_enabled; then
    if ls config/archive/repository-s3-*.zip >/dev/null 2>&1; then ok "archive: repository-s3 plugin zip cached"
    else failm "archive enabled but repository-s3 zip missing (fetch / airgap import)"; fails=$((fails+1)); fi
    if [[ -f config/wazuh_indexer_ssl_certs/rustfs-tls/rustfs_cert.pem ]]; then ok "archive: RustFS TLS directory prepared"
    else failm "archive enabled but rustfs-tls/ not prepared - re-run: archive enable (after pki sign)"; fails=$((fails+1)); fi
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
    say "[*] Pulling pinned images (core + archive module)..."
    local img
    while read -r img; do
      say "    $img"
      docker pull -q "$img" >/dev/null
    done < <(CORE_IMAGES; ARCHIVE_IMAGES; MAPS_IMAGES; AGENT_IMAGES; SOC_IMAGES)
    ok "images ready (version pinned $WAZUH_VERSION)"
    local pzip="config/archive/repository-s3-$OPENSEARCH_VERSION.zip"
    if [[ ! -f "$pzip" ]]; then
      say "[*] Downloading repository-s3 plugin (archive module, OpenSearch $OPENSEARCH_VERSION)..."
      curl -fSL --retry 3 -o "$pzip" \
        "https://artifacts.opensearch.org/releases/plugins/repository-s3/$OPENSEARCH_VERSION/repository-s3-$OPENSEARCH_VERSION.zip"
    fi
    ok "repository-s3 plugin cached ($pzip)"
    local ttar="$CACHE/maps/$(basename "$TILES_URL")"
    if [[ ! -f "$ttar" ]]; then
      say "[*] Downloading offline map tiles (~225 MB)..."
      mkdir -p "$CACHE/maps"
      curl -fSL --retry 3 -o "$ttar" "$TILES_URL"
    fi
    ok "offline map tiles cached ($ttar)"
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

  # 1. docker images - core AND archive module, so the target can enable the
  #    archive later without internet access
  local img missing=0
  while read -r img; do
    docker image inspect "$img" >/dev/null 2>&1 || { failm "image not present locally: $img (run fetch first)"; missing=1; }
  done < <(CORE_IMAGES; ARCHIVE_IMAGES; MAPS_IMAGES; AGENT_IMAGES; SOC_IMAGES)
  (( missing == 0 )) || exit 1
  say "    saving images -> images/wazuh-images.tar (several GB, takes a few minutes)"
  # shellcheck disable=SC2046
  docker save -o "$out/images/wazuh-images.tar" $( (CORE_IMAGES; ARCHIVE_IMAGES; MAPS_IMAGES; AGENT_IMAGES; SOC_IMAGES) | tr '\n' ' ')

  # 1b. offline plugin zips (repository-s3 for the archive module)
  if ls config/archive/*.zip >/dev/null 2>&1; then
    mkdir -p "$out/plugins"
    cp config/archive/*.zip "$out/plugins/"
    say "    included OpenSearch plugin zips"
  fi

  # 1c. offline map tiles (maps module)
  if ls "$CACHE"/maps/*.tar.gz >/dev/null 2>&1; then
    mkdir -p "$out/maps"
    cp "$CACHE"/maps/*.tar.gz "$out/maps/"
    say "    included offline map tiles"
  fi

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
  if ls "$dir"/plugins/*.zip >/dev/null 2>&1; then
    cp "$dir"/plugins/*.zip config/archive/
    ok "OpenSearch plugin zips copied to config/archive/"
  fi
  if ls "$dir"/maps/*.tar.gz >/dev/null 2>&1; then
    mkdir -p "$CACHE/maps"
    cp "$dir"/maps/*.tar.gz "$CACHE/maps/"
    ok "offline map tiles copied to $CACHE/maps/"
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
                local tmpl
                tmpl=$(cfg pki adcs_template WazuhNode)
                # certreq submission script for the Windows ADCS admin
                {
                  echo "# Submits every Wazuh CSR to the ADCS CA using template '$tmpl'."
                  echo "# Run on a domain-joined admin workstation, next to the .csr files."
                  echo "# The template must preserve CSR SANs and issue Server+Client Auth EKUs."
                  echo "Get-ChildItem -Filter *.csr | ForEach-Object {"
                  echo "    \$out = \$_.BaseName + '.pem'"
                  echo "    certreq -submit -attrib \"CertificateTemplate:$tmpl\" \$_.Name \$out"
                  echo "    Write-Host \"[OK] \$out\""
                  echo "}"
                } > config/wazuh_indexer_ssl_certs/csr/submit-csrs.ps1
                tar czf "$tarball" -C config/wazuh_indexer_ssl_certs csr
                ok "CSRs exported: $tarball (contains ONLY .csr/.cnf + submit-csrs.ps1 - no private keys)"
                say "    ADCS: run submit-csrs.ps1 on the CA side (template: $tmpl), return the .pem files"
                say "    plus the CA chain as root-ca.pem, then: pki import <dir>" ;;
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

# ==================================================================== dns ====
# Generates ready-to-run records for the EXTERNAL Windows AD DNS (or client
# hosts files) from the node inventory + dns.host_ip. Re-run any time after
# changing dns.* in deployment.yml.
cmd_dns() {
  require_config
  local sub="${1:-records}"
  [[ "$sub" == "records" ]] || { failm "usage: wazuh-deploy.sh dns records"; exit 1; }
  local host_ip zone
  host_ip=$(cfg dns host_ip 10.0.0.50)
  zone="$SIEM_DOMAIN"
  mkdir -p config/dns

  # ---- Windows AD DNS (run on a DC / DNS admin workstation) ----
  {
    echo "# Adds/updates every DNS record for the Wazuh deployment in AD DNS."
    echo "# Zone: $zone   Deployment host IP: $host_ip"
    echo "# Generated from config/nodes.yml by 'wazuh-deploy.sh dns records'."
    echo "# Idempotent: existing records are updated to the current IP."
    echo ""
    echo "\$zone = \"$zone\""
    echo "if (-not (Get-DnsServerZone -Name \$zone -ErrorAction SilentlyContinue)) {"
    echo "    Add-DnsServerPrimaryZone -Name \$zone -ReplicationScope \"Forest\""
    echo "}"
    echo ""
    echo "\$records = @("
    # apex + public aliases all point at the deployment host
    echo "    @{ Name = \"@\";         IP = \"$host_ip\" },"
    echo "    @{ Name = \"dashboard\"; IP = \"$host_ip\" },"
    echo "    @{ Name = \"manager\";   IP = \"$host_ip\" },"
    echo "    @{ Name = \"indexer\";   IP = \"$host_ip\" },"
    echo "    @{ Name = \"s3\";        IP = \"$host_ip\" },"
    echo "    @{ Name = \"archive\";   IP = \"$host_ip\" },"
    echo "    @{ Name = \"sso\";       IP = \"$host_ip\" },"
    echo "    @{ Name = \"misp\";      IP = \"$host_ip\" },"
    echo "    @{ Name = \"iris\";      IP = \"$host_ip\" },"
    # per-node records (docker: all = host_ip; baremetal: per-node IPs)
    awk '/- name:/{n=$3}/hostname:/{h=$2}/ip:/{print n, h, $2}' "$NODES" | \
    while read -r name fqdn ip; do
      [[ "$ip" == "docker-internal" ]] && ip="$host_ip"
      [[ "$ip" == "REPLACE_ME" ]] && ip="CHANGE_ME"
      local short="${fqdn%%.$zone}"
      [[ "$short" == "$fqdn" ]] && continue   # hostname not under the zone
      echo "    @{ Name = \"$short\"; IP = \"$ip\" },"
    done | sed '$ s/,$//'
    echo ")"
    cat <<'PS1'

foreach ($r in $records) {
    $existing = Get-DnsServerResourceRecord -ZoneName $zone -Name $r.Name -RRType A -ErrorAction SilentlyContinue
    if ($existing) { Remove-DnsServerResourceRecord -ZoneName $zone -Name $r.Name -RRType A -Force }
    Add-DnsServerResourceRecordA -ZoneName $zone -Name $r.Name -IPv4Address $r.IP
    Write-Host "[OK] $($r.Name).$zone -> $($r.IP)"
}
PS1
  } > config/dns/add-dns-records.ps1

  # ---- hosts-file fallback (Linux /etc/hosts, Windows drivers\etc\hosts) ----
  {
    echo "# Append to /etc/hosts (Linux) or C:\\Windows\\System32\\drivers\\etc\\hosts (Windows)"
    echo "# on every client/agent if no DNS zone is available."
    echo "$host_ip  $zone dashboard.$zone manager.$zone indexer.$zone s3.$zone archive.$zone sso.$zone misp.$zone iris.$zone"
  } > config/dns/hosts.snippet

  ok "wrote config/dns/add-dns-records.ps1  (run on the Windows DNS server)"
  ok "wrote config/dns/hosts.snippet        (hosts-file fallback)"
  [[ -n "$(cfg dns server)" ]] && say "    DNS server on record: $(cfg dns server)"
}

# =================================================================== maps ====
# Self-hosted offline maps (the air-gap equivalent of Elastic Maps Server).
cmd_maps() {
  require_config
  local sub="${1:-}"; shift || true
  case "$sub" in
    enable)
      enable_profile maps
      say "    next: docker compose up -d && ./wazuh-deploy.sh maps init"
      ;;
    init)
      maps_enabled || { failm "maps module not enabled - run: maps enable"; exit 1; }
      local tar="$CACHE/maps/$(basename "$TILES_URL")"
      if [[ ! -f "$tar" ]]; then
        if [[ "$ENVIRONMENT" == "connected" ]]; then
          say "[*] Downloading tiles set ($(basename "$TILES_URL"), ~225 MB)..."
          mkdir -p "$CACHE/maps"
          curl -fSL --retry 3 -o "$tar" "$TILES_URL"
        else
          failm "tiles set missing ($tar) - import an airgap bundle built after this feature"
          exit 1
        fi
      fi
      say "[*] Loading tiles into the maps volume (one-time)..."
      docker run --rm -v multi-node_maps-tiles:/tiles \
        -v "$PWD/$CACHE/maps:/src:ro" nginx:1.29-alpine \
        sh -c "tar xzf /src/$(basename "$tar") --strip-components=1 -C /tiles && ls /tiles | head -3"
      docker compose up -d maps-server >/dev/null 2>&1 || docker restart maps-server >/dev/null
      sleep 5
      cmd_maps status
      ;;
    status)
      docker ps --filter name=maps-server --format '{{.Names}}: {{.Status}}'
      local code
      code=$(curl -ks --cacert config/wazuh_indexer_ssl_certs/root-ca.pem \
        --resolve "$SIEM_DOMAIN:8080:127.0.0.1" \
        -o /dev/null -w '%{http_code}' "https://$SIEM_DOMAIN:8080/manifest.json" || true)
      if [[ "$code" == "200" ]]; then
        ok "maps manifest served over TLS: https://$SIEM_DOMAIN:8080/manifest.json"
      else
        failm "manifest not reachable (HTTP $code) - is the maps profile up and tiles loaded?"
        exit 1
      fi
      ;;
    *) failm "usage: wazuh-deploy.sh maps {enable|init|status}"; exit 1 ;;
  esac
}

# ================================================================ archive ====
# rclone one-shot against the RustFS endpoint, sharing the archiver's config
s3cmd() {
  docker run --rm --network siem \
    -v "$PWD/config/wazuh_indexer_ssl_certs/root-ca.pem:/certs/root-ca.pem:ro" \
    -e RCLONE_CONFIG_ARCHIVE_TYPE=s3 \
    -e RCLONE_CONFIG_ARCHIVE_PROVIDER=Other \
    -e "RCLONE_CONFIG_ARCHIVE_ENDPOINT=$(grep '^ARCHIVE_S3_ENDPOINT=' .env | cut -d= -f2)" \
    -e "RCLONE_CONFIG_ARCHIVE_ACCESS_KEY_ID=$(grep '^S3_ACCESS_KEY=' .env | cut -d= -f2)" \
    -e "RCLONE_CONFIG_ARCHIVE_SECRET_ACCESS_KEY=$(grep '^S3_SECRET_KEY=' .env | cut -d= -f2)" \
    -e RCLONE_CONFIG_ARCHIVE_FORCE_PATH_STYLE=true \
    -e RCLONE_CA_CERT=/certs/root-ca.pem \
    "rclone/rclone:${RCLONE_VERSION:-1.68}" "$@"
}

# CA-verified curl against the indexer REST API, from inside the trust domain
idx_api() { # idx_api <method> <path> [json-file-or-inline]
  local method="$1" path="$2" body="${3:-}"
  local args=(-s --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem
              -u "admin:$(grep '^INDEXER_PASSWORD=' .env | cut -d= -f2)"
              -X "$method" "https://master1.indexer:9200$path")
  [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" -d "$body")
  docker exec master1.indexer curl "${args[@]}"
}

cmd_archive() {
  require_config
  local sub="${1:-}"; shift || true
  case "$sub" in
    enable)
      [[ -f .env ]] || { failm "run ./generate-credentials.sh first"; exit 1; }
      grep -q '^S3_ACCESS_KEY=' .env || cat >> .env <<EOF

# --- archive module (RustFS S3 long retention) -------------------------------
S3_ACCESS_KEY=wazuh-archive-$(openssl rand -hex 8)
S3_SECRET_KEY=$(openssl rand -hex 24)
ARCHIVE_S3_ENDPOINT=https://rustfs:9000
COMPOSE_PROFILES=archive
EOF
      ok "archive credentials + profile set in .env"
      # RustFS TLS material (dedicated server identity from the PKI)
      if [[ -f config/wazuh_indexer_ssl_certs/rustfs.pem ]]; then
        mkdir -p config/wazuh_indexer_ssl_certs/rustfs-tls
        cp config/wazuh_indexer_ssl_certs/rustfs.pem     config/wazuh_indexer_ssl_certs/rustfs-tls/rustfs_cert.pem
        cp config/wazuh_indexer_ssl_certs/rustfs-key.pem config/wazuh_indexer_ssl_certs/rustfs-tls/rustfs_key.pem
        ok "RustFS TLS directory prepared (rustfs_cert.pem/rustfs_key.pem)"
      else
        warn "no rustfs certificate yet - run: pki csr && pki sign (the inventory includes 'rustfs'), then re-run archive enable"
      fi
      # raw-event archives on the master (archives.json) feed the raw bucket
      if [[ -f config/wazuh_cluster/wazuh_manager.conf ]] && \
         grep -q "<logall_json>no</logall_json>" config/wazuh_cluster/wazuh_manager.conf; then
        sed -i.bak 's|<logall_json>no</logall_json>|<logall_json>yes</logall_json>|' \
          config/wazuh_cluster/wazuh_manager.conf && rm -f config/wazuh_cluster/wazuh_manager.conf.bak
        ok "enabled <logall_json> on the master (raw archives feed)"
      fi
      # offline plugin availability
      if ! ls config/archive/repository-s3-*.zip >/dev/null 2>&1; then
        if [[ "$ENVIRONMENT" == "connected" ]]; then
          say "[*] Downloading repository-s3 plugin..."
          curl -fSL --retry 3 -o "config/archive/repository-s3-$OPENSEARCH_VERSION.zip" \
            "https://artifacts.opensearch.org/releases/plugins/repository-s3/$OPENSEARCH_VERSION/repository-s3-$OPENSEARCH_VERSION.zip"
          ok "plugin cached"
        else
          warn "repository-s3 zip missing - import an airgap bundle built after this feature"
        fi
      fi
      say ""
      say "Next:"
      if [[ ! -f config/wazuh_indexer_ssl_certs/rustfs-tls/rustfs_cert.pem ]]; then
        say "  ./wazuh-deploy.sh pki csr && ./wazuh-deploy.sh pki sign   # issues the rustfs cert (idempotent)"
        say "  ./wazuh-deploy.sh archive enable                          # re-run to install the TLS dir"
      fi
      say "  docker compose up -d                    # recreates indexers, starts rustfs + archiver"
      say "  docker compose up -d --force-recreate wazuh.master   # config-mount changes apply on RECREATION, not restart"
      say "  ./wazuh-deploy.sh archive init          # buckets, snapshot repository, ISM policy"
      ;;
    init)
      archive_enabled || { failm "archive module not enabled - run: archive enable"; exit 1; }
      say "[*] Creating buckets..."
      s3cmd mkdir archive:wazuh-index-snapshots
      s3cmd mkdir archive:wazuh-raw-archives
      ok "buckets: wazuh-index-snapshots, wazuh-raw-archives"
      say "[*] Registering the snapshot repository..."
      idx_api PUT "/_snapshot/wazuh-index-snapshots" \
        '{"type":"s3","settings":{"bucket":"wazuh-index-snapshots","base_path":"wazuh"}}' ; echo
      say "[*] Verifying the repository from every node..."
      local vres
      vres=$(idx_api POST "/_snapshot/wazuh-index-snapshots/_verify")
      if echo "$vres" | grep -q '"nodes"'; then
        ok "repository verified by $(echo "$vres" | grep -o '"name"' | wc -l | tr -d ' ') node(s)"
      else
        failm "repository verification failed: $vres"; exit 1
      fi
      say "[*] Applying the archive ISM policy (snapshot before delete)..."
      local seq prim
      seq=$(idx_api GET "/_plugins/_ism/policies/wazuh-hot-warm-cold" | grep -o '"_seq_no":[0-9]*' | cut -d: -f2 || true)
      prim=$(idx_api GET "/_plugins/_ism/policies/wazuh-hot-warm-cold" | grep -o '"_primary_term":[0-9]*' | cut -d: -f2 || true)
      local qs=""
      [[ -n "$seq" && -n "$prim" ]] && qs="?if_seq_no=$seq&if_primary_term=$prim"
      docker exec -i master1.indexer curl -s \
        --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
        -u "admin:$(grep '^INDEXER_PASSWORD=' .env | cut -d= -f2)" \
        -X PUT "https://master1.indexer:9200/_plugins/_ism/policies/wazuh-hot-warm-cold$qs" \
        -H "Content-Type: application/json" \
        --data-binary @- < config/ism/wazuh-hot-warm-cold-archive-policy.json | grep -q '"policy"' \
        && ok "ISM policy updated (hot 7d -> warm 30d -> cold 90d -> snapshot -> delete)" \
        || { failm "ISM policy update failed"; exit 1; }
      ok "archive module initialized"
      ;;
    snapshot)
      archive_enabled || { failm "archive module not enabled"; exit 1; }
      local name="manual-$(date -u +%Y%m%d%H%M%S)"
      say "[*] Snapshotting wazuh-alerts-* to wazuh-index-snapshots/$name ..."
      idx_api PUT "/_snapshot/wazuh-index-snapshots/$name?wait_for_completion=true" \
        '{"indices":"wazuh-alerts-*","include_global_state":false}' \
        | grep -o '"state":"[A-Z]*"\|"failed":[0-9]*' | tr '\n' ' '; echo
      ;;
    status)
      archive_enabled || { warn "archive module not enabled"; exit 0; }
      docker ps --filter name=rustfs --filter name=siem-archiver --format '{{.Names}}: {{.Status}}'
      say ""
      say "Buckets:"
      s3cmd lsd archive: 2>/dev/null | sed 's/^/  /'
      say ""
      say "Snapshots (latest 5):"
      idx_api GET "/_cat/snapshots/wazuh-index-snapshots?h=id,status,end_time&s=end_time" 2>/dev/null | tail -5 | sed 's/^/  /'
      ;;
    *) failm "usage: wazuh-deploy.sh archive {enable|init|snapshot|status}"; exit 1 ;;
  esac
}

# ==================================================================== sso ====
# Keycloak OIDC single sign-on for the dashboard + indexer security plugin.
cmd_sso() {
  require_config
  local sub="${1:-}"; shift || true
  case "$sub" in
    enable)
      [[ -f .env ]] || { failm "run ./generate-credentials.sh first"; exit 1; }
      grep -q '^OIDC_CLIENT_SECRET=' .env || cat >> .env <<SSOEOF

# --- SSO module (Keycloak OIDC) ----------------------------------------------
KEYCLOAK_ADMIN_PASSWORD=Kc1.$(openssl rand -hex 14)
OIDC_CLIENT_SECRET=$(openssl rand -hex 20)
SSO_ADMIN_PASSWORD=Sso1.$(openssl rand -hex 12)
SSO_ANALYST_PASSWORD=Sso1.$(openssl rand -hex 12)
SSOEOF
      enable_profile sso
      sed -e "s|REPLACE_WITH_OIDC_CLIENT_SECRET|$(grep '^OIDC_CLIENT_SECRET=' .env | cut -d= -f2)|" \
          -e "s|REPLACE_WITH_SSO_ADMIN_PASSWORD|$(grep '^SSO_ADMIN_PASSWORD=' .env | cut -d= -f2)|" \
          -e "s|REPLACE_WITH_SSO_ANALYST_PASSWORD|$(grep '^SSO_ANALYST_PASSWORD=' .env | cut -d= -f2)|" \
          config/templates/keycloak-realm.json.tpl > config/keycloak/realm-siem.json
      ok "realm import rendered (config/keycloak/realm-siem.json)"
      cp config/templates/opensearch_dashboards.yml.tpl config/wazuh_dashboard/opensearch_dashboards.yml
      cat >> config/wazuh_dashboard/opensearch_dashboards.yml <<SSOEOF

# --- SSO (Keycloak OIDC) - appended by 'wazuh-deploy.sh sso enable' ----------
opensearch_security.auth.type: ["basicauth","openid"]
opensearch_security.auth.multiple_auth_enabled: true
opensearch_security.ui.openid.login.buttonname: "Keycloak SSO"
opensearch_security.openid.connect_url: "https://keycloak:8443/realms/siem/.well-known/openid-configuration"
opensearch_security.openid.client_id: "wazuh-dashboard"
opensearch_security.openid.client_secret: "$(grep '^OIDC_CLIENT_SECRET=' .env | cut -d= -f2)"
opensearch_security.openid.base_redirect_url: "https://$SIEM_DOMAIN"
opensearch_security.openid.root_ca: "/usr/share/wazuh-dashboard/certs/root-ca.pem"
SSOEOF
      ok "dashboard config rendered with OIDC (multiple-auth)"
      say ""
      say "Next:"
      say "  ./wazuh-deploy.sh pki csr && ./wazuh-deploy.sh pki sign   # keycloak cert (idempotent)"
      say "  docker compose up -d && docker compose up -d --force-recreate wazuh.dashboard"
      say "  ./wazuh-deploy.sh sso init"
      say "  (browsers need a DNS/hosts record: sso.$SIEM_DOMAIN -> host IP, port 8443)"
      ;;
    init)
      grep -qs 'OIDC_CLIENT_SECRET' .env || { failm "run: sso enable first"; exit 1; }
      say "[*] Waiting for Keycloak (realm import can take ~1 min)..."
      local i ready=no
      for i in $(seq 1 30); do
        if curl -ks --cacert config/wazuh_indexer_ssl_certs/root-ca.pem \
          --resolve "sso.$SIEM_DOMAIN:8443:127.0.0.1" \
          "https://sso.$SIEM_DOMAIN:8443/realms/siem/.well-known/openid-configuration" \
          | grep -q '"issuer"'; then ready=yes; break; fi
        sleep 10
      done
      [[ "$ready" == "yes" ]] || { failm "Keycloak discovery not answering"; exit 1; }
      ok "Keycloak realm 'siem' is up (OIDC discovery over TLS)"

      say "[*] Applying OIDC auth + role mappings to the indexer security plugin..."
      mkdir -p config/wazuh_indexer/security
      cat > config/wazuh_indexer/security/config.yml <<'SECEOF'
_meta:
  type: "config"
  config_version: 2
config:
  dynamic:
    http:
      anonymous_auth_enabled: false
    authc:
      basic_internal_auth_domain:
        description: "Internal users (admin, kibanaserver, ...)"
        http_enabled: true
        transport_enabled: true
        order: 0
        http_authenticator:
          type: basic
          challenge: false
        authentication_backend:
          type: intern
      openid_auth_domain:
        description: "Keycloak OIDC (groups claim -> backend roles)"
        http_enabled: true
        transport_enabled: true
        order: 1
        http_authenticator:
          type: openid
          challenge: false
          config:
            subject_key: preferred_username
            roles_key: groups
            openid_connect_url: https://keycloak:8443/realms/siem/.well-known/openid-configuration
            openid_connect_idp:
              enable_ssl: true
              verify_hostnames: true
              pemtrustedcas_filepath: /usr/share/wazuh-indexer/config/certs/root-ca.pem
        authentication_backend:
          type: noop
SECEOF
      say "[*] Applying config/sso-groups.conf to every permission layer..."
      python3 scripts/apply-sso-groups.py || { failm "group mapping failed"; exit 1; }

      if [[ -f config/ism/security-audit-retention-policy.json ]]; then
        idx_api PUT "/_plugins/_ism/policies/security-audit-retention" \
          "$(cat config/ism/security-audit-retention-policy.json)" >/dev/null 2>&1 || true
        ok "audit-index retention policy applied (security-auditlog-*, 180d)"
      fi
      ok "SSO initialized - test with: ./wazuh-deploy.sh sso status"
      ;;
    status)
      local tok
      tok=$(curl -ks --cacert config/wazuh_indexer_ssl_certs/root-ca.pem \
        --resolve "sso.$SIEM_DOMAIN:8443:127.0.0.1" \
        -d "client_id=wazuh-dashboard" \
        -d "client_secret=$(grep '^OIDC_CLIENT_SECRET=' .env | cut -d= -f2)" \
        -d "grant_type=password" -d "username=analyst1" \
        -d "password=$(grep '^SSO_ANALYST_PASSWORD=' .env | cut -d= -f2)" \
        "https://sso.$SIEM_DOMAIN:8443/realms/siem/protocol/openid-connect/token" \
        | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))")
      [[ -n "$tok" ]] || { failm "could not obtain OIDC token for analyst1"; exit 1; }
      ok "OIDC token issued for analyst1 (direct grant against the realm)"
      say "   group map: config/sso-groups.conf"
      docker exec master1.indexer curl -s \
        --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
        -H "Authorization: Bearer $tok" \
        "https://master1.indexer:9200/_plugins/_security/authinfo" \
        | python3 -c "import json,sys; d=json.load(sys.stdin); print('   user:', d.get('user_name')); print('   backend roles:', d.get('backend_roles')); print('   indexer roles:', d.get('roles'))"
      # second layer: what the Wazuh API grants this user via run_as
      local pw rt
      pw=$(grep '^API_PASSWORD=' .env | cut -d= -f2)
      rt=$(curl -ks -u "wazuh-wui:$pw" -H "Content-Type: application/json" \
        --cacert config/wazuh_indexer_ssl_certs/root-ca.pem \
        --resolve "wazuh.master:55000:127.0.0.1" \
        -X POST "https://wazuh.master:55000/security/user/authenticate/run_as?raw=true" \
        -d '{"user_name":"analyst1","backend_roles":["siem-analysts"]}')
      curl -ks -H "Authorization: Bearer $rt" --cacert config/wazuh_indexer_ssl_certs/root-ca.pem \
        --resolve "wazuh.master:55000:127.0.0.1" "https://wazuh.master:55000/security/users/me" \
        | python3 -c "
import json,sys
d=json.load(sys.stdin)['data']['affected_items'][0]
print('   wazuh API roles:', [r['name'] for r in d['roles']])
print('   mitre:read granted:', any(p['name']=='mitre_read_mitre' for r in d['roles'] for p in r['policies']))"
      ;;
    *) failm "usage: wazuh-deploy.sh sso {enable|init|status}"; exit 1 ;;
  esac
}

# ==================================================================== soc ====
# MISP (threat intel) + DFIR-IRIS (case management), both behind Keycloak OIDC.
cmd_soc() {
  require_config
  local sub="${1:-}"; shift || true
  case "$sub" in
    enable)
      [[ -f .env ]] || { failm "run ./generate-credentials.sh first"; exit 1; }
      grep -qs 'OIDC_CLIENT_SECRET' .env || { failm "enable SSO first: ./wazuh-deploy.sh sso enable"; exit 1; }
      grep -q '^MISP_DB_PASSWORD=' .env || cat >> .env <<SOCEOF

# --- SOC module (MISP + DFIR-IRIS) -------------------------------------------
MISP_DB_PASSWORD=$(openssl rand -hex 16)
MISP_DB_ROOT_PASSWORD=$(openssl rand -hex 16)
MISP_ADMIN_EMAIL=admin@siem.local
MISP_ADMIN_PASSWORD=Misp1.$(openssl rand -hex 12)
MISP_OIDC_SECRET=$(openssl rand -hex 20)
IRIS_DB_USER=raccoon
IRIS_DB_PASSWORD=$(openssl rand -hex 16)
IRIS_DB_ADMIN_USER=raccoon_admin
IRIS_DB_ADMIN_PASSWORD=$(openssl rand -hex 16)
IRIS_SECRET_KEY=$(openssl rand -hex 32)
IRIS_SALT=$(openssl rand -hex 16)
IRIS_ADMIN_PASSWORD=Iris1.$(openssl rand -hex 12)
IRIS_API_KEY=$(openssl rand -hex 32)
IRIS_OIDC_SECRET=$(openssl rand -hex 20)
SOCEOF
      enable_profile soc
      # render the realm with all three client secrets
      sed -e "s|REPLACE_WITH_OIDC_CLIENT_SECRET|$(grep '^OIDC_CLIENT_SECRET=' .env | cut -d= -f2)|" \
          -e "s|REPLACE_WITH_MISP_OIDC_SECRET|$(grep '^MISP_OIDC_SECRET=' .env | cut -d= -f2)|" \
          -e "s|REPLACE_WITH_IRIS_OIDC_SECRET|$(grep '^IRIS_OIDC_SECRET=' .env | cut -d= -f2)|" \
          -e "s|REPLACE_WITH_SSO_ADMIN_PASSWORD|$(grep '^SSO_ADMIN_PASSWORD=' .env | cut -d= -f2)|" \
          -e "s|REPLACE_WITH_SSO_ANALYST_PASSWORD|$(grep '^SSO_ANALYST_PASSWORD=' .env | cut -d= -f2)|" \
          config/templates/keycloak-realm.json.tpl > config/keycloak/realm-siem.json
      ok "realm re-rendered with misp + iris OIDC clients"
      say ""
      say "Next:"
      say "  ./wazuh-deploy.sh pki csr && ./wazuh-deploy.sh pki sign   # misp + iris certs"
      say "  docker compose up -d                                      # starts the SOC tier"
      say "  docker compose restart keycloak                           # re-imports the realm clients"
      say "  ./wazuh-deploy.sh soc init                                # Wazuh -> IRIS/MISP wiring"
      say "  DNS/hosts: misp.$SIEM_DOMAIN and iris.$SIEM_DOMAIN -> host IP"
      ;;
    init)
      soc_enabled || { failm "soc module not enabled - run: soc enable"; exit 1; }
      say "[*] Installing the Wazuh -> IRIS / MISP integrations on the master..."
      docker cp scripts/integrations/custom-iris wazuh.master:/var/ossec/integrations/custom-iris
      docker cp scripts/integrations/custom-iris.py wazuh.master:/var/ossec/integrations/custom-iris.py
      docker cp scripts/integrations/custom-misp wazuh.master:/var/ossec/integrations/custom-misp
      docker cp scripts/integrations/custom-misp.py wazuh.master:/var/ossec/integrations/custom-misp.py
      docker exec wazuh.master chmod 750 /var/ossec/integrations/custom-iris /var/ossec/integrations/custom-iris.py \
        /var/ossec/integrations/custom-misp /var/ossec/integrations/custom-misp.py
      docker exec wazuh.master chown root:wazuh /var/ossec/integrations/custom-iris /var/ossec/integrations/custom-iris.py \
        /var/ossec/integrations/custom-misp /var/ossec/integrations/custom-misp.py
      ok "integration scripts installed (enabled by the <integration> blocks in the manager config)"
      say "[*] Endpoint checks:"
      local c
      for spec in "misp:8081:/users/login" "iris:8082:/"; do
        local h p path
        IFS=':' read -r h p path <<< "$spec"
        c=$(curl -ks -o /dev/null -w '%{http_code}' --cacert config/wazuh_indexer_ssl_certs/root-ca.pem \
            --resolve "$h.$SIEM_DOMAIN:$p:127.0.0.1" "https://$h.$SIEM_DOMAIN:$p$path" || true)
        [[ "$c" =~ ^(200|302|303)$ ]] && ok "$h reachable over TLS (HTTP $c)" \
          || warn "$h not ready yet (HTTP $c) - first boot takes several minutes"
      done
      ;;
    status)
      docker ps --filter name=misp --filter name=iris --format '{{.Names}}: {{.Status}}'
      ;;
    *) failm "usage: wazuh-deploy.sh soc {enable|init|status}"; exit 1 ;;
  esac
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
  # expected count is profile-aware (archive/ml modules add services)
  local up expected
  expected=$(docker compose config --services 2>/dev/null | wc -l | tr -d ' ')
  up=$(docker compose ps --status running --format '{{.Name}}' 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$up" == "$expected" ]]; then ok "containers: $up/$expected running"
  else failm "containers: $up/$expected running"; fails=$((fails+1)); fi

  # Wazuh server cluster
  local cl
  cl=$(docker exec wazuh.master /var/ossec/bin/cluster_control -l 2>/dev/null | grep -c worker || true)
  if [[ "$cl" == "4" ]]; then ok "Wazuh master + 4 workers joined"
  else failm "Wazuh cluster: only $cl/4 workers joined"; fails=$((fails+1)); fi

  # indexer cluster - full TLS verification from inside the trust domain.
  # Expected node count = running *.indexer containers (profile-aware).
  local health exp_nodes
  exp_nodes=$(docker ps --format '{{.Names}}' | grep -c '\.indexer$' || true)
  health=$(docker exec master1.indexer curl -s \
    --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
    -u "admin:$(grep '^INDEXER_PASSWORD=' .env | cut -d= -f2)" \
    "https://master1.indexer:9200/_cluster/health" 2>/dev/null || true)
  if echo "$health" | grep -q "\"number_of_nodes\":$exp_nodes" && echo "$health" | grep -q '"status":"green"'; then
    ok "indexer cluster: $exp_nodes nodes, health green (TLS verified against root CA)"
  else
    failm "indexer cluster unhealthy (expected $exp_nodes nodes): $(echo "$health" | head -c 120)"; fails=$((fails+1))
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
  dns)          cmd_dns "$@" ;;
  maps)         cmd_maps "$@" ;;
  sso)          cmd_sso "$@" ;;
  soc)          cmd_soc "$@" ;;
  archive)      cmd_archive "$@" ;;
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
  archive enable|init|snapshot|status   optional RustFS S3 long-retention module
  maps enable|init|status               optional offline maps (self-hosted tiles)
  sso enable|init|status                optional Keycloak OIDC single sign-on
  soc enable|init|status                optional MISP + DFIR-IRIS SOC tier
  dns records                           regenerate AD DNS script / hosts snippet
  deploy docker|baremetal
  verify                       runtime verification
  status
EOF
    exit 1 ;;
esac
