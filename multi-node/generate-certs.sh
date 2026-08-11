#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# PKI lifecycle tooling for the air-gapped Wazuh multi-node deployment.
#
# The certificate lifecycle is EXPLICIT and staged:
#
#   private key -> CSR -> CA signing -> signed certificate -> import -> verify
#
# Commands:
#   ./generate-certs.sh csr                  Phase 1: keys + CSRs (no certs)
#   ./generate-certs.sh sign --ca step       Phase 2A: bundled step-ca signs the CSRs
#   ./generate-certs.sh sign --ca openssl    Phase 2B: bundled openssl CA signs the CSRs
#                                            Phase 2C: corporate CA - submit csr/*.csr
#                                            to your PKI, copy signed certs back
#   ./generate-certs.sh import              Phase 3: check externally signed certs
#                                            are all present, then verify
#   ./generate-certs.sh verify              Preflight gate: full validation of every
#                                            certificate; non-zero exit blocks deploy
#   ./generate-certs.sh                     Legacy one-shot: csr -> sign -> verify
#                                            (each stage printed explicitly)
#
# Options / env:
#   --force            allow overwriting existing keys/CSRs/certs (destructive)
#   --ca step|openssl  CA engine for 'sign' (or CA_MODE env; default step)
#   SIEM_DOMAIN        DNS suffix used in SANs (default siem.local.domain).
#                      Docker uses service names + this suffix; VM/bare-metal
#                      deployments should set it to their real DNS zone.
#   CERT_DAYS / CA_DAYS / STEP_IMAGE / OUT_DIR / CA_DIR / CSR_DIR overrides.
#
# All identities come from ONE canonical inventory: config/certs-inventory.conf
# (name|role|sans|required_ekus). CSR generation, signing, verification and
# deploy-certs.sh all parse that file - nothing is defined twice.
#
# Air-gap: no network access is used. step mode runs the already-transferred
# smallstep/step-ca image; openssl mode is pure host openssl.
#
# Security: the CA private key lives in $CA_DIR, is used only by 'sign', is
# never mounted into any runtime container, and should be moved to offline
# protected storage after issuance. The running stack needs only root-ca.pem,
# the leaf certificates and the leaf private keys.
# -----------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

SIEM_DOMAIN="${SIEM_DOMAIN:-${DOMAIN:-siem.local.domain}}"
CA_MODE="${CA_MODE:-step}"
CA_DAYS="${CA_DAYS:-3650}"
CERT_DAYS="${CERT_DAYS:-825}"
STEP_IMAGE="${STEP_IMAGE:-smallstep/step-ca:latest}"

CA_DIR="${CA_DIR:-config/certs-ca}"
OUT_DIR="${OUT_DIR:-config/wazuh_indexer_ssl_certs}"
CSR_DIR="${CSR_DIR:-$OUT_DIR/csr}"
INVENTORY="${INVENTORY:-config/certs-inventory.conf}"

FORCE=no

# --- inventory ---------------------------------------------------------------
# Emits: name|role|sans|ekus  (domain expanded, comments stripped)
inventory() {
  grep -Ev '^\s*(#|$)' "$INVENTORY" | sed "s/@DOMAIN@/$SIEM_DOMAIN/g"
}

sha256() { openssl dgst -sha256 -r | cut -d' ' -f1; }

step() {
  docker run --rm -v "$PWD:/work" -w /work --entrypoint step "$STEP_IMAGE" "$@"
}

# =============================================================================
# Phase 1 - csr: private keys + CSRs (CA-agnostic, plain openssl)
# =============================================================================
cmd_csr() {
  mkdir -p "$OUT_DIR" "$CSR_DIR"
  local made=0
  while IFS='|' read -r name role sans ekus; do
    local key="$OUT_DIR/$name-key.pem" csr="$CSR_DIR/$name.csr" cnf="$CSR_DIR/$name.cnf"

    # The .cnf is kept next to the CSR so the requested identity is auditable
    # and the CSR is reproducible.
    cat > "$cnf" <<EOF
# CSR request configuration for '$name' (role: $role)
# Generated from config/certs-inventory.conf - regenerate there, not here.
[req]
default_md          = sha256
prompt              = no
distinguished_name  = dn
req_extensions      = ext
[dn]
CN = $name
[ext]
basicConstraints    = CA:FALSE
keyUsage            = critical, digitalSignature, keyEncipherment
extendedKeyUsage    = ${ekus//,/, }
subjectAltName      = DNS:${sans//,/,DNS:}
EOF

    if [[ -f "$key" && "$FORCE" != "yes" ]]; then
      echo "[SKIP] $name: private key exists"
    else
      openssl genrsa -out "$key" 2048 2>/dev/null
      chmod 644 "$key"
      echo "[KEY ] $name: private key generated"
    fi

    if [[ -f "$csr" && "$FORCE" != "yes" ]]; then
      echo "[SKIP] $name: CSR exists"
    else
      openssl req -new -key "$key" -config "$cnf" -out "$csr"
      echo "[CSR ] $name: CSR generated (SANs: $sans; EKUs: $ekus)"
      made=$((made+1))
    fi
  done < <(inventory)

  cat <<EOF

CSRs generated successfully ($made new).

Submit the files under:
  $CSR_DIR/

to your CA (bundled step/openssl CA via './generate-certs.sh sign', or your
corporate PKI - see DEPLOYMENT-GUIDE.md section 4).

PRIVATE KEYS MUST NOT LEAVE THIS HOST.
The CA needs ONLY the .csr files.

After receiving the signed certificates (and root-ca.pem), run:
  ./generate-certs.sh import      (or: ./wazuh-deploy.sh pki import)
EOF
}

# =============================================================================
# Phase 2 - sign: the bundled CA signs the EXISTING CSRs
# =============================================================================
ensure_ca() {
  mkdir -p "$CA_DIR"
  if [[ -f "$CA_DIR/root-ca.pem" && -f "$CA_DIR/root-ca.key" ]]; then
    echo "[*] Reusing existing CA in $CA_DIR"
    return
  fi
  if [[ -f "$CA_DIR/root-ca.pem" ]]; then
    echo "[!] $CA_DIR/root-ca.pem exists without its key - this host cannot sign." >&2
    echo "    Use the corporate-CA flow (csr -> external signing -> import) instead." >&2
    exit 1
  fi
  echo "[*] Creating root CA ($CA_MODE) for $SIEM_DOMAIN"
  if [[ "$CA_MODE" == "step" ]]; then
    step certificate create "SIEM Root CA ($SIEM_DOMAIN)" \
      "$CA_DIR/root-ca.pem" "$CA_DIR/root-ca.key" \
      --profile root-ca --kty RSA --size 4096 \
      --not-after "$((CA_DAYS * 24))h" --no-password --insecure
  else
    openssl genrsa -out "$CA_DIR/root-ca.key" 4096 2>/dev/null
    openssl req -x509 -new -nodes -key "$CA_DIR/root-ca.key" -sha256 \
      -days "$CA_DAYS" -subj "/CN=SIEM Root CA ($SIEM_DOMAIN)" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -out "$CA_DIR/root-ca.pem"
  fi
  chmod 600 "$CA_DIR/root-ca.key"
}

cmd_sign() {
  [[ "$CA_MODE" == "step" || "$CA_MODE" == "openssl" ]] || {
    echo "[!] --ca must be 'step' or 'openssl' (got: $CA_MODE)" >&2; exit 1; }

  # Refuse to invent CSRs: phase 1 must have run.
  local missing=()
  while IFS='|' read -r name _; do
    [[ -f "$CSR_DIR/$name.csr" ]] || missing+=("$name")
  done < <(inventory)
  if (( ${#missing[@]} > 0 )); then
    echo "[!] No CSR found for: ${missing[*]}" >&2
    echo "    Run './generate-certs.sh csr' first (this phase signs existing CSRs" >&2
    echo "    and never regenerates them; use 'csr --force' to redo them)." >&2
    exit 1
  fi

  ensure_ca
  cp "$CA_DIR/root-ca.pem" "$OUT_DIR/root-ca.pem"

  while IFS='|' read -r name role sans ekus; do
    local crt="$OUT_DIR/$name.pem" csr="$CSR_DIR/$name.csr"
    if [[ -f "$crt" && "$FORCE" != "yes" ]]; then
      echo "[SKIP] $name.pem already exists"
      continue
    fi
    if [[ "$CA_MODE" == "step" ]]; then
      # step's leaf profile preserves the CSR's SANs and issues
      # serverAuth+clientAuth EKUs.
      step certificate sign --profile leaf \
        --not-after "$((CERT_DAYS * 24))h" \
        "$csr" "$CA_DIR/root-ca.pem" "$CA_DIR/root-ca.key" > "$crt"
    else
      # Extensions come from the canonical inventory (the same data the CSR
      # requested), so the issued certificate cannot drift from it.
      local ext_file
      ext_file="$(mktemp)"
      {
        echo "basicConstraints=CA:FALSE"
        echo "keyUsage=critical,digitalSignature,keyEncipherment"
        echo "extendedKeyUsage=serverAuth,clientAuth"
        echo "subjectAltName=DNS:${sans//,/,DNS:}"
      } > "$ext_file"
      openssl x509 -req -in "$csr" \
        -CA "$CA_DIR/root-ca.pem" -CAkey "$CA_DIR/root-ca.key" -CAcreateserial \
        -days "$CERT_DAYS" -sha256 -extfile "$ext_file" -out "$crt" 2>/dev/null
      rm -f "$ext_file"
    fi
    chmod 644 "$crt"
    echo "[SIGN] $name.pem issued by the $CA_MODE CA"
  done < <(inventory)

  cat <<EOF

Signing complete. The CA private key in $CA_DIR is NOT needed at runtime -
move $CA_DIR to offline protected storage now.

Next:
  ./generate-certs.sh verify      (or: ./wazuh-deploy.sh pki verify)
EOF
}

# =============================================================================
# Phase 3 - import: externally signed certificates dropped into place
# =============================================================================
cmd_import() {
  local missing=()
  [[ -f "$OUT_DIR/root-ca.pem" ]] || missing+=("root-ca.pem (CA chain)")
  while IFS='|' read -r name _; do
    [[ -f "$OUT_DIR/$name.pem" ]]     || missing+=("$name.pem")
    [[ -f "$OUT_DIR/$name-key.pem" ]] || missing+=("$name-key.pem")
  done < <(inventory)

  if (( ${#missing[@]} > 0 )); then
    echo "Import incomplete - missing from $OUT_DIR:"
    printf '  - %s\n' "${missing[@]}"
    cat <<EOF

Expected layout (names must match exactly - see config/certs-inventory.conf):
  $OUT_DIR/<name>.pem        signed certificate (leaf first, then any
                             intermediate; do NOT append the root)
  $OUT_DIR/<name>-key.pem    private key (generated here in phase 1)
  $OUT_DIR/root-ca.pem       trust chain: intermediate(s) then root,
                             concatenated in that order
EOF
    exit 1
  fi
  chmod 644 "$OUT_DIR"/*.pem
  echo "[*] All expected certificate files are present. Running verification..."
  echo
  cmd_verify
}

# =============================================================================
# verify - preflight gate (never needs the CA private key)
# =============================================================================
eku_label() {
  case "$1" in
    serverAuth) echo "TLS Web Server Authentication" ;;
    clientAuth) echo "TLS Web Client Authentication" ;;
    *)          echo "$1" ;;
  esac
}

cmd_verify() {
  echo "Certificate preflight"
  echo "======================"
  echo
  local total=0 ok=0 fail=0

  # --- Root CA / chain ---
  if [[ ! -f "$OUT_DIR/root-ca.pem" ]]; then
    echo "[FAIL] Root CA"
    echo "       $OUT_DIR/root-ca.pem is missing"
    fail=$((fail+1))
  elif ! openssl x509 -in "$OUT_DIR/root-ca.pem" -noout -checkend 0 >/dev/null 2>&1; then
    echo "[FAIL] Root CA"
    echo "       root-ca.pem is expired or unreadable"
    fail=$((fail+1))
  elif ! openssl x509 -in "$OUT_DIR/root-ca.pem" -noout -text 2>/dev/null | grep -q "CA:TRUE"; then
    echo "[FAIL] Root CA"
    echo "       first certificate in root-ca.pem is not a CA certificate"
    fail=$((fail+1))
  else
    echo "[OK] Root CA"
    ok=$((ok+1))
  fi
  total=$((total+1))

  # --- every leaf ---
  while IFS='|' read -r name role sans ekus; do
    total=$((total+1))
    local crt="$OUT_DIR/$name.pem" key="$OUT_DIR/$name-key.pem"
    local errs=()

    if [[ ! -f "$crt" ]]; then
      errs+=("certificate file $name.pem is missing")
    elif [[ ! -f "$key" ]]; then
      errs+=("private key $name-key.pem is missing")
    else
      # key <-> cert match (public key sha256)
      local kh ch
      kh=$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | sha256)
      ch=$(openssl x509 -in "$crt" -pubkey -noout 2>/dev/null \
            | openssl pkey -pubin -pubout -outform DER 2>/dev/null | sha256)
      [[ -n "$kh" && "$kh" == "$ch" ]] || errs+=("private key does not match the certificate")

      # chain to root-ca.pem; -untrusted "$crt" lets a bundled intermediate in
      # the leaf file participate in chain building. Also catches expired /
      # not-yet-valid certificates.
      local vout
      if ! vout=$(openssl verify -CAfile "$OUT_DIR/root-ca.pem" -untrusted "$crt" "$crt" 2>&1); then
        errs+=("does not chain to root-ca.pem: $(echo "$vout" | grep -m1 error || echo "$vout" | head -1)")
      fi

      # subject / CN
      local subj
      subj=$(openssl x509 -in "$crt" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')
      if [[ "$role" == "indexer" || "$name" == "admin" ]]; then
        # pinned verbatim in nodes_dn / admin_dn - must be exactly CN=<name>
        [[ "$subj" == "CN=$name" ]] || errs+=("subject must be exactly 'CN=$name' (pinned in opensearch.yml), got '$subj'")
      else
        echo ",$subj," | grep -q ",CN=$name," || errs+=("subject CN is not '$name' (got '$subj')")
      fi

      # SANs
      local san_out
      san_out=$(openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null || true)
      local s
      for s in ${sans//,/ }; do
        echo "$san_out" | grep -Eq "DNS:$s(,|[[:space:]]|$)" \
          || errs+=("Certificate SAN does not contain: $s")
      done

      # required EKUs
      local eku_out e
      eku_out=$(openssl x509 -in "$crt" -noout -ext extendedKeyUsage 2>/dev/null || true)
      for e in ${ekus//,/ }; do
        echo "$eku_out" | grep -q "$(eku_label "$e")" \
          || errs+=("required EKU missing: $e")
      done

      # key strength
      local bits
      bits=$(openssl x509 -in "$crt" -noout -text 2>/dev/null \
              | grep -m1 "Public-Key:" | grep -o '[0-9]*')
      if [[ -n "$bits" ]]; then
        local min=2048
        openssl x509 -in "$crt" -noout -text 2>/dev/null | grep -q "id-ecPublicKey" && min=256
        (( bits >= min )) || errs+=("public key too small: $bits bits (minimum $min)")
      fi

      # expiry warning (30 days) - non-fatal
      if ! openssl x509 -in "$crt" -noout -checkend 2592000 >/dev/null 2>&1 \
         && openssl x509 -in "$crt" -noout -checkend 0 >/dev/null 2>&1; then
        echo "[WARN] $name expires within 30 days"
      fi
    fi

    if (( ${#errs[@]} == 0 )); then
      echo "[OK] $name"
      ok=$((ok+1))
    else
      echo "[FAIL] $name"
      printf '       %s\n' "${errs[@]}"
      fail=$((fail+1))
    fi
  done < <(inventory)

  echo
  echo "$ok/$total certificates valid."
  echo
  if (( fail > 0 )); then
    echo "TLS certificate validation FAILED."
    echo
    echo "DEPLOYMENT BLOCKED."
    exit 1
  fi
  cat <<EOF
TLS certificate validation PASSED.

It is now safe to run:

  docker compose up -d
EOF
}

# =============================================================================
# argument parsing
# =============================================================================
CMD="${1:-all}"
[[ $# -gt 0 ]] && shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=yes ;;
    --ca)    CA_MODE="$2"; shift ;;
    --ca=*)  CA_MODE="${1#--ca=}" ;;
    *) echo "[!] Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

case "$CMD" in
  csr)    cmd_csr ;;
  sign)   cmd_sign ;;
  import) cmd_import ;;
  verify) cmd_verify ;;
  all)
    echo "=== Stage 1/3: private keys + CSRs ==========================="
    cmd_csr
    echo
    echo "=== Stage 2/3: CA signs the CSRs ($CA_MODE) =================="
    cmd_sign
    echo
    echo "=== Stage 3/3: verification =================================="
    cmd_verify
    ;;
  *)
    echo "Usage: $0 [csr|sign|import|verify] [--ca step|openssl] [--force]" >&2
    exit 1
    ;;
esac
