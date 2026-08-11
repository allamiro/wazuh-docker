#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# TLS certificate generation for the air-gapped Wazuh multi-node stack.
#
# Simulates the "external CA" workflow: a root CA is created (or provided by
# your organisation), every component gets its own private key and CSR, and
# each CSR is signed by the CA. Two modes:
#
#   CA_MODE=step    (default) - uses the smallstep/step-ca container.
#   CA_MODE=openssl           - pure openssl on the host, no extra image.
#
# To have certificates signed by a REAL external/corporate CA instead:
#   run with GENERATE_CSR_ONLY=yes, hand the CSRs in ./csr/ to your CA,
#   then drop the signed certs back with the expected file names (see guide).
#
# Outputs (relative to multi-node/):
#   config/certs-ca/root-ca.key            CA private key   - PROTECT THIS
#   config/wazuh_indexer_ssl_certs/*.pem   leaf certs + keys + root-ca.pem
# -----------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

DOMAIN="${DOMAIN:-siem.local.domain}"
CA_MODE="${CA_MODE:-step}"
GENERATE_CSR_ONLY="${GENERATE_CSR_ONLY:-no}"
CA_DAYS="${CA_DAYS:-3650}"
CERT_DAYS="${CERT_DAYS:-825}"
STEP_IMAGE="${STEP_IMAGE:-smallstep/step-ca:latest}"

CA_DIR="config/certs-ca"
OUT_DIR="config/wazuh_indexer_ssl_certs"
CSR_DIR="$OUT_DIR/csr"

# entity list: "<file-and-CN>|<comma separated SANs>"
# CN-only subjects: plugins.security.nodes_dn / authcz.admin_dn in the indexer
# configs must match these exactly (they are "CN=<name>").
ENTITIES=(
  # indexer cluster - 16 nodes
  "master1.indexer|master1.indexer,master1.$DOMAIN"
  "master2.indexer|master2.indexer,master2.$DOMAIN"
  "master3.indexer|master3.indexer,master3.$DOMAIN"
  "hot1.indexer|hot1.indexer,hot1.$DOMAIN"
  "hot2.indexer|hot2.indexer,hot2.$DOMAIN"
  "hot3.indexer|hot3.indexer,hot3.$DOMAIN"
  "warm1.indexer|warm1.indexer,warm1.$DOMAIN"
  "warm2.indexer|warm2.indexer,warm2.$DOMAIN"
  "warm3.indexer|warm3.indexer,warm3.$DOMAIN"
  "cold1.indexer|cold1.indexer,cold1.$DOMAIN"
  "cold2.indexer|cold2.indexer,cold2.$DOMAIN"
  "cold3.indexer|cold3.indexer,cold3.$DOMAIN"
  "ingest1.indexer|ingest1.indexer,ingest1.$DOMAIN"
  "ingest2.indexer|ingest2.indexer,ingest2.$DOMAIN"
  "coord1.indexer|coord1.indexer,indexer.$DOMAIN"
  "coord2.indexer|coord2.indexer,indexer.$DOMAIN"
  # securityadmin client certificate
  "admin|admin"
  # Wazuh server cluster - Filebeat client certs (+ authd server cert on master)
  "wazuh.master|wazuh.master,$DOMAIN,manager.$DOMAIN"
  "wazuh.worker1|wazuh.worker1"
  "wazuh.worker2|wazuh.worker2"
  "wazuh.worker3|wazuh.worker3"
  "wazuh.worker4|wazuh.worker4"
  # dashboard HTTPS server cert - this is what browsers see
  "wazuh.dashboard|wazuh.dashboard,$DOMAIN,dashboard.$DOMAIN,localhost"
)

mkdir -p "$CA_DIR" "$OUT_DIR" "$CSR_DIR"

step() {
  # Run the step CLI from the step-ca container. The repo root is mounted at
  # /work so paths used below stay relative.
  docker run --rm -v "$PWD:/work" -w /work --entrypoint step "$STEP_IMAGE" "$@"
}

# --- 1. Root CA --------------------------------------------------------------
if [[ -f "$CA_DIR/root-ca.pem" && -f "$CA_DIR/root-ca.key" ]]; then
  echo "[*] Reusing existing root CA in $CA_DIR"
elif [[ -f "$CA_DIR/root-ca.pem" ]]; then
  echo "[*] Found root-ca.pem without key (external CA mode)"
else
  echo "[*] Creating root CA ($CA_MODE) for $DOMAIN"
  if [[ "$CA_MODE" == "step" ]]; then
    step certificate create "SIEM Root CA ($DOMAIN)" \
      "$CA_DIR/root-ca.pem" "$CA_DIR/root-ca.key" \
      --profile root-ca --kty RSA --size 4096 \
      --not-after "$((CA_DAYS * 24))h" --no-password --insecure
  else
    openssl genrsa -out "$CA_DIR/root-ca.key" 4096
    openssl req -x509 -new -nodes -key "$CA_DIR/root-ca.key" -sha256 \
      -days "$CA_DAYS" -subj "/CN=SIEM Root CA ($DOMAIN)" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -out "$CA_DIR/root-ca.pem"
  fi
fi
cp "$CA_DIR/root-ca.pem" "$OUT_DIR/root-ca.pem"

# --- 2. Keys + CSRs + signing ------------------------------------------------
for entry in "${ENTITIES[@]}"; do
  name="${entry%%|*}"
  sans="${entry##*|}"

  if [[ -f "$OUT_DIR/$name.pem" ]]; then
    echo "[*] $name: certificate exists, skipping"
    continue
  fi

  echo "[*] $name: generating key + CSR (SANs: $sans)"
  if [[ "$CA_MODE" == "step" ]]; then
    san_flags=()
    IFS=',' read -ra san_list <<< "$sans"
    for s in "${san_list[@]}"; do san_flags+=(--san "$s"); done
    step certificate create "$name" \
      "$CSR_DIR/$name.csr" "$OUT_DIR/$name-key.pem" \
      --csr --kty RSA --size 2048 "${san_flags[@]}" \
      --no-password --insecure
  else
    openssl genrsa -out "$OUT_DIR/$name-key.pem" 2048
    san_ext="subjectAltName=DNS:$(echo "$sans" | sed 's/,/,DNS:/g')"
    openssl req -new -key "$OUT_DIR/$name-key.pem" \
      -subj "/CN=$name" -addext "$san_ext" -out "$CSR_DIR/$name.csr"
  fi

  if [[ "$GENERATE_CSR_ONLY" == "yes" ]]; then
    echo "    -> CSR written to $CSR_DIR/$name.csr (not signing)"
    continue
  fi

  echo "[*] $name: signing CSR with the CA"
  if [[ "$CA_MODE" == "step" ]]; then
    step certificate sign --profile leaf \
      --not-after "$((CERT_DAYS * 24))h" \
      "$CSR_DIR/$name.csr" "$CA_DIR/root-ca.pem" "$CA_DIR/root-ca.key" \
      > "$OUT_DIR/$name.pem"
  else
    ext_file="$(mktemp)"
    {
      echo "basicConstraints=CA:FALSE"
      echo "keyUsage=critical,digitalSignature,keyEncipherment"
      echo "extendedKeyUsage=serverAuth,clientAuth"
      echo "subjectAltName=DNS:$(echo "$sans" | sed 's/,/,DNS:/g')"
    } > "$ext_file"
    openssl x509 -req -in "$CSR_DIR/$name.csr" \
      -CA "$CA_DIR/root-ca.pem" -CAkey "$CA_DIR/root-ca.key" -CAcreateserial \
      -days "$CERT_DAYS" -sha256 -extfile "$ext_file" \
      -out "$OUT_DIR/$name.pem"
    rm -f "$ext_file"
  fi
done

[[ "$GENERATE_CSR_ONLY" == "yes" ]] && { echo "[*] CSR-only mode done. Send $CSR_DIR/*.csr to your CA."; exit 0; }

# --- 3. Verify ---------------------------------------------------------------
echo
echo "[*] Verifying issued certificates against the root CA:"
fail=0
for entry in "${ENTITIES[@]}"; do
  name="${entry%%|*}"
  if openssl verify -CAfile "$OUT_DIR/root-ca.pem" "$OUT_DIR/$name.pem" >/dev/null 2>&1; then
    subj=$(openssl x509 -in "$OUT_DIR/$name.pem" -noout -subject | sed 's/subject=//')
    sans=$(openssl x509 -in "$OUT_DIR/$name.pem" -noout -ext subjectAltName 2>/dev/null | tail -1 | sed 's/^ *//')
    printf "    OK  %-28s %s  [%s]\n" "$name" "$subj" "$sans"
  else
    echo "    FAIL $name"
    fail=1
  fi
done
[[ $fail -eq 1 ]] && exit 1

# Containers (indexer uid 1000, dashboard uid 1000) must be able to read the
# keys; the directory itself should be owned by root on the host.
chmod 644 "$OUT_DIR"/*.pem
chmod 600 "$CA_DIR/root-ca.key" 2>/dev/null || true

echo
echo "[*] Done. Leaf certs + keys: $OUT_DIR"
echo "[!] Protect $CA_DIR/root-ca.key - it is the CA. It is NOT needed at runtime."
