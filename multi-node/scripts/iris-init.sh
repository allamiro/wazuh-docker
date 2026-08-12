#!/bin/sh
# Trust the deployment root CA before IRIS starts.
#
# In oidc_proxy mode IRIS decodes the JWT forwarded by the OAuth2 proxy and
# fetches Keycloaks JWKS over TLS. It does that with Python, which reads the
# certifi bundle inside the virtualenv - NOT the system store and NOT
# TLS_ROOT_CA. Without appending the CA to certifi every login fails with
# "CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate".
set -e
CA=/etc/ssl/certs/siem-root-ca.pem
if [ -f "$CA" ]; then
  # system store (used by curl and OpenSSL directly)
  if command -v update-ca-certificates >/dev/null 2>&1; then
    cp "$CA" /usr/local/share/ca-certificates/siem-root-ca.crt 2>/dev/null || true
    update-ca-certificates >/dev/null 2>&1 || true
  fi
  # certifi bundle (used by Python: urllib, requests, oic)
  CERTIFI=$(python3 -c "import certifi; print(certifi.where())" 2>/dev/null || true)
  for b in "$CERTIFI" /etc/ssl/certs/ca-certificates.crt; do
    [ -n "$b" ] && [ -f "$b" ] || continue
    grep -qF "$(head -2 "$CA" | tail -1)" "$b" 2>/dev/null || cat "$CA" >> "$b"
  done
fi
exec "$@"
