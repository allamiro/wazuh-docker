#!/bin/bash
# Install the deployment root CA into the system trust store before MISP
# starts. Without it MISPs OIDC client fails with
# "cURL error #60: SSL certificate problem: unable to get local issuer
# certificate" when it calls Keycloak, and every page returns 500.
set -e
if [ -f /siem-root-ca.pem ]; then
  cp /siem-root-ca.pem /usr/local/share/ca-certificates/siem-root-ca.crt
  update-ca-certificates >/dev/null 2>&1 || true
fi
exec /entrypoint.sh "$@"
