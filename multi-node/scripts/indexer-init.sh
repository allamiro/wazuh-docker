#!/bin/bash
# -----------------------------------------------------------------------------
# Indexer container init wrapper (entrypoint). Two jobs:
#
#  1. Assemble the node's opensearch.yml from the read-only mounted
#     /opensearch.node.yml, appending the S3 client block only when the
#     archive module is enabled (S3_ENDPOINT set). The settings cannot live
#     in the static file because OpenSearch refuses unknown settings while
#     the repository-s3 plugin is not installed.
#  2. When the archive module is enabled: install the bundled repository-s3
#     plugin (offline zip from /archive), trust the deployment root CA in the
#     bundled JDK (the S3 client uses the JVM truststore, not the security
#     plugin's PEM trust), and load the S3 keys into the OpenSearch keystore
#     (never into plain config files).
#
# Without S3_ENDPOINT this wrapper only performs step 1 and behaves exactly
# like the stock image.
# -----------------------------------------------------------------------------
set -e
HOME_DIR=/usr/share/wazuh-indexer
CONF=$HOME_DIR/config
# the stock entrypoint exports these before starting opensearch; the CLI tools
# (opensearch-plugin / opensearch-keystore) need them here too
export OPENSEARCH_HOME=$HOME_DIR
export OPENSEARCH_PATH_CONF=$CONF
export OPENSEARCH_JAVA_HOME=${OPENSEARCH_JAVA_HOME:-$HOME_DIR/jdk}

cp /opensearch.node.yml "$CONF/opensearch.yml"

if [ -n "${S3_ENDPOINT:-}" ]; then
  cat >> "$CONF/opensearch.yml" <<EOF

# --- archive module (appended by indexer-init.sh) ---
s3.client.default.endpoint: $S3_ENDPOINT
s3.client.default.path_style_access: true
s3.client.default.region: ${S3_REGION:-us-east-1}
EOF

  # opensearch-env sources this file unconditionally when the CLI tools run
  # outside the stock entrypoint; make sure it exists.
  mkdir -p /etc/sysconfig && touch /etc/sysconfig/wazuh-indexer

  if ! "$HOME_DIR/bin/opensearch-plugin" list 2>/dev/null | grep -q "^repository-s3"; then
    zip=$(ls /archive/repository-s3-*.zip 2>/dev/null | head -1 || true)
    if [ -n "$zip" ]; then
      echo "[indexer-init] installing repository-s3 plugin from $zip"
      "$HOME_DIR/bin/opensearch-plugin" install --batch "file://$zip"
      chown -R wazuh-indexer:wazuh-indexer "$HOME_DIR/plugins"
    else
      echo "[indexer-init] ERROR: S3_ENDPOINT set but no repository-s3 zip in /archive/" >&2
      echo "               run './wazuh-deploy.sh fetch' (connected) or import an airgap bundle" >&2
      exit 1
    fi
  fi

  if ! "$HOME_DIR/jdk/bin/keytool" -list -alias siem-root-ca -cacerts -storepass changeit >/dev/null 2>&1; then
    echo "[indexer-init] importing root CA into the JVM truststore"
    "$HOME_DIR/jdk/bin/keytool" -importcert -noprompt -alias siem-root-ca \
      -cacerts -storepass changeit -file "$CONF/certs/root-ca.pem"
  fi

  if [ -n "${S3_ACCESS_KEY:-}" ]; then
    [ -f "$CONF/opensearch.keystore" ] || "$HOME_DIR/bin/opensearch-keystore" create >/dev/null
    printf '%s' "$S3_ACCESS_KEY" | "$HOME_DIR/bin/opensearch-keystore" add --stdin --force s3.client.default.access_key >/dev/null
    printf '%s' "$S3_SECRET_KEY" | "$HOME_DIR/bin/opensearch-keystore" add --stdin --force s3.client.default.secret_key >/dev/null
    chown wazuh-indexer:wazuh-indexer "$CONF/opensearch.keystore"
  fi
fi

chown wazuh-indexer:wazuh-indexer "$CONF/opensearch.yml"
exec /entrypoint.sh
