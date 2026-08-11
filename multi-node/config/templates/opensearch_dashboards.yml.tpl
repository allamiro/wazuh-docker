server.host: 0.0.0.0
server.port: 5601
# All dashboard queries go through the dedicated coordinating nodes.
opensearch.hosts: ["https://coord1.indexer:9200", "https://coord2.indexer:9200"]
# Certificates carry proper DNS SANs, so full hostname verification is enabled.
opensearch.ssl.verificationMode: full
opensearch.requestHeadersWhitelist: ["securitytenant","Authorization"]
# Multi-tenancy = the OpenSearch equivalent of Kibana "spaces": each tenant is
# a separate workspace for dashboards/visualizations/saved searches. Tenants
# and who may use them are declared in config/sso-groups.conf.
opensearch_security.multitenancy.enabled: true
opensearch_security.multitenancy.tenants.enable_global: true
opensearch_security.multitenancy.tenants.enable_private: false
opensearch_security.multitenancy.tenants.preferred: ["Global"]
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: true
server.ssl.key: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
server.ssl.certificate: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem"
opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wz-home
# Session expiration settings (15 minutes)
opensearch_security.cookie.ttl: 900000
opensearch_security.session.ttl: 900000
opensearch_security.session.keepalive: true
# Cookies only over TLS
opensearch_security.cookie.secure: true
# Offline maps (optional "maps" profile): self-hosted tiles instead of the
# unreachable maps.opensearch.org. Served via the nginx TLS vhost; without
# the maps profile this is simply unreachable (maps stay blank, as before).
map.opensearchManifestServiceUrl: "https://siem.local.domain:8080/manifest.json"
