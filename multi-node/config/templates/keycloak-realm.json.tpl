{
  "realm": "siem",
  "enabled": true,
  "sslRequired": "external",
  "registrationAllowed": false,
  "bruteForceProtected": true,
  "groups": [
    {
      "name": "siem-admins"
    },
    {
      "name": "siem-analysts"
    },
    {
      "name": "siem-readonly"
    }
  ],
  "users": [
    {
      "username": "ssoadmin",
      "enabled": true,
      "emailVerified": true,
      "firstName": "SIEM",
      "lastName": "Admin",
      "email": "ssoadmin@siem.local",
      "groups": [
        "siem-admins"
      ],
      "credentials": [
        {
          "type": "password",
          "value": "REPLACE_WITH_SSO_ADMIN_PASSWORD",
          "temporary": false
        }
      ]
    },
    {
      "username": "analyst1",
      "enabled": true,
      "emailVerified": true,
      "firstName": "SIEM",
      "lastName": "Analyst",
      "email": "analyst1@siem.local",
      "groups": [
        "siem-analysts"
      ],
      "credentials": [
        {
          "type": "password",
          "value": "REPLACE_WITH_SSO_ANALYST_PASSWORD",
          "temporary": false
        }
      ]
    }
  ],
  "clients": [
    {
      "clientId": "wazuh-dashboard",
      "name": "Wazuh Dashboard",
      "enabled": true,
      "protocol": "openid-connect",
      "publicClient": false,
      "secret": "REPLACE_WITH_OIDC_CLIENT_SECRET",
      "redirectUris": [
        "https://siem.local.domain/*"
      ],
      "webOrigins": [
        "https://siem.local.domain"
      ],
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": true,
      "protocolMappers": [
        {
          "name": "groups",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-group-membership-mapper",
          "consentRequired": false,
          "config": {
            "claim.name": "groups",
            "full.path": "false",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true"
          }
        }
      ]
    },
    {
      "clientId": "misp",
      "name": "MISP",
      "enabled": true,
      "protocol": "openid-connect",
      "publicClient": false,
      "secret": "REPLACE_WITH_MISP_OIDC_SECRET",
      "redirectUris": [
        "https://misp.siem.local.domain:8081/*"
      ],
      "webOrigins": [
        "https://misp.siem.local.domain:8081"
      ],
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": true,
      "protocolMappers": [
        {
          "name": "groups",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-group-membership-mapper",
          "consentRequired": false,
          "config": {
            "claim.name": "groups",
            "full.path": "false",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true"
          }
        }
      ]
    },
    {
      "clientId": "iris",
      "name": "DFIR-IRIS",
      "enabled": true,
      "protocol": "openid-connect",
      "publicClient": false,
      "secret": "REPLACE_WITH_IRIS_OIDC_SECRET",
      "redirectUris": [
        "https://iris.siem.local.domain:8082/*"
      ],
      "webOrigins": [
        "https://iris.siem.local.domain:8082"
      ],
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": true,
      "protocolMappers": [
        {
          "name": "groups",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-group-membership-mapper",
          "consentRequired": false,
          "config": {
            "claim.name": "groups",
            "full.path": "false",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true"
          }
        }
      ]
    }
  ]
}