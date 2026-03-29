#!/usr/bin/env bash
# ============================================================================
# SOFTWARE: OSL: Sovereign Accounting Suite - Production Installer
# AUTHOR & COPYRIGHT: Cel-Tech-Serv Pty Ltd (ACN: 144 651 632)
# ============================================================================
# DESCRIPTION: 
# System-agnostic installer for the OSL Core. Requires Docker and Caddy.
# ============================================================================

set -e

GITHUB_USER="Celcius1" 
GITHUB_REPO="OpenSourceLedger"
INSTALL_ROOT="/opt/docker/OSL"

echo "----------------------------------------------------------------"
echo "  OSL: Sovereign Accounting Suite - Installation Wizard"
echo "  Property of: Cel-Tech-Serv Pty Ltd (ACN: 144 651 632)"
echo "----------------------------------------------------------------"

# 1. Critical Dependency Check (Including Caddy Enforce)
echo "[*] Verifying system dependencies..."

# Check for Caddy specifically with a hard stop
if ! command -v caddy &> /dev/null; then
    echo ""
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "[CRITICAL ERROR] Caddy Web Server not found."
    echo "OSL requires Caddy for secure reverse proxy and gateway handling."
    echo "Please install Caddy (https://caddyserver.com/) and try again."
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo ""
    exit 1
fi

# Check for other base requirements
for cmd in docker python3 curl; do
    if ! command -v $cmd &> /dev/null; then
        echo "[ERROR] Missing core dependency: $cmd. Please install it."
        exit 1
    fi
done

echo "[OK] All dependencies met. Proceeding with OSL Core setup."

# 2. Infrastructure Intelligence
read -p "Enter Base Domain [osl.net.au]: " OSL_DOMAIN
OSL_DOMAIN=${OSL_DOMAIN:-osl.net.au}

read -s -p "Set Master Security Password (DB/LDAP): " OSL_PASS
echo ""

# 3. Directory Architecture
echo "[*] Constructing filesystem at ${INSTALL_ROOT}..."
sudo mkdir -p ${INSTALL_ROOT}/{core/config,core/templates,src/web,ops/docker/auth/config,plugins/bin,include,sql}
sudo chown -R $USER:$USER ${INSTALL_ROOT}

# 4. Secret Seeding
JWT_SECRET=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
cat <<EOF > ${INSTALL_ROOT}/ops/docker/.env
OSL_BASE_DOMAIN=${OSL_DOMAIN}
OSL_DB_PASS=${OSL_PASS}
LLDAP_JWT_SECRET=${JWT_SECRET}
LLDAP_ADMIN_PASS=${OSL_PASS}
TZ=Australia/Adelaide
EOF

# 5. Minimalist Core Configuration (Identity-Blind)
cat <<EOF > ${INSTALL_ROOT}/core/config/osl_config.json
{
    "core": {
        "currency": "AUD",
        "debug_mode": true,
        "seal_grace_period_minutes": 15
    },
    "infrastructure": {
        "ldap_uri": "ldap://osl-identity:3890",
        "admin_group": "admins"
    },
    "plugins": {}
}
EOF

# 6. Plugin Scraper & Manifest Injection
echo "[*] Querying GitHub for Official OSL Plugins..."
PLUGIN_API="https://api.github.com/repos/${GITHUB_USER}/${GITHUB_REPO}/contents/src/plugins/official"
PLUGIN_LIST=$(curl -s "$PLUGIN_API" | grep '"name":' | cut -d'"' -f4)

if [ -n "$PLUGIN_LIST" ]; then
    echo "Available Official Plugins:"
    select PLUGIN in $PLUGIN_LIST "Skip"; do
        if [ "$PLUGIN" == "Skip" ] || [ -z "$PLUGIN" ]; then break; fi
        
        echo "[+] Fetching manifest for $PLUGIN..."
        MANIFEST_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/main/src/plugins/official/${PLUGIN}/osl-manifest.json"
        
        TEMP_MANIFEST=$(mktemp)
        curl -s -o "$TEMP_MANIFEST" "$MANIFEST_URL"

        # Python Injection Logic for the manifest
        python3 -c "
import json
try:
    with open('${INSTALL_ROOT}/core/config/osl_config.json', 'r') as f:
        config = json.load(f)
    with open('$TEMP_MANIFEST', 'r') as f:
        manifest = json.load(f)

    p_id = manifest['plugin_id']
    config['plugins'][p_id] = manifest['config_entry']

    with open('${INSTALL_ROOT}/core/config/osl_config.json', 'w') as f:
        json.dump(config, f, indent=4)
    print(f'[SUCCESS] Registered: {p_id}')
except Exception as e:
    print(f'[FAIL] Plugin Injection Error: {e}')
"
        rm "$TEMP_MANIFEST"
    done
fi

# 7. Production Docker-Compose Construction
echo "[*] Generating final docker-compose.yml..."
cat <<EOF > ${INSTALL_ROOT}/ops/docker/docker-compose.yml
services:
  osl-vault:
    image: postgres:15-alpine
    container_name: osl-vault
    restart: always
    environment:
      POSTGRES_USER: osl_admin
      POSTGRES_PASSWORD: \${OSL_DB_PASS}
      POSTGRES_DB: osl_main
    volumes:
      - osl_ledger_data:/var/lib/postgresql/data
      - ${INSTALL_ROOT}/sql/init_schema.sql:/docker-entrypoint-initdb.d/init.sql:ro
    networks:
      - osl_internal_net

  osl-identity:
    image: lldap/lldap:latest
    container_name: osl-identity
    restart: always
    environment:
      - LLDAP_LDAP_BASE_DN=dc=osl,dc=net,dc=au
      - LLDAP_LDAP_USER_PASS=\${LLDAP_ADMIN_PASS}
      - LLDAP_DATABASE_URL=postgres://osl_admin:\${OSL_DB_PASS}@osl-vault:5432/osl_identity
      - LLDAP_JWT_SECRET=\${LLDAP_JWT_SECRET}
      - LLDAP_KEY_SEED=osl_sovereign_identity_seed_2026
    networks:
      - osl_internal_net
    ports:
      - "17180:17170"

  osl-core:
    build:
      context: ../../
      dockerfile: ops/docker/Dockerfile.core
    container_name: osl-core
    restart: always
    volumes:
      - ${INSTALL_ROOT}/core/templates:/app/core/templates:ro
      - ${INSTALL_ROOT}/core/config:/app/core/config:rw
      - ${INSTALL_ROOT}/src/web:/app/www:ro
      - osl_plugin_binaries:/plugins/tax:ro
    environment:
      - OSL_PORT=8080
      - OSL_BASE_DOMAIN=\${OSL_BASE_DOMAIN}
      - OSL_DB_CONN=host=osl-vault user=osl_admin password=\${OSL_DB_PASS} dbname=osl_main
    networks:
      - osl_internal_net
      - default
    depends_on:
      - osl-vault

networks:
  osl_internal_net:
    name: osl_internal_net
    driver: bridge
    ipam:
      config:
        - subnet: 10.5.0.0/24
          gateway: 10.5.0.1

volumes:
  osl_ledger_data:
  osl_plugin_binaries:
EOF

echo "----------------------------------------------------------------"
echo "[FINISH] OSL Suite Core set up and registered to Cel-Tech-Serv."
echo "----------------------------------------------------------------"