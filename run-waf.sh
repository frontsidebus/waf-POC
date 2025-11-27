#!/bin/bash

# Default Values
MONGO_USER="admin"
MONGO_PASS="securepassword123"
ADMIN_USER="admin"
ADMIN_PASS="admin"
API_TOKEN=""
FLASK_SECRET=$(openssl rand -hex 32)

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Help Function
show_help() {
    echo -e "${BLUE}OpenWebUI WAF - Deployment Wrapper${NC}"
    echo "Usage: ./run-waf.sh [options]"
    echo ""
    echo "Options:"
    echo "  --mongo-user <user>     Set MongoDB root username (default: admin)"
    echo "  --mongo-pass <pass>     Set MongoDB root password (default: securepassword123)"
    echo "  --admin-user <user>     Set WAF Dashboard username (default: admin)"
    echo "  --admin-pass <pass>     Set WAF Dashboard password (default: admin)"
    echo "  --api-token <token>     Set a static Bearer Token for REST API access"
    echo "  --oauth-id <id>         Google OAuth Client ID (optional)"
    echo "  --oauth-secret <sec>    Google OAuth Client Secret (optional)"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Example:"
    echo "  ./run-waf.sh --mongo-pass MySecretDBPass --api-token MyApiToken123"
}

# Argument Parsing
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --mongo-user) MONGO_USER="$2"; shift ;;
        --mongo-pass) MONGO_PASS="$2"; shift ;;
        --admin-user) ADMIN_USER="$2"; shift ;;
        --admin-pass) ADMIN_PASS="$2"; shift ;;
        --api-token) API_TOKEN="$2"; shift ;;
        --oauth-id) OAUTH_CLIENT_ID="$2"; shift ;;
        --oauth-secret) OAUTH_CLIENT_SECRET="$2"; shift ;;
        -h|--help) show_help; exit 0 ;;
        *) echo -e "${RED}Unknown parameter passed: $1${NC}"; show_help; exit 1 ;;
    esac
    shift
done

echo -e "${GREEN}[*] Configuring WAF Environment...${NC}"

# Create .env file for docker-compose
cat > .env <<EOF
MONGO_USER=${MONGO_USER}
MONGO_PASS=${MONGO_PASS}
ADMIN_USER=${ADMIN_USER}
ADMIN_PASS=${ADMIN_PASS}
API_TOKEN=${API_TOKEN}
FLASK_SECRET=${FLASK_SECRET}
OAUTH_CLIENT_ID=${OAUTH_CLIENT_ID}
OAUTH_CLIENT_SECRET=${OAUTH_CLIENT_SECRET}
EOF

echo -e "${GREEN}[*] Environment variables set in .env${NC}"
echo -e "${BLUE}    MongoDB User:${NC} $MONGO_USER"
echo -e "${BLUE}    WAF Admin User:${NC} $ADMIN_USER"
if [ ! -z "$API_TOKEN" ]; then
    echo -e "${BLUE}    API Token:${NC} Set"
fi

echo -e "${GREEN}[*] Building and Starting Containers...${NC}"
docker-compose up -d --build

echo ""
echo -e "${GREEN}SUCCESS! The WAF stack is running.${NC}"
echo -e " -> WAF Proxy:      http://localhost:8080"
echo -e " -> WAF Dashboard:  http://localhost:5000/waf-admin"
echo -e " -> MongoDB:        localhost:27017 (User: $MONGO_USER)"
echo ""
echo "To stop the stack, run: docker-compose down"