#!/bin/bash

# Hardcoded Insecure Defaults (for comparison)
DEFAULT_MONGO_PASS="securepassword123"
DEFAULT_ADMIN_PASS="admin"

# 1. Initialize Variables (Priority: Env Vars -> Defaults)
MONGO_USER="${MONGO_USER:-admin}"
MONGO_PASS="${MONGO_PASS:-$DEFAULT_MONGO_PASS}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-$DEFAULT_ADMIN_PASS}"
API_TOKEN="${API_TOKEN:-}" # No default, must be provided
FLASK_SECRET="${FLASK_SECRET:-$(openssl rand -hex 32)}"
OAUTH_CLIENT_ID="${OAUTH_CLIENT_ID:-}"
OAUTH_CLIENT_SECRET="${OAUTH_CLIENT_SECRET:-}"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

show_help() {
    echo -e "${BLUE}OpenWebUI WAF - Deployment Wrapper${NC}"
    echo "Usage: ./run-waf.sh [options]"
    echo ""
    echo "Required:"
    echo "  --api-token <token>     Set Bearer Token for REST API (cannot be empty)"
    echo ""
    echo "Options:"
    echo "  --mongo-user <user>     Set MongoDB root username (default: admin)"
    echo "  --mongo-pass <pass>     Set MongoDB root password (default: $DEFAULT_MONGO_PASS)"
    echo "  --admin-user <user>     Set WAF Dashboard username (default: admin)"
    echo "  --admin-pass <pass>     Set WAF Dashboard password (default: $DEFAULT_ADMIN_PASS)"
    echo "  --oauth-id <id>         Google OAuth Client ID"
    echo "  --oauth-secret <sec>    Google OAuth Client Secret"
    echo "  -h, --help              Show this help message"
}

# 2. Parse Arguments (Flags override Env Vars)
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
        *) echo -e "${RED}Unknown parameter: $1${NC}"; show_help; exit 1 ;;
    esac
    shift
done

# --- GUARDRAILS ---

echo -e "${BLUE}[*] Running Security Checks...${NC}"

# Check 1: Empty Values
ERRORS=()
if [[ -z "$MONGO_PASS" ]]; then ERRORS+=("MongoDB Password cannot be empty."); fi
if [[ -z "$ADMIN_PASS" ]]; then ERRORS+=("Admin Password cannot be empty."); fi
if [[ -z "$FLASK_SECRET" ]]; then ERRORS+=("Flask Secret cannot be empty."); fi
if [[ -z "$API_TOKEN" ]]; then ERRORS+=("API Token cannot be empty. Please provide one via --api-token or API_TOKEN env var."); fi

if [ ${#ERRORS[@]} -ne 0 ]; then
    echo -e "${RED}Error: Security Guardrails Failed${NC}"
    for err in "${ERRORS[@]}"; do
        echo -e " - $err"
    done
    echo ""
    echo "Example: ./run-waf.sh --api-token \"my-secret-token\""
    exit 1
fi

# Check 2: Insecure Defaults
USING_DEFAULTS=false

if [[ "$MONGO_PASS" == "$DEFAULT_MONGO_PASS" ]]; then
    echo -e "${RED}WARNING: You are using the default insecure MongoDB password.${NC}"
    USING_DEFAULTS=true
fi
if [[ "$ADMIN_PASS" == "$DEFAULT_ADMIN_PASS" ]]; then
    echo -e "${RED}WARNING: You are using the default insecure Admin password.${NC}"
    USING_DEFAULTS=true
fi

if [ "$USING_DEFAULTS" = true ]; then
    echo -e "${BLUE}It is strongly recommended to set custom passwords using --mongo-pass and --admin-pass.${NC}"
    # Interactive prompt (skip if in CI/non-interactive mode)
    if [ -t 0 ]; then
        read -p "Are you sure you want to proceed with insecure defaults? (y/N) " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Aborting."
            exit 1
        fi
    else
        echo "Non-interactive mode detected. Proceeding with defaults (Not Recommended)."
    fi
fi

# --- EXECUTION ---

echo -e "${GREEN}[*] Configuring Environment...${NC}"

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

echo -e "${GREEN}[*] Starting Stack...${NC}"
docker-compose up -d --build

echo ""
echo -e "${GREEN}SUCCESS! The WAF stack is running.${NC}"
echo -e " -> Dashboard: http://localhost:5000/waf-admin"
echo -e " -> Proxy:     http://localhost:8080"