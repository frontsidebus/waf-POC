# Microservices WAF for OpenWebUI

A distributed Web Application Firewall architecture that protects OpenWebUI.

## Architecture

1. **Input Filter (Port 8080):** Public-facing Gatekeeper. Blocks malicious inputs (SQLi, Jailbreaks).
2. **Output Filter (Internal Port 8081):** Exit Guard. Redacts PII from LLM responses.
3. **Policy & Logger (Port 5000):** Control Plane backed by MongoDB. Supports REST API and OAuth 2.0.

## Prerequisites

* Docker & Docker Compose
* Bash (for the wrapper script)

## Quick Start (Recommended)

The easiest way to run the stack is using the included wrapper script. It handles configuration and startup automatically.

### 1. Make the script executable

```bash
chmod +x run-waf.sh
```

### 2. Run with default settings

```bash
./run-waf.sh
```

### 3. Run with custom credentials (Secure Production Setup)

```bash
./run-waf.sh \
  --mongo-pass "SuperSecretDBPass" \
  --admin-user "security_admin" \
  --admin-pass "ComplexPassword123" \
  --api-token "MyStaticAuthToken"
```

## Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--mongo-user` | MongoDB root username | `admin` |
| `--mongo-pass` | MongoDB root password | `securepassword123` |
| `--admin-user` | WAF Dashboard username | `admin` |
| `--admin-pass` | WAF Dashboard password | `admin` |
| `--api-token` | Static Bearer Token for REST API access | (Empty) |
| `--oauth-id` | Google OAuth Client ID | (Empty) |
| `--oauth-secret` | Google OAuth Client Secret | (Empty) |

## Access Points

* **Application:** `http://localhost:8080` (Traffic flows WAF -> OpenWebUI)
* **Admin Dashboard:** `http://localhost:5000/waf-admin`
* **REST API:** `http://localhost:5000/api/v1/rules`

## Authentication Configuration

### Google OAuth 2.0

To enable "Login with Google":

1. Create Credentials in Google Cloud Console.
2. Set Redirect URI: `http://localhost:5000/auth/callback`
3. Run the stack:

```bash
./run-waf.sh --oauth-id "YOUR_CLIENT_ID" --oauth-secret "YOUR_CLIENT_SECRET"
```

## REST API Access

You can manage rules programmatically using the API Token set via the wrapper script.

**Example Request:**

```bash
curl -X POST http://localhost:5000/api/v1/rules \
  -H "Authorization: Bearer MyStaticAuthToken" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block Project X",
    "pattern": "Project X",
    "scope": "both"
  }'
```

## Manual Deployment (Docker Compose)

If you prefer not to use the wrapper script, you can run standard Docker commands. You must create a `.env` file first.

### 1. Create `.env`

```bash
MONGO_USER=admin
MONGO_PASS=password
ADMIN_USER=admin
ADMIN_PASS=admin
FLASK_SECRET=randomstring
```

### 2. Run Compose

```bash
docker-compose up -d --build
```