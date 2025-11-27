# Microservices WAF for OpenWebUI

A distributed Web Application Firewall architecture that protects OpenWebUI.

## Architecture

1. **Input Filter (Port 8080):** Public-facing Gatekeeper. Blocks malicious inputs (SQLi, Jailbreaks).
2. **Output Filter (Internal Port 8081):** Exit Guard. Redacts PII from LLM responses.
3. **Policy & Logger (Port 5000):** Control Plane backed by MongoDB. Supports REST API and OAuth 2.0.

## Prerequisites

* Docker & Docker Compose
* Bash (for the wrapper script)

## Quick Start

The included wrapper script enforces security guardrails. You must provide an API Token, and it will warn you if you use default passwords.

### 1. Make the script executable

```bash
chmod +x run-waf.sh
```

### 2. Run with auto-generated token (Minimum Requirement)

```bash
# Generates a random token to pass the guardrail
./run-waf.sh --api-token "$(openssl rand -hex 16)"
```

**Note:** The script will ask for confirmation if you use default passwords.

### 3. Secure Production Setup (Recommended)

```bash
./run-waf.sh \
  --mongo-pass "SuperSecretDBPass" \
  --admin-user "security_admin" \
  --admin-pass "ComplexPassword123" \
  --api-token "MyStaticAuthToken"
```

## Guardrails & Error Handling

The wrapper script includes strict checks:

* **Empty Values:** The script will exit with an error if `API_TOKEN`, `MONGO_PASS`, or `ADMIN_PASS` are explicitly empty or missing (in the case of API_TOKEN).
* **Insecure Defaults:** If you rely on the built-in default passwords (`admin` / `securepassword123`), the script will pause and ask for interactive confirmation before proceeding.

## Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--api-token` | Required. Static Bearer Token for REST API. | (None) |
| `--mongo-user` | MongoDB root username | `admin` |
| `--mongo-pass` | MongoDB root password | `securepassword123` |
| `--admin-user` | WAF Dashboard username | `admin` |
| `--admin-pass` | WAF Dashboard password | `admin` |
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
./run-waf.sh \
  --api-token "mytoken" \
  --oauth-id "YOUR_CLIENT_ID" \
  --oauth-secret "YOUR_CLIENT_SECRET"
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