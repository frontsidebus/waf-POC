# Microservices WAF for OpenWebUI

A distributed Web Application Firewall architecture that protects OpenWebUI.

## Architecture

1. **Input Filter (Port 8080):** Public-facing Gatekeeper. Blocks malicious inputs (SQLi, Jailbreaks).
2. **Output Filter (Internal Port 8081):** Exit Guard. Redacts PII from LLM responses.
3. **Policy & Logger (Port 5000):** Control Plane with REST API and OAuth 2.0.

## Prerequisites

* Docker & Docker Compose

## Getting Started

### 1. Run the Stack

```bash
docker-compose up -d --build
```

### 2. Access Points

* **Application:** `http://localhost:8080`
* **Admin Dashboard:** `http://localhost:5000/waf-admin` (Default: admin/admin)

## Authentication Configuration

The Policy Service supports Google OAuth 2.0.

### 1. Create Credentials

Go to the Google Cloud Console, create an OAuth 2.0 Client ID.

### 2. Set Redirect URI

`http://localhost:5000/auth/callback`

### 3. Update `docker-compose.yml`

```yaml
waf-logger:
  environment:
    - OAUTH_CLIENT_ID=your-google-client-id
    - OAUTH_CLIENT_SECRET=your-google-client-secret
```

### 4. Restart

```bash
docker-compose up -d
```

* The login page will now show "Login with Google".

## REST API Documentation

The Policy Service exposes a JSON API.

**Base URL:** `http://localhost:5000/api/v1`

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/rules` | Fetch all active rules. Query param `?scope=input` supported. | No (Internal) |
| `POST` | `/rules` | Create a new rule. JSON: `{ "name": "...", "pattern": "...", "scope": "input" }` | Yes |
| `DELETE` | `/rules/<id>` | Delete a rule by ID. | Yes |

**Note:** Write operations (`POST`, `DELETE`) require an active session authentication cookie.