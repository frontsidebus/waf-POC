# OpenWebUI Web Application Firewall (WAF) - v2

A Python-based reverse proxy for OpenWebUI. This tool filters both Input (malicious prompts sent to the AI) and Output (sensitive data leaking from the AI), providing a secure layer between users and your LLM.

## Features

* **Dual-Direction Filtering:**
  * **Input (Inbound):** Blocks SQL Injection, XSS, and Jailbreak attempts before they reach the backend.
  * **Output (Outbound):** Scans LLM responses for PII (SSNs, Credit Cards) and sensitive keys.
* **Response Sanitization:** If sensitive data is detected in the response, the WAF intercepts it and replaces the entire message with a generic, safe template.
* **Admin Dashboard:** Manage rules, view security logs, and configure the generic response template.
* **Authentication:** Supports Google OAuth or Basic Auth (Username/Password).
* **Configurable Scope:** Rules can be set to scan Inputs, Outputs, or Both.

## Important Note on Streaming

To effectively scan output for patterns like Credit Card numbers (which might be split across data chunks), this WAF buffers the entire response from OpenWebUI before sending it to the user.

* **Trade-off:** You will lose the "typing" effect (streaming). The user will see a loading state until the full response is ready.
* **Benefit:** Prevents partial leakage of sensitive data.

## Docker Deployment (Recommended)

The easiest way to run the WAF is using Docker Compose. This ensures the WAF and OpenWebUI run in the same network, and you can lock down direct access to OpenWebUI.

### 1. Prepare Files

Ensure you have `waf_proxy.py`, `Dockerfile`, and `docker-compose.yml` in the same directory.

### 2. Start Services

```bash
docker-compose up -d --build
```

### 3. Access

* **App:** `http://localhost:8080` (Traffic flows WAF -> OpenWebUI)
* **Admin UI:** `http://localhost:8080/waf-admin`
* **Direct OpenWebUI:** Blocked (unless you uncomment ports in docker-compose).

## Manual Installation (Local Python)

### 1. Requirements

```bash
pip install flask requests
```

### 2. Run the WAF

```bash
# Set environment variables if needed
export TARGET_URL="http://localhost:3000"
python waf_proxy.py
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TARGET_URL` | URL of the OpenWebUI instance | `http://localhost:3000` |
| `WAF_PORT` | Port the WAF listens on | `8080` |
| `ADMIN_USER` | Basic Auth Username | `admin` |
| `ADMIN_PASS` | Basic Auth Password | `admin` |
| `OAUTH_CLIENT_ID` | Google OAuth Client ID | (Empty/Disabled) |
| `OAUTH_CLIENT_SECRET` | Google OAuth Secret | (Empty/Disabled) |

## Managing Rules

In the Admin Dashboard (`/waf-admin`), when adding a rule, select the **Scope**:

* **Input:** Blocks the request immediately. (Example: `DROP TABLE`)
* **Output:** Allows the request, but checks the AI's answer. If it matches, the answer is replaced.

## Default Rules

The WAF comes pre-seeded with:

* **Input:** OWASP SQLi, OWASP XSS, System Overrides.
* **Output:** SSN patterns, Credit Card patterns, API Key regex.