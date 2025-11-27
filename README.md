# Microservices WAF for OpenWebUI

A distributed Web Application Firewall architecture that protects OpenWebUI by separating concerns into three distinct microservices. This setup acts as a secure gateway, filtering both incoming prompts and outgoing LLM responses.

## Architecture

### 1. Input Filter (Port 8080)

* **Role:** Public-facing Gatekeeper.
* **Function:** Blocks malicious inputs (SQL Injection, Jailbreaks, XSS) before they reach the backend.
* **Flow:** Forwards valid traffic to the Output Filter.

### 2. Output Filter (Internal Port 8081)

* **Role:** Exit Guard.
* **Function:** Buffers LLM responses to scan for and redact PII (SSNs, Credit Cards, API Keys).
* **Flow:** Forwards sanitized traffic to the User.

### 3. Policy & Logger (Port 5000)

* **Role:** Control Plane.
* **Function:** Central database for Rules and Logs. Provides an API for filters to fetch rules and an Admin UI for management.

## Prerequisites

* **Docker:** Ensure Docker Engine is installed and running.
* **Docker Compose:** Required to orchestrate the multi-container setup.

## Getting Started

### 1. Project Setup

Ensure your project directory contains the following files (generated from the provided code):

* `docker-compose.yml`
* `Dockerfile`
* `logger_service.py`
* `input_filter.py`
* `output_filter.py`

### 2. Configure Credentials

Open `docker-compose.yml` and locate the `waf-logger` service. Update the environment variables to set your desired admin credentials:

```yaml
  waf-logger:
    # ...
    environment:
      - FLASK_APP=logger_service.py
      - ADMIN_USER=my_secure_username  # <--- Change this
      - ADMIN_PASS=my_secure_password  # <--- Change this
```

### 3. Run the Stack

This command builds the WAF images and pulls the latest OpenWebUI image.

```bash
docker-compose up -d --build
```

### 4. Access Points

* **Main Application:** http://localhost:8080
  * Access OpenWebUI through this URL. Traffic is automatically filtered.
* **Admin Dashboard:** http://localhost:5000/waf-admin
  * Login using the credentials configured in step 2.
  * Use this dashboard to view security logs and manage blocking rules.

## Configuration & Customization

### Environment Variables

You can customize the services by modifying `docker-compose.yml`:

| Service | Variable | Description | Default |
|---------|----------|-------------|---------|
| waf-logger | `ADMIN_USER` | Username for the Admin Dashboard. | `admin` |
| waf-logger | `ADMIN_PASS` | Password for the Admin Dashboard. | `admin` |
| waf-input | `LOGGER_URL` | Internal URL to reach the Policy Service. | `http://waf-logger:5000` |
| waf-output | `TARGET_URL` | Internal URL of the OpenWebUI container. | `http://open-webui:8080` |

### OpenWebUI Integration

This architecture runs OpenWebUI as a container named `open-webui` within the same Docker network.

* The `waf-output` service forwards traffic to `http://open-webui:8080`.
* **Security Note:** OpenWebUI is not exposed to the host machine directly in the default configuration. This forces all traffic to pass through the WAF (Port 8080).

## Development Notes

* **Decoupled:** The filters do not share a database with the logger; they communicate via HTTP API.
* **Scalability:** You can scale the `waf-input` container independently of the `waf-output` container in a swarm/Kubernetes setup.
* **Data Persistence:**
  * WAF Rules and Logs are stored in `./waf_data` (mapped to the `waf-logger` container).
  * OpenWebUI data is stored in the `open-webui-data` volume.