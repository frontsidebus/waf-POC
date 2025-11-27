import requests
import re
import json
import logging
import os
from flask import Flask, request, jsonify, Response

# CONFIG
LOGGER_API = os.environ.get("LOGGER_URL", "http://localhost:5000")
NEXT_HOP = os.environ.get("NEXT_HOP_URL", "http://localhost:8081")
PORT = 8080

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

def get_rules():
    try:
        # Fetch fresh rules from Policy Service
        res = requests.get(f"{LOGGER_API}/api/rules?scope=input", timeout=2)
        return res.json()
    except Exception as e:
        logging.error(f"Failed to fetch rules: {e}")
        return []

def log_event(ip, rule, snippet):
    try:
        payload = {
            "service": "input_filter",
            "ip": ip,
            "rule": rule,
            "snippet": snippet,
            "action": "BLOCKED"
        }
        requests.post(f"{LOGGER_API}/api/log", json=payload, timeout=1)
    except:
        pass

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def input_proxy(path):
    # 1. Inspect Input
    if request.method in ['POST', 'PUT']:
        content = ""
        if request.is_json:
            content = json.dumps(request.get_json())
        elif request.form:
            content = str(request.form.to_dict())
        
        rules = get_rules()
        for rule in rules:
            if re.search(rule['pattern'], content, re.IGNORECASE):
                log_event(request.remote_addr, rule['name'], content)
                return jsonify({"error": True, "message": f"Blocked by Input Filter: {rule['name']}"}), 403

    # 2. Forward to Output Filter
    try:
        target = f"{NEXT_HOP}/{path}" if path else NEXT_HOP
        
        # Strip hop headers
        excluded_headers = ['Host', 'Content-Length']
        headers = {k: v for k, v in request.headers.items() if k not in excluded_headers}

        resp = requests.request(
            method=request.method,
            url=target,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=True # Stream response from next hop
        )
        
        # Forward response back to client (Output filter handles the rest)
        excluded_resp_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        resp_headers = [(k, v) for k, v in resp.raw.headers.items() if k.lower() not in excluded_resp_headers]

        return Response(resp.iter_content(chunk_size=1024), status=resp.status_code, headers=resp_headers)

    except Exception as e:
        return f"Input Filter Error: {str(e)}", 502

if __name__ == '__main__':
    print(f"[*] Input Filter running on port {PORT} -> Next Hop: {NEXT_HOP}")
    app.run(host='0.0.0.0', port=PORT)