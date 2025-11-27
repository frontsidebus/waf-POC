import requests
import re
import logging
import os
from flask import Flask, request, jsonify, Response

# CONFIG
LOGGER_API = os.environ.get("LOGGER_URL", "http://localhost:5000")
TARGET_URL = os.environ.get("TARGET_URL", "http://localhost:3000")
PORT = 8081

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

def get_rules():
    try:
        res = requests.get(f"{LOGGER_API}/api/rules?scope=output", timeout=2)
        return res.json()
    except:
        return []

def get_redaction_message():
    try:
        res = requests.get(f"{LOGGER_API}/api/settings/block_message", timeout=1)
        return res.json().get('value', "Redacted")
    except:
        return "Security Alert: Response Redacted."

def log_event(rule, snippet):
    try:
        requests.post(f"{LOGGER_API}/api/log", json={
            "service": "output_filter",
            "ip": "internal",
            "rule": rule,
            "snippet": snippet,
            "action": "REDACTED"
        }, timeout=1)
    except:
        pass

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def output_proxy(path):
    target = f"{TARGET_URL}/{path}" if path else TARGET_URL
    
    # 1. Forward Request to LLM
    try:
        headers = {k: v for k, v in request.headers.items() if k != 'Host'}
        
        # Buffer response (stream=False) to inspect it
        resp = requests.request(
            method=request.method,
            url=target,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=False 
        )

        # 2. Inspect Output
        # Only check text content
        ctype = resp.headers.get('Content-Type', '')
        if 'text' in ctype or 'json' in ctype:
            content = resp.text
            rules = get_rules()
            
            for rule in rules:
                if re.search(rule['pattern'], content, re.IGNORECASE):
                    # HIT: Log and Redact
                    log_event(rule['name'], content)
                    
                    msg = get_redaction_message()
                    if 'application/json' in ctype:
                        return jsonify({"content": msg, "error": "Sensitive Data Redacted"}), 200
                    return msg, 200

        # Return original if safe
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        resp_headers = [(k, v) for k, v in resp.raw.headers.items() if k.lower() not in excluded_headers]
        
        return Response(resp.content, status=resp.status_code, headers=resp_headers)

    except Exception as e:
        return f"Output Filter Error: {str(e)}", 502

if __name__ == '__main__':
    print(f"[*] Output Filter running on port {PORT} -> Target: {TARGET_URL}")
    app.run(host='0.0.0.0', port=PORT)