import sys
import logging
import re
import json
import sqlite3
import requests
from urllib.parse import urljoin
from datetime import datetime
from flask import Flask, request, Response, render_template_string, redirect, url_for, jsonify

# ==========================================
# CONFIGURATION
# ==========================================
# The URL where OpenWebUI is running
TARGET_URL = "http://localhost:3000" 
# The port this WAF will listen on
WAF_PORT = '$WAF_PORT'
# Admin username/password (Simple protection)
ADMIN_USER = "$ADMIN_USER"
ADMIN_PASS = "$ADMIN_PASS"

# ==========================================
# LOGGING & DATABASE SETUP
# ==========================================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("WAF")

def init_db():
    conn = sqlite3.connect('waf_rules.db')
    c = conn.cursor()
    
    # Table for Rules
    c.execute('''CREATE TABLE IF NOT EXISTS rules 
                 (id INTEGER PRIMARY KEY, 
                  name TEXT, 
                  pattern TEXT, 
                  type TEXT, 
                  is_active INTEGER DEFAULT 1)''')
    
    # Table for Logs
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY, 
                  timestamp TEXT, 
                  ip TEXT, 
                  rule_matched TEXT, 
                  input_snippet TEXT, 
                  action TEXT)''')
    
    # Seed OWASP Top 10 - Simplistic Signatures (Demonstration purposes)
    # 1. Injection (SQLi)
    # 2. XSS
    # 3. Command Injection
    initial_rules = [
        ("OWASP-SQLi-Basic", r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*\b(FROM|INTO|VALUES|TABLE)\b)|(' OR '1'='1)", "regex", 1),
        ("OWASP-XSS-Script", r"<script.*?>.*?</script>", "regex", 1),
        ("OWASP-XSS-Events", r"on(load|error|click|mouseover)\s*=", "regex", 1),
        ("OWASP-Cmd-Injection", r"(;|\||&&)\s*(cat|nc|netstat|whoami|curl|wget)\s+", "regex", 1),
        ("Prompt-Injection-System", r"(ignore previous instructions|you are now|system override)", "regex", 0), # Disabled by default
    ]
    
    c.execute("SELECT count(*) FROM rules")
    if c.fetchone()[0] == 0:
        c.executemany("INSERT INTO rules (name, pattern, type, is_active) VALUES (?, ?, ?, ?)", initial_rules)
        conn.commit()
        logger.info("Database initialized with default OWASP rules.")
        
    conn.close()

# ==========================================
# FLASK APP
# ==========================================
app = Flask(__name__)

# --- ADMIN UI TEMPLATES ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenWebUI WAF Admin</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen font-sans">
    <nav class="bg-slate-800 text-white p-4 shadow-lg">
        <div class="container mx-auto flex justify-between items-center">
            <h1 class="text-xl font-bold"><i class="fa-solid fa-shield-halved mr-2"></i>OpenWebUI WAF Defense</h1>
            <div class="space-x-4">
                <a href="/waf-admin" class="hover:text-blue-300 transition">Dashboard</a>
                <a href="/waf-admin/logs" class="hover:text-blue-300 transition">Security Logs</a>
                <a href="/" target="_blank" class="bg-blue-600 px-3 py-1 rounded text-sm hover:bg-blue-500">Go to App</a>
            </div>
        </div>
    </nav>

    <div class="container mx-auto mt-8 p-4">
        {% block content %}{% endblock %}
    </div>

    <script>
        function toggleRule(id, currentState) {
            fetch(`/waf-admin/toggle/${id}`, {method: 'POST'})
                .then(() => window.location.reload());
        }
    </script>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
{% extends "base" %}
{% block content %}
<div class="grid grid-cols-1 md:grid-cols-3 gap-6">
    <!-- Stats -->
    <div class="bg-white p-6 rounded-lg shadow-md border-l-4 border-blue-500">
        <h3 class="text-gray-500 text-sm uppercase font-semibold">Active Rules</h3>
        <p class="text-3xl font-bold text-gray-800">{{ active_count }}</p>
    </div>
    <div class="bg-white p-6 rounded-lg shadow-md border-l-4 border-red-500">
        <h3 class="text-gray-500 text-sm uppercase font-semibold">Threats Blocked</h3>
        <p class="text-3xl font-bold text-gray-800">{{ block_count }}</p>
    </div>
    <div class="bg-white p-6 rounded-lg shadow-md border-l-4 border-green-500">
        <h3 class="text-gray-500 text-sm uppercase font-semibold">System Status</h3>
        <p class="text-3xl font-bold text-green-600">Active</p>
    </div>
</div>

<!-- Add Rule Form -->
<div class="mt-8 bg-white p-6 rounded-lg shadow-md">
    <h2 class="text-lg font-bold mb-4 text-gray-800">Add Custom Filter</h2>
    <form action="/waf-admin/add" method="POST" class="flex flex-col md:flex-row gap-4">
        <input type="text" name="name" placeholder="Rule Name (e.g. No PII)" class="border p-2 rounded flex-1" required>
        <input type="text" name="pattern" placeholder="Regex Pattern (e.g. \d{3}-\d{2}-\d{4})" class="border p-2 rounded flex-[2]" required>
        <select name="type" class="border p-2 rounded">
            <option value="regex">Regex</option>
            <option value="string">String Match</option>
        </select>
        <button type="submit" class="bg-indigo-600 text-white px-6 py-2 rounded hover:bg-indigo-700 transition">Add Rule</button>
    </form>
</div>

<!-- Rules List -->
<div class="mt-8 bg-white rounded-lg shadow-md overflow-hidden">
    <div class="px-6 py-4 border-b bg-gray-50">
        <h2 class="font-bold text-gray-700">Filtering Rules</h2>
    </div>
    <table class="w-full text-left border-collapse">
        <thead>
            <tr class="text-sm text-gray-600 bg-gray-50">
                <th class="p-4 border-b">Status</th>
                <th class="p-4 border-b">Rule Name</th>
                <th class="p-4 border-b">Pattern</th>
                <th class="p-4 border-b">Type</th>
                <th class="p-4 border-b">Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for rule in rules %}
            <tr class="hover:bg-gray-50">
                <td class="p-4 border-b">
                    <button onclick="toggleRule({{ rule[0] }})" class="w-10 h-6 rounded-full p-1 transition-colors {{ 'bg-green-500' if rule[4] else 'bg-gray-300' }}">
                        <div class="w-4 h-4 bg-white rounded-full shadow-md transform transition-transform {{ 'translate-x-4' if rule[4] else '' }}"></div>
                    </button>
                </td>
                <td class="p-4 border-b font-medium text-gray-800">{{ rule[1] }}</td>
                <td class="p-4 border-b text-mono text-sm text-red-600 font-mono bg-gray-50 rounded px-2 py-1 inline-block mt-2">{{ rule[2] }}</td>
                <td class="p-4 border-b text-sm text-gray-500">{{ rule[3] }}</td>
                <td class="p-4 border-b">
                    <a href="/waf-admin/delete/{{ rule[0] }}" class="text-red-500 hover:text-red-700"><i class="fa-solid fa-trash"></i></a>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% endblock %}
"""

LOGS_TEMPLATE = """
{% extends "base" %}
{% block content %}
<div class="bg-white rounded-lg shadow-md overflow-hidden">
    <div class="px-6 py-4 border-b bg-gray-50 flex justify-between items-center">
        <h2 class="font-bold text-gray-700">Security Event Logs</h2>
        <a href="/waf-admin/clear-logs" class="text-sm text-red-600 hover:underline">Clear Logs</a>
    </div>
    <div class="overflow-x-auto">
        <table class="w-full text-left">
            <thead class="bg-gray-100 text-gray-600 text-sm uppercase">
                <tr>
                    <th class="p-4">Time</th>
                    <th class="p-4">IP Address</th>
                    <th class="p-4">Rule Matched</th>
                    <th class="p-4">Triggered Content</th>
                    <th class="p-4">Action</th>
                </tr>
            </thead>
            <tbody class="divide-y">
                {% for log in logs %}
                <tr class="hover:bg-gray-50 transition">
                    <td class="p-4 text-sm whitespace-nowrap">{{ log[1] }}</td>
                    <td class="p-4 text-sm">{{ log[2] }}</td>
                    <td class="p-4 text-sm font-semibold text-red-600">{{ log[3] }}</td>
                    <td class="p-4 text-xs font-mono text-gray-500 max-w-xs truncate" title="{{ log[4] }}">{{ log[4] }}</td>
                    <td class="p-4"><span class="bg-red-100 text-red-800 text-xs px-2 py-1 rounded-full uppercase font-bold">{{ log[5] }}</span></td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="5" class="p-8 text-center text-gray-500">No threats detected yet.</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
{% endblock %}
"""

# ==========================================
# WAF LOGIC
# ==========================================
def get_rules():
    conn = sqlite3.connect('waf_rules.db')
    c = conn.cursor()
    c.execute("SELECT * FROM rules WHERE is_active = 1")
    rules = c.fetchall()
    conn.close()
    return rules

def log_incident(ip, rule_name, content_snippet):
    conn = sqlite3.connect('waf_rules.db')
    c = conn.cursor()
    c.execute("INSERT INTO logs (timestamp, ip, rule_matched, input_snippet, action) VALUES (?, ?, ?, ?, ?)",
              (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, rule_name, content_snippet[:200], "BLOCKED"))
    conn.commit()
    conn.close()
    logger.warning(f"BLOCKED request from {ip} matching {rule_name}")

def check_payload(content, ip):
    """Checks string content against all active rules."""
    rules = get_rules()
    if not isinstance(content, str):
        content = json.dumps(content)
        
    for rule in rules:
        # rule: (id, name, pattern, type, is_active)
        r_name = rule[1]
        r_pattern = rule[2]
        r_type = rule[3]
        
        if r_type == 'regex':
            if re.search(r_pattern, content, re.IGNORECASE):
                log_incident(ip, r_name, content)
                return True, r_name
        elif r_type == 'string':
            if r_pattern.lower() in content.lower():
                log_incident(ip, r_name, content)
                return True, r_name
                
    return False, None

# ==========================================
# ROUTES
# ==========================================

# --- Admin Routes ---
@app.route('/waf-admin')
def admin_dashboard():
    conn = sqlite3.connect('waf_rules.db')
    c = conn.cursor()
    c.execute("SELECT * FROM rules ORDER BY id DESC")
    rules = c.fetchall()
    c.execute("SELECT count(*) FROM rules WHERE is_active=1")
    active_count = c.fetchone()[0]
    c.execute("SELECT count(*) FROM logs")
    block_count = c.fetchone()[0]
    conn.close()
    
    # Combine base template with dashboard
    full_html = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', DASHBOARD_TEMPLATE)
    return render_template_string(full_html, rules=rules, active_count=active_count, block_count=block_count)

@app.route('/waf-admin/logs')
def admin_logs():
    conn = sqlite3.connect('waf_rules.db')
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 100")
    logs = c.fetchall()
    conn.close()
    
    full_html = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', LOGS_TEMPLATE)
    return render_template_string(full_html, logs=logs)

@app.route('/waf-admin/add', methods=['POST'])
def add_rule():
    name = request.form.get('name')
    pattern = request.form.get('pattern')
    r_type = request.form.get('type')
    
    if name and pattern:
        conn = sqlite3.connect('waf_rules.db')
        c = conn.cursor()
        c.execute("INSERT INTO rules (name, pattern, type, is_active) VALUES (?, ?, ?, 1)", (name, pattern, r_type))
        conn.commit()
        conn.close()
        
    return redirect('/waf-admin')

@app.route('/waf-admin/toggle/<int:rule_id>', methods=['POST'])
def toggle_rule(rule_id):
    conn = sqlite3.connect('waf_rules.db')
    c = conn.cursor()
    c.execute("UPDATE rules SET is_active = NOT is_active WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route('/waf-admin/delete/<int:rule_id>')
def delete_rule(rule_id):
    conn = sqlite3.connect('waf_rules.db')
    c = conn.cursor()
    c.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()
    return redirect('/waf-admin')

@app.route('/waf-admin/clear-logs')
def clear_logs():
    conn = sqlite3.connect('waf_rules.db')
    c = conn.cursor()
    c.execute("DELETE FROM logs")
    conn.commit()
    conn.close()
    return redirect('/waf-admin/logs')

# --- Proxy Logic ---
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def proxy(path):
    # 1. Block access to internal WAF db or logic from outside
    if path.startswith("waf-admin"):
        return redirect('/waf-admin')

    target_url = urljoin(TARGET_URL, path)
    client_ip = request.remote_addr

    # 2. Inspect Request Body (Inputs)
    # OpenWebUI usually sends prompt in 'messages' or 'prompt' fields within JSON
    if request.method in ['POST', 'PUT']:
        if request.is_json:
            try:
                data = request.get_json()
                # Recursive search in JSON for strings to check
                blocked, rule = check_payload(json.dumps(data), client_ip)
                if blocked:
                    return jsonify({
                        "error": True, 
                        "message": f"Security Alert: Request blocked by WAF rule '{rule}'."
                    }), 403
            except Exception as e:
                logger.error(f"Error parsing JSON: {e}")
        elif request.form:
             # Check form data
             blocked, rule = check_payload(str(request.form.to_dict()), client_ip)
             if blocked:
                return f"Security Alert: Request blocked by WAF rule '{rule}'.", 403

    # 3. Forward Request to OpenWebUI
    try:
        # Exclude headers that might confuse the backend or are hop-by-hop
        headers = {key: value for (key, value) in request.headers if key != 'Host'}
        
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=True # Important for LLM streaming responses
        )

        # 4. Handle Response
        # Note: We stream the response back. Filtering *streamed* output (token by token) 
        # is complex and adds latency. For a basic WAF, we primarily filter INPUT.
        # If output filtering is strictly required, we would need to buffer the stream 
        # (losing the typing effect) or use a complex generator.
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items()
                   if name.lower() not in excluded_headers]

        return Response(resp.iter_content(chunk_size=1024),
                        status=resp.status_code,
                        headers=headers)

    except requests.exceptions.ConnectionError:
        return "Error: Could not connect to OpenWebUI. Is it running on port 3000?", 502

if __name__ == '__main__':
    init_db()
    print(f"[*] WAF Active on http://0.0.0.0:{WAF_PORT}")
    print(f"[*] Proxying to {TARGET_URL}")
    print(f"[*] Admin UI at http://0.0.0.0:{WAF_PORT}/waf-admin")
    app.run(host='0.0.0.0', port=WAF_PORT)
