import sys
import os
import logging
import re
import json
import sqlite3
import requests
import secrets
from urllib.parse import urljoin, urlencode
from datetime import datetime
from functools import wraps
from flask import Flask, request, Response, render_template_string, redirect, url_for, jsonify, session

# ==========================================
# CONFIGURATION
# ==========================================
TARGET_URL = os.environ.get("TARGET_URL", "http://localhost:3000")
WAF_PORT = int(os.environ.get("WAF_PORT", 8080))

# --- AUTHENTICATION CONFIG ---
# 1. OAUTH (Google Example by default, change URLs for others)
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "")         # e.g., "123...apps.googleusercontent.com"
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "") # e.g., "GOCSPX-..."
OAUTH_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
OAUTH_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
OAUTH_REDIRECT_URI = f"http://localhost:{WAF_PORT}/auth/callback"

# 2. FALLBACK BASIC AUTH (Used if OAuth is missing)
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")

# ==========================================
# LOGGING & DATABASE SETUP
# ==========================================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("WAF")

def init_db():
    conn = sqlite3.connect('waf_rules.db')
    c = conn.cursor()
    
    try:
        c.execute("ALTER TABLE rules ADD COLUMN scope TEXT DEFAULT 'input'")
    except sqlite3.OperationalError:
        pass 

    c.execute('''CREATE TABLE IF NOT EXISTS rules 
                 (id INTEGER PRIMARY KEY, 
                  name TEXT, 
                  pattern TEXT, 
                  type TEXT, 
                  is_active INTEGER DEFAULT 1,
                  scope TEXT DEFAULT 'input')''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY, 
                  timestamp TEXT, 
                  ip TEXT, 
                  rule_matched TEXT, 
                  input_snippet TEXT, 
                  action TEXT,
                  direction TEXT)''')
                  
    c.execute('''CREATE TABLE IF NOT EXISTS settings
                 (key TEXT PRIMARY KEY, value TEXT)''')

    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('block_message', 'Security Alert: The response contained sensitive data and was redacted by the WAF.')")

    initial_rules = [
        ("OWASP-SQLi", r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*\b(FROM|INTO|VALUES|TABLE)\b)|(' OR '1'='1)", "regex", 1, "input"),
        ("OWASP-XSS", r"<script.*?>.*?</script>", "regex", 1, "input"),
        ("System-Override", r"(ignore previous instructions|you are now|system override)", "regex", 0, "input"),
        ("PII-SSN", r"\b\d{3}-\d{2}-\d{4}\b", "regex", 1, "output"),
        ("PII-CreditCard", r"\b(?:\d[ -]*?){13,16}\b", "regex", 1, "output"),
        ("Sensitive-Key", r"(?i)(api_key|secret|password)\s*[:=]\s*['\"]?[a-zA-Z0-9]{8,}['\"]?", "regex", 1, "output")
    ]
    
    c.execute("SELECT count(*) FROM rules")
    if c.fetchone()[0] == 0:
        c.executemany("INSERT INTO rules (name, pattern, type, is_active, scope) VALUES (?, ?, ?, ?, ?)", initial_rules)
        conn.commit()
        
    conn.commit()
    conn.close()

# ==========================================
# HELPERS
# ==========================================
def get_setting(key):
    with sqlite3.connect('waf_rules.db') as conn:
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key=?", (key,))
        res = c.fetchone()
        return res[0] if res else ""

def update_setting(key, value):
    with sqlite3.connect('waf_rules.db') as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))

def log_incident(ip, rule_name, snippet, action, direction):
    with sqlite3.connect('waf_rules.db') as conn:
        conn.execute("INSERT INTO logs (timestamp, ip, rule_matched, input_snippet, action, direction) VALUES (?, ?, ?, ?, ?, ?)",
                  (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, rule_name, snippet[:200], action, direction))
    logger.warning(f"{direction} BLOCKED: {rule_name} | IP: {ip}")

def check_content(content, scope):
    with sqlite3.connect('waf_rules.db') as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM rules WHERE is_active = 1 AND (scope = ? OR scope = 'both')", (scope,))
        rules = c.fetchall()

    content_str = content if isinstance(content, str) else json.dumps(content)

    for rule in rules:
        r_name, r_pattern, r_type = rule[1], rule[2], rule[3]
        if r_type == 'regex':
            if re.search(r_pattern, content_str, re.IGNORECASE):
                return True, r_name
        elif r_type == 'string':
            if r_pattern.lower() in content_str.lower():
                return True, r_name
    return False, None

# ==========================================
# FLASK APP & AUTH
# ==========================================
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

# AUTH DECORATOR
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# --- TEMPLATES ---
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WAF Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-gray-900 min-h-screen flex items-center justify-center">
    <div class="bg-white p-8 rounded-lg shadow-xl w-96">
        <div class="text-center mb-8">
            <h1 class="text-2xl font-bold text-gray-800"><i class="fa-solid fa-shield-cat mr-2 text-indigo-600"></i>WAF Admin</h1>
            <p class="text-gray-500 text-sm">Secure Access Gateway</p>
        </div>

        {% if oauth_enabled %}
        <a href="/auth/login" class="block w-full bg-white border border-gray-300 text-gray-700 font-bold py-3 px-4 rounded hover:bg-gray-50 flex items-center justify-center transition mb-4">
            <img src="https://www.svgrepo.com/show/475656/google-color.svg" class="w-6 h-6 mr-3" alt="Google">
            Sign in with Google
        </a>
        <div class="relative mb-4">
            <div class="absolute inset-0 flex items-center"><div class="w-full border-t border-gray-300"></div></div>
            <div class="relative flex justify-center text-sm"><span class="px-2 bg-white text-gray-500">Or use credentials</span></div>
        </div>
        {% endif %}

        <form action="/auth/basic" method="POST">
            <div class="mb-4">
                <label class="block text-gray-700 text-sm font-bold mb-2">Username</label>
                <input type="text" name="username" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-500">
            </div>
            <div class="mb-6">
                <label class="block text-gray-700 text-sm font-bold mb-2">Password</label>
                <input type="password" name="password" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-500">
            </div>
            {% if error %}
            <p class="text-red-500 text-xs italic mb-4">{{ error }}</p>
            {% endif %}
            <button class="bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-2 px-4 rounded w-full focus:outline-none focus:shadow-outline" type="submit">
                Login
            </button>
        </form>
    </div>
</body>
</html>
"""

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Admin</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen font-sans">
    <nav class="bg-slate-900 text-white p-4 shadow-lg">
        <div class="container mx-auto flex justify-between items-center">
            <h1 class="text-xl font-bold"><i class="fa-solid fa-shield-cat mr-2"></i>WAF Dashboard</h1>
            <div class="flex items-center space-x-6">
                <a href="/waf-admin" class="hover:text-blue-300">Rules</a>
                <a href="/waf-admin/logs" class="hover:text-blue-300">Logs</a>
                <a href="/waf-admin/settings" class="hover:text-blue-300">Settings</a>
                <span class="text-gray-400 text-sm border-l pl-4 border-gray-600">{{ user }}</span>
                <a href="/logout" class="text-red-400 hover:text-white text-sm"><i class="fa-solid fa-sign-out-alt"></i></a>
            </div>
        </div>
    </nav>
    <div class="container mx-auto mt-8 p-4">
        {% block content %}{% endblock %}
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
{% extends "base" %}
{% block content %}
<div class="bg-white p-6 rounded-lg shadow-md mb-8">
    <h2 class="text-lg font-bold mb-4 text-gray-800">Add New Filter</h2>
    <form action="/waf-admin/add" method="POST" class="grid grid-cols-1 md:grid-cols-5 gap-4">
        <input type="text" name="name" placeholder="Rule Name" class="border p-2 rounded" required>
        <input type="text" name="pattern" placeholder="Pattern (Regex/String)" class="border p-2 rounded md:col-span-2" required>
        <select name="type" class="border p-2 rounded">
            <option value="regex">Regex</option>
            <option value="string">String Match</option>
        </select>
        <select name="scope" class="border p-2 rounded">
            <option value="input">Input (Block Request)</option>
            <option value="output">Output (Sanitize Response)</option>
            <option value="both">Both</option>
        </select>
        <button type="submit" class="bg-indigo-600 text-white px-6 py-2 rounded hover:bg-indigo-700 md:col-span-5">Add Rule</button>
    </form>
</div>

<div class="bg-white rounded-lg shadow-md overflow-hidden">
    <table class="w-full text-left border-collapse">
        <thead class="bg-gray-50 text-gray-600 uppercase text-sm">
            <tr>
                <th class="p-4">Active</th>
                <th class="p-4">Name</th>
                <th class="p-4">Scope</th>
                <th class="p-4">Pattern</th>
                <th class="p-4">Action</th>
            </tr>
        </thead>
        <tbody>
            {% for rule in rules %}
            <tr class="hover:bg-gray-50 border-b">
                <td class="p-4">
                    <form action="/waf-admin/toggle/{{ rule[0] }}" method="POST">
                        <button type="submit" class="text-xl {{ 'text-green-500' if rule[4] else 'text-gray-300' }}">
                            <i class="fa-solid fa-toggle-{{ 'on' if rule[4] else 'off' }}"></i>
                        </button>
                    </form>
                </td>
                <td class="p-4 font-bold text-gray-700">{{ rule[1] }}</td>
                <td class="p-4">
                    <span class="px-2 py-1 text-xs font-bold rounded 
                    {{ 'bg-blue-100 text-blue-800' if rule[5] == 'input' else 'bg-purple-100 text-purple-800' }}">
                        {{ rule[5]|upper }}
                    </span>
                </td>
                <td class="p-4 font-mono text-sm text-red-600 bg-gray-50 p-1 rounded">{{ rule[2] }}</td>
                <td class="p-4">
                    <a href="/waf-admin/delete/{{ rule[0] }}" class="text-red-400 hover:text-red-600"><i class="fa-solid fa-trash"></i></a>
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
<div class="flex justify-between items-center mb-4">
    <h2 class="text-2xl font-bold text-gray-800">Security Events</h2>
    <a href="/waf-admin/clear-logs" class="text-red-600 hover:underline">Clear History</a>
</div>
<div class="bg-white rounded-lg shadow-md overflow-hidden">
    <table class="w-full text-left">
        <thead class="bg-gray-100 text-gray-600 uppercase text-sm">
            <tr>
                <th class="p-4">Time</th>
                <th class="p-4">Direction</th>
                <th class="p-4">Rule</th>
                <th class="p-4">Snippet</th>
                <th class="p-4">Outcome</th>
            </tr>
        </thead>
        <tbody class="divide-y">
            {% for log in logs %}
            <tr class="hover:bg-gray-50">
                <td class="p-4 text-sm whitespace-nowrap">{{ log[1] }}</td>
                <td class="p-4"><span class="font-bold text-xs px-2 py-1 rounded {{ 'bg-yellow-100 text-yellow-800' if log[6] == 'OUTBOUND' else 'bg-blue-100 text-blue-800' }}">{{ log[6] }}</span></td>
                <td class="p-4 text-sm font-semibold text-red-600">{{ log[3] }}</td>
                <td class="p-4 text-xs font-mono text-gray-500 max-w-xs truncate">{{ log[4] }}</td>
                <td class="p-4 text-sm font-bold text-gray-700">{{ log[5] }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% endblock %}
"""

SETTINGS_TEMPLATE = """
{% extends "base" %}
{% block content %}
<div class="max-w-2xl mx-auto bg-white p-8 rounded-lg shadow-md">
    <h2 class="text-2xl font-bold mb-6 text-gray-800">Response Configuration</h2>
    <form action="/waf-admin/settings" method="POST">
        <label class="block text-sm font-bold mb-2 text-gray-700">Generic Response Template</label>
        <p class="text-sm text-gray-500 mb-2">This message will replace the actual response from OpenWebUI if sensitive data is detected.</p>
        <textarea name="block_message" rows="4" class="w-full border rounded p-3 mb-6 focus:ring focus:ring-blue-200">{{ block_message }}</textarea>
        
        <button type="submit" class="bg-blue-600 text-white px-6 py-2 rounded hover:bg-blue-700 font-bold w-full">Save Settings</button>
    </form>
</div>
{% endblock %}
"""

# ==========================================
# AUTH ROUTES
# ==========================================
@app.route('/login')
def login_page():
    # If OAuth creds are present, we enable the button in the template
    oauth_enabled = bool(OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET)
    return render_template_string(LOGIN_TEMPLATE, oauth_enabled=oauth_enabled)

@app.route('/auth/basic', methods=['POST'])
def auth_basic():
    user = request.form.get('username')
    pw = request.form.get('password')
    if user == ADMIN_USER and pw == ADMIN_PASS:
        session['user'] = user
        return redirect('/waf-admin')
    return render_template_string(LOGIN_TEMPLATE, error="Invalid Credentials", oauth_enabled=bool(OAUTH_CLIENT_ID))

@app.route('/auth/login')
def auth_oauth_redirect():
    if not OAUTH_CLIENT_ID:
        return "OAuth not configured", 500
    
    # Generate Google OAuth URL
    params = {
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account"
    }
    url = f"{OAUTH_AUTH_URL}?{urlencode(params)}"
    return redirect(url)

@app.route('/auth/callback')
def auth_callback():
    code = request.args.get('code')
    if not code:
        return "Error: No code provided", 400

    # 1. Exchange Code for Token
    token_data = {
        "code": code,
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "grant_type": "authorization_code"
    }
    try:
        res = requests.post(OAUTH_TOKEN_URL, data=token_data)
        res.raise_for_status()
        tokens = res.json()
        access_token = tokens.get('access_token')

        # 2. Get User Info
        headers = {'Authorization': f'Bearer {access_token}'}
        user_res = requests.get(OAUTH_USERINFO_URL, headers=headers)
        user_res.raise_for_status()
        user_info = user_res.json()
        
        # 3. Log User In
        session['user'] = user_info.get('email')
        return redirect('/waf-admin')
        
    except Exception as e:
        logger.error(f"OAuth Error: {e}")
        return f"Authentication Failed: {e}", 400

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

# ==========================================
# ADMIN ROUTES (Protected)
# ==========================================

@app.route('/waf-admin')
@admin_required
def admin_dash():
    conn = sqlite3.connect('waf_rules.db')
    c = conn.cursor()
    c.execute("SELECT * FROM rules ORDER BY id DESC")
    rules = c.fetchall()
    conn.close()
    full_html = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', DASHBOARD_TEMPLATE)
    return render_template_string(full_html, rules=rules, user=session['user'])

@app.route('/waf-admin/logs')
@admin_required
def admin_logs():
    conn = sqlite3.connect('waf_rules.db')
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 50")
    logs = c.fetchall()
    conn.close()
    full_html = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', LOGS_TEMPLATE)
    return render_template_string(full_html, logs=logs, user=session['user'])

@app.route('/waf-admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    if request.method == 'POST':
        update_setting('block_message', request.form.get('block_message'))
        return redirect('/waf-admin/settings')
    
    msg = get_setting('block_message')
    full_html = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', SETTINGS_TEMPLATE)
    return render_template_string(full_html, block_message=msg, user=session['user'])

@app.route('/waf-admin/add', methods=['POST'])
@admin_required
def add_rule():
    with sqlite3.connect('waf_rules.db') as conn:
        conn.execute("INSERT INTO rules (name, pattern, type, is_active, scope) VALUES (?, ?, ?, 1, ?)", 
                  (request.form['name'], request.form['pattern'], request.form['type'], request.form['scope']))
    return redirect('/waf-admin')

@app.route('/waf-admin/toggle/<int:rid>', methods=['POST'])
@admin_required
def toggle_rule(rid):
    with sqlite3.connect('waf_rules.db') as conn:
        conn.execute("UPDATE rules SET is_active = NOT is_active WHERE id = ?", (rid,))
    return redirect('/waf-admin')

@app.route('/waf-admin/delete/<int:rid>')
@admin_required
def delete_rule(rid):
    with sqlite3.connect('waf_rules.db') as conn:
        conn.execute("DELETE FROM rules WHERE id = ?", (rid,))
    return redirect('/waf-admin')

@app.route('/waf-admin/clear-logs')
@admin_required
def clear_logs():
    with sqlite3.connect('waf_rules.db') as conn:
        conn.execute("DELETE FROM logs")
    return redirect('/waf-admin/logs')

# ==========================================
# PROXY LOGIC (Public / App Traffic)
# ==========================================
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def proxy(path):
    # 1. Block access to internal WAF/Auth routes via proxy path
    if path.startswith("waf-admin") or path.startswith("auth") or path == "login":
        # Let Flask routing handle these, don't proxy them
        return redirect(url_for('login_page'))

    target_url = urljoin(TARGET_URL, path)
    client_ip = request.remote_addr

    # 2. INPUT FILTERING
    if request.method in ['POST', 'PUT']:
        data_str = ""
        if request.is_json:
            data_str = json.dumps(request.get_json())
        elif request.form:
            data_str = str(request.form.to_dict())
        
        blocked, rule = check_content(data_str, 'input')
        if blocked:
            log_incident(client_ip, rule, data_str, "BLOCKED_REQUEST", "INBOUND")
            return jsonify({"error": True, "message": f"WAF: Request blocked by rule '{rule}'"}), 403

    # 3. FORWARD REQUEST
    try:
        headers = {key: value for (key, value) in request.headers if key != 'Host'}
        
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=False 
        )

        # 4. OUTPUT FILTERING
        content_type = resp.headers.get('Content-Type', '')
        if 'text' in content_type or 'json' in content_type:
            try:
                response_text = resp.text
                blocked, rule = check_content(response_text, 'output')
                
                if blocked:
                    log_incident(client_ip, rule, response_text, "SANITIZED_RESPONSE", "OUTBOUND")
                    generic_msg = get_setting('block_message')
                    if 'application/json' in content_type:
                        return jsonify({"content": generic_msg, "error": "Sensitive Data Redacted"}), 200
                    else:
                        return generic_msg, 200
                        
            except Exception as e:
                logger.error(f"Error scanning response: {e}")

        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items()
                   if name.lower() not in excluded_headers]

        return Response(resp.content, status=resp.status_code, headers=headers)

    except requests.exceptions.ConnectionError:
        return "Error: Could not connect to OpenWebUI backend.", 502

if __name__ == '__main__':
    init_db()
    print(f"[*] WAF Active on http://0.0.0.0:{WAF_PORT}")
    if OAUTH_CLIENT_ID:
        print(f"[*] OAuth Enabled (Client ID: {OAUTH_CLIENT_ID[:5]}...)")
    else:
        print(f"[*] OAuth Disabled. Using Basic Auth (User: {ADMIN_USER})")
        
    app.run(host='0.0.0.0', port=WAF_PORT)