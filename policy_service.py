import logging
import os
import secrets
import requests
from urllib.parse import urlencode
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, redirect, session, url_for
from pymongo import MongoClient
from bson.objectid import ObjectId

# CONFIG
PORT = 5000
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")
# Added API Token support
API_TOKEN = os.environ.get("API_TOKEN", "") 
FLASK_SECRET = os.environ.get("FLASK_SECRET", secrets.token_hex(32))
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")

# OAUTH CONFIG
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")
OAUTH_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
OAUTH_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
OAUTH_REDIRECT_URI = "http://localhost:5000/auth/callback"

app = Flask(__name__)
app.secret_key = FLASK_SECRET
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PolicyService")

# --- DATABASE (MongoDB) ---
def get_db():
    client = MongoClient(MONGO_URI)
    return client.waf_db

def init_db():
    try:
        db = get_db()
        # Seed Default Rules
        if db.rules.count_documents({}) == 0:
            defaults = [
                {"name": "OWASP-SQLi", "pattern": r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*\b(FROM|INTO|VALUES|TABLE)\b)|(' OR '1'='1)", "type": "regex", "is_active": True, "scope": "input"},
                {"name": "OWASP-XSS", "pattern": r"<script.*?>.*?</script>", "type": "regex", "is_active": True, "scope": "input"},
                {"name": "PII-SSN", "pattern": r"\b\d{3}-\d{2}-\d{4}\b", "type": "regex", "is_active": True, "scope": "output"},
                {"name": "PII-CreditCard", "pattern": r"\b(?:\d[ -]*?){13,16}\b", "type": "regex", "is_active": True, "scope": "output"}
            ]
            db.rules.insert_many(defaults)
            logger.info("Seeded default rules into MongoDB")
        
        # Seed Settings
        if not db.settings.find_one({"_id": "block_message"}):
            db.settings.insert_one({"_id": "block_message", "value": "Security Alert: Response redacted."})
    except Exception as e:
        logger.error(f"Database Init Failed: {e}")

def serialize_doc(doc):
    if not doc: return None
    doc['id'] = str(doc['_id'])
    del doc['_id']
    return doc

# --- AUTH ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Check for Static API Token (for scripts/curl)
        auth_header = request.headers.get('Authorization')
        if API_TOKEN and auth_header:
            # support "Bearer <token>"
            token = auth_header.split(" ")[1] if " " in auth_header else auth_header
            if token == API_TOKEN:
                return f(*args, **kwargs)

        # 2. Check for Web Session (for browser)
        if 'user' not in session:
            # If requesting JSON (API), return 401 instead of redirect
            if request.path.startswith('/api/'):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for('login_page'))
            
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login')
def login_page():
    oauth_enabled = bool(OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET)
    return render_template_string(LOGIN_TEMPLATE, oauth_enabled=oauth_enabled)

@app.route('/auth/basic', methods=['POST'])
def auth_basic():
    if request.form.get('username') == ADMIN_USER and request.form.get('password') == ADMIN_PASS:
        session['user'] = ADMIN_USER
        return redirect('/waf-admin')
    return render_template_string(LOGIN_TEMPLATE, error="Invalid Credentials", oauth_enabled=bool(OAUTH_CLIENT_ID))

@app.route('/auth/login')
def oauth_redirect():
    if not OAUTH_CLIENT_ID: return "OAuth not configured", 500
    params = {"client_id": OAUTH_CLIENT_ID, "redirect_uri": OAUTH_REDIRECT_URI, "response_type": "code", "scope": "openid email", "access_type": "offline", "prompt": "select_account"}
    return redirect(f"{OAUTH_AUTH_URL}?{urlencode(params)}")

@app.route('/auth/callback')
def auth_callback():
    code = request.args.get('code')
    if not code: return "No code provided", 400
    try:
        token_res = requests.post(OAUTH_TOKEN_URL, data={"code": code, "client_id": OAUTH_CLIENT_ID, "client_secret": OAUTH_CLIENT_SECRET, "redirect_uri": OAUTH_REDIRECT_URI, "grant_type": "authorization_code"})
        token_res.raise_for_status()
        user_info = requests.get(OAUTH_USERINFO_URL, headers={'Authorization': f"Bearer {token_res.json()['access_token']}"}).json()
        session['user'] = user_info.get('email')
        return redirect('/waf-admin')
    except Exception as e:
        return f"Auth Failed: {e}", 400

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

# --- REST API (v1) ---

@app.route('/api/rules', methods=['GET'])
@app.route('/api/v1/rules', methods=['GET'])
def get_rules():
    db = get_db()
    scope = request.args.get('scope', 'both')
    query = {"is_active": True}
    if scope != 'both':
        query = {"is_active": True, "$or": [{"scope": scope}, {"scope": "both"}]}

    rules = list(db.rules.find(query))
    return jsonify([serialize_doc(r) for r in rules])

@app.route('/api/v1/rules', methods=['POST'])
@admin_required
def create_rule():
    data = request.json
    if not data or 'name' not in data or 'pattern' not in data:
        return jsonify({"error": "Missing name or pattern"}), 400
    
    db = get_db()
    result = db.rules.insert_one({
        "name": data['name'], 
        "pattern": data['pattern'], 
        "type": "regex", 
        "is_active": True,
        "scope": data.get('scope', 'input')
    })
    return jsonify({"status": "created", "id": str(result.inserted_id)}), 201

@app.route('/api/v1/rules/<rid>', methods=['DELETE'])
@admin_required
def delete_rule_api(rid):
    db = get_db()
    try:
        db.rules.delete_one({"_id": ObjectId(rid)})
        return jsonify({"status": "deleted"})
    except:
        return jsonify({"error": "Invalid ID"}), 400

@app.route('/api/log', methods=['POST'])
def receive_log():
    data = request.json
    db = get_db()
    db.logs.insert_one({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "service": data.get('service'),
        "ip": data.get('ip'),
        "rule_matched": data.get('rule'),
        "snippet": data.get('snippet', '')[:200],
        "action": data.get('action')
    })
    return jsonify({"status": "logged"}), 201

@app.route('/api/settings/<key>', methods=['GET'])
def get_setting_api(key):
    db = get_db()
    res = db.settings.find_one({"_id": key})
    return jsonify({"value": res['value'] if res else ""})

# --- ADMIN UI ROUTES ---
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head><title>WAF Login</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-900 min-h-screen flex items-center justify-center">
    <div class="bg-white p-8 rounded-lg shadow-xl w-96">
        <h1 class="text-2xl font-bold mb-6 text-center">WAF Policy Control</h1>
        {% if oauth_enabled %}
        <a href="/auth/login" class="block w-full text-center bg-blue-600 text-white font-bold py-2 px-4 rounded hover:bg-blue-700 mb-4">Login with Google</a>
        <div class="text-center text-gray-500 mb-4">- OR -</div>
        {% endif %}
        <form action="/auth/basic" method="POST">
            <input type="text" name="username" placeholder="Username" class="border w-full p-2 mb-4 rounded">
            <input type="password" name="password" placeholder="Password" class="border w-full p-2 mb-4 rounded">
            {% if error %}<p class="text-red-500 text-xs mb-4">{{ error }}</p>{% endif %}
            <button class="bg-gray-800 text-white w-full py-2 rounded">Login</button>
        </form>
    </div>
</body>
</html>
"""

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>WAF Control Plane</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 font-sans">
    <nav class="bg-gray-900 text-white p-4">
        <div class="container mx-auto flex justify-between items-center">
            <h1 class="font-bold text-xl"><i class="fa-solid fa-server mr-2"></i>WAF Control Plane</h1>
            <div class="flex items-center gap-4">
                <a href="/waf-admin" class="hover:text-blue-300">Rules</a>
                <a href="/waf-admin/logs" class="hover:text-blue-300">Logs</a>
                <span class="text-gray-500 border-l pl-4">{{ user }}</span>
                <a href="/logout" class="text-red-400 text-sm">Logout</a>
            </div>
        </div>
    </nav>
    <div class="container mx-auto mt-8 p-4">
        {% block content %}{% endblock %}
    </div>
</body>
</html>
"""

DASHBOARD = """
{% extends "base" %}
{% block content %}
<div class="bg-white p-6 rounded shadow mb-6">
    <h2 class="font-bold text-lg mb-4">Add Rule</h2>
    <form action="/waf-admin/add" method="POST" class="flex gap-2">
        <input type="text" name="name" placeholder="Name" class="border p-2 rounded" required>
        <input type="text" name="pattern" placeholder="Regex Pattern" class="border p-2 rounded flex-grow" required>
        <select name="scope" class="border p-2 rounded">
            <option value="input">Input Service</option>
            <option value="output">Output Service</option>
        </select>
        <button class="bg-blue-600 text-white px-4 py-2 rounded">Add</button>
    </form>
</div>
<table class="w-full bg-white shadow rounded overflow-hidden">
    <thead class="bg-gray-50 border-b">
        <tr><th class="p-3 text-left">Name</th><th class="p-3 text-left">Scope</th><th class="p-3 text-left">Pattern</th><th class="p-3">Action</th></tr>
    </thead>
    <tbody>
        {% for rule in rules %}
        <tr class="border-b hover:bg-gray-50">
            <td class="p-3 font-bold">{{ rule['name'] }}</td>
            <td class="p-3"><span class="px-2 py-1 text-xs font-bold rounded {{ 'bg-blue-100 text-blue-800' if rule['scope']=='input' else 'bg-purple-100 text-purple-800' }}">{{ rule['scope']|upper }}</span></td>
            <td class="p-3 font-mono text-red-600 text-sm">{{ rule['pattern'] }}</td>
            <td class="p-3 text-center">
                <a href="/waf-admin/delete/{{ rule['id'] }}" class="text-red-500"><i class="fa-solid fa-trash"></i></a>
            </td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% endblock %}
"""

LOGS_UI = """
{% extends "base" %}
{% block content %}
<div class="flex justify-between mb-4">
    <h2 class="text-xl font-bold">Event Logs</h2>
    <a href="/waf-admin/clear" class="text-red-600">Clear Logs</a>
</div>
<table class="w-full bg-white shadow rounded">
    <thead class="bg-gray-50 border-b">
        <tr><th class="p-3 text-left">Time</th><th class="p-3 text-left">Service</th><th class="p-3 text-left">Rule</th><th class="p-3 text-left">Snippet</th></tr>
    </thead>
    <tbody>
        {% for log in logs %}
        <tr class="border-b">
            <td class="p-3 text-sm text-gray-500">{{ log['timestamp'] }}</td>
            <td class="p-3 font-bold text-xs uppercase {{ 'text-blue-600' if log['service']=='input_filter' else 'text-purple-600' }}">{{ log['service'] }}</td>
            <td class="p-3 font-bold text-red-600">{{ log['rule_matched'] }}</td>
            <td class="p-3 font-mono text-xs text-gray-500">{{ log['snippet'] }}</td>
        </tr>
        {% else %}
        <tr><td colspan="4" class="p-6 text-center text-gray-400">No events found.</td></tr>
        {% endfor %}
    </tbody>
</table>
{% endblock %}
"""

@app.route('/waf-admin')
@admin_required
def admin_dash():
    db = get_db()
    rules = list(db.rules.find().sort("_id", -1))
    return render_template_string(HTML_TEMPLATE.replace('{% block content %}{% endblock %}', DASHBOARD), rules=[serialize_doc(r) for r in rules], user=session.get('user'))

@app.route('/waf-admin/logs')
@admin_required
def admin_logs():
    db = get_db()
    logs = list(db.logs.find().sort("_id", -1).limit(50))
    return render_template_string(HTML_TEMPLATE.replace('{% block content %}{% endblock %}', LOGS_UI), logs=[serialize_doc(l) for l in logs], user=session.get('user'))

@app.route('/waf-admin/add', methods=['POST'])
@admin_required
def add_rule():
    db = get_db()
    db.rules.insert_one({
        "name": request.form['name'],
        "pattern": request.form['pattern'],
        "type": "regex",
        "is_active": True,
        "scope": request.form['scope']
    })
    return redirect('/waf-admin')

@app.route('/waf-admin/delete/<rid>')
@admin_required
def delete_rule(rid):
    db = get_db()
    try:
        db.rules.delete_one({"_id": ObjectId(rid)})
    except:
        pass
    return redirect('/waf-admin')

@app.route('/waf-admin/clear')
@admin_required
def clear_logs():
    db = get_db()
    db.logs.delete_many({})
    return redirect('/waf-admin/logs')

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=PORT)