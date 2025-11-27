import sqlite3
import logging
import os
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string, redirect

# CONFIG
DB_PATH = os.path.join("waf_data", "waf_rules.db")
PORT = 5000
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PolicyService")

# --- DATABASE ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Enable Write-Ahead Logging for concurrency
    c.execute('PRAGMA journal_mode=WAL;')
    
    c.execute('''CREATE TABLE IF NOT EXISTS rules 
                 (id INTEGER PRIMARY KEY, name TEXT, pattern TEXT, type TEXT, is_active INTEGER DEFAULT 1, scope TEXT DEFAULT 'input')''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY, timestamp TEXT, service TEXT, ip TEXT, rule_matched TEXT, snippet TEXT, action TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('block_message', 'Security Alert: Response redacted.')")

    # Seed Defaults
    defaults = [
        ("OWASP-SQLi", r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*\b(FROM|INTO|VALUES|TABLE)\b)|(' OR '1'='1)", "regex", 1, "input"),
        ("OWASP-XSS", r"<script.*?>.*?</script>", "regex", 1, "input"),
        ("PII-SSN", r"\b\d{3}-\d{2}-\d{4}\b", "regex", 1, "output"),
        ("PII-CreditCard", r"\b(?:\d[ -]*?){13,16}\b", "regex", 1, "output")
    ]
    c.execute("SELECT count(*) FROM rules")
    if c.fetchone()[0] == 0:
        c.executemany("INSERT INTO rules (name, pattern, type, is_active, scope) VALUES (?, ?, ?, ?, ?)", defaults)
        conn.commit()
    conn.close()

def query_db(query, args=(), one=False):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.execute(query, args)
    rv = cur.fetchall()
    conn.commit() # Needed for INSERT/UPDATE
    conn.close()
    return (rv[0] if rv else None) if one else rv

# --- API ENDPOINTS (For Filters) ---

@app.route('/api/rules', methods=['GET'])
def get_rules():
    scope = request.args.get('scope', 'input')
    rules = query_db("SELECT * FROM rules WHERE is_active=1 AND (scope=? OR scope='both')", (scope,))
    return jsonify([dict(r) for r in rules])

@app.route('/api/log', methods=['POST'])
def receive_log():
    data = request.json
    query_db("INSERT INTO logs (timestamp, service, ip, rule_matched, snippet, action) VALUES (?, ?, ?, ?, ?, ?)",
             (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), data.get('service'), data.get('ip'), 
              data.get('rule'), data.get('snippet', '')[:200], data.get('action')))
    return jsonify({"status": "logged"}), 201

@app.route('/api/settings/<key>', methods=['GET'])
def get_setting_api(key):
    res = query_db("SELECT value FROM settings WHERE key=?", (key,), one=True)
    return jsonify({"value": res['value'] if res else ""})

# --- ADMIN UI ---
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
        <div class="container mx-auto flex justify-between">
            <h1 class="font-bold text-xl"><i class="fa-solid fa-server mr-2"></i>WAF Control Plane</h1>
            <div>
                <a href="/waf-admin" class="mr-4 hover:text-blue-300">Rules</a>
                <a href="/waf-admin/logs" class="hover:text-blue-300">Logs</a>
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
def admin_dash():
    rules = query_db("SELECT * FROM rules ORDER BY id DESC")
    return render_template_string(HTML_TEMPLATE.replace('{% block content %}{% endblock %}', DASHBOARD), rules=rules)

@app.route('/waf-admin/logs')
def admin_logs():
    logs = query_db("SELECT * FROM logs ORDER BY id DESC LIMIT 50")
    return render_template_string(HTML_TEMPLATE.replace('{% block content %}{% endblock %}', LOGS_UI), logs=logs)

@app.route('/waf-admin/add', methods=['POST'])
def add_rule():
    query_db("INSERT INTO rules (name, pattern, type, scope) VALUES (?, ?, 'regex', ?)", 
             (request.form['name'], request.form['pattern'], request.form['scope']))
    return redirect('/waf-admin')

@app.route('/waf-admin/delete/<int:rid>')
def delete_rule(rid):
    query_db("DELETE FROM rules WHERE id=?", (rid,))
    return redirect('/waf-admin')

@app.route('/waf-admin/clear')
def clear_logs():
    query_db("DELETE FROM logs")
    return redirect('/waf-admin/logs')

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=PORT)