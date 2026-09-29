import os
import time
import re
import requests
from urllib.parse import urlparse
from flask import Flask, jsonify, request, render_template_string, Response, redirect, url_for, session

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "aegis_super_secret_key_2026")

try:
    import psycopg2
except ImportError:
    psycopg2 = None

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db_connection():
    if not DATABASE_URL or not psycopg2:
        return None
    try:
        url = urlparse(DATABASE_URL)
        conn = psycopg2.connect(
            database=url.path[1:],
            user=url.username,
            password=url.password,
            host=url.hostname,
            port=url.port
        )
        return conn
    except Exception as e:
        print("Database connection error:", e)
        return None

def init_db():
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            # কাস্টমার টেবিল তৈরি
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS customers (
                    api_key TEXT PRIMARY KEY,
                    username TEXT,
                    email TEXT,
                    password TEXT,
                    client_name TEXT,
                    domain TEXT,
                    plan TEXT,
                    origin_ip TEXT
                )
            ''')
            
            # নিরাপত্তার জন্য যদি টেবিল আগে থেকেই থাকে কিন্তু কলামগুলো না থাকে, তবে তা যুক্ত করে নেবে
            cursor.execute("ALTER TABLE customers ADD COLUMN IF NOT EXISTS username TEXT;")
            cursor.execute("ALTER TABLE customers ADD COLUMN IF NOT EXISTS email TEXT;")
            cursor.execute("ALTER TABLE customers ADD COLUMN IF NOT EXISTS password TEXT;")
            
            # সিকিউরিটি লগ টেবিল
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_logs (
                    id SERIAL PRIMARY KEY,
                    timestamp TEXT,
                    ip TEXT,
                    path TEXT,
                    threat TEXT,
                    ai_patch TEXT,
                    client_domain TEXT
                )
            ''')
            conn.commit()
            
            # ডিফল্ট অ্যাডমিন বা টেস্ট কাস্টমার ইনসার্ট
            cursor.execute("SELECT COUNT(*) FROM customers")
            if cursor.fetchone()[0] == 0:
                cursor.execute(
                    "INSERT INTO customers (api_key, username, email, password, client_name, domain, plan, origin_ip) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    ("aegis_live_key_999", "ibr@him", "admin@firewall.com", "muhib5869@", "Acme Corp", "acme.com", "Enterprise", "http://192.168.1.50:8000")
                )
                conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            print("DB Init Error:", e)

try:
    init_db()
except Exception as e:
    print("Database initialization skipped:", e)

DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "YOUR_DISCORD_WEBHOOK_URL_HERE")

ADMIN_USER = "ibr@him"
ADMIN_EMAIL = "admin@firewall.com"
ADMIN_PASS = "muhib5869@"

BLOCKED_IPS = set()
blocked_until = {}
BLOCK_DURATION = 300

SQLI_PATTERNS = [
    (r"union\s+select", "SQL Injection (UNION based)"),
    (r"or\s+1\s*=\s*1", "SQL Injection (Boolean based tautology)"),
    (r"drop\s+table", "SQL Injection (Destructive DROP command)"),
    (r"(\%27)|(\')", "SQL Injection (Single quote anomaly)")
]

XSS_PATTERNS = [
    (r"<script[^>]*>[\s\S]*?</script>", "Cross-Site Scripting (Script tag injection)"),
    (r"javascript\s*:", "Cross-Site Scripting (JS pseudo-protocol)"),
    (r"onerror\s*=", "Cross-Site Scripting (Event handler injection)")
]

def generate_ai_patch_advice(threat_type):
    if "SQL Injection" in threat_type:
        return {
            "vulnerability": "SQL Injection",
            "risk_level": "CRITICAL",
            "developer_fix": "Use Parameterized Queries or ORM instead of raw string concatenation.",
            "secure_code_example": "cursor.execute('SELECT * FROM users WHERE username = %s', (username,))"
        }
    elif "Cross-Site Scripting" in threat_type:
        return {
            "vulnerability": "XSS (Cross-Site Scripting)",
            "risk_level": "HIGH",
            "developer_fix": "Always escape user inputs before rendering them in HTML templates.",
            "secure_code_example": "{{ user_input | escape }}"
        }
    return {
        "vulnerability": "General Web Attack",
        "risk_level": "MEDIUM",
        "developer_fix": "Ensure all input parameters are strictly validated."
    }

def analyze_payload(text):
    if not text:
        return None
    text_lower = str(text).lower()
    for pattern, desc in SQLI_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return desc
    for pattern, desc in XSS_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return desc
    return None

def send_discord_alert(threat_data):
    if "YOUR_DISCORD_WEBHOOK_URL" in DISCORD_WEBHOOK_URL:
        return
    payload = {
        "content": f"🚨 **Aegis Core WAF Alert!**\n"
                   f"• **Threat:** {threat_data['threat']}\n"
                   f"• **Attacker IP:** `{threat_data['ip']}`\n"
                   f"• **Target Path:** `{threat_data['path']}`\n"
                   f"• **Action:** IP Blocked & Logged"
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=3)
    except Exception as e:
        print("Discord alert failed:", e)

@app.before_request
def aegis_firewall_middleware():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    path = request.path
    
    if path.startswith('/admin') or path.startswith('/client') or path == '/' or path == '/api/v1/security/logs' or path.startswith('/proxy/'):
        return
        
    if client_ip in BLOCKED_IPS:
        if current_time < blocked_until.get(client_ip, 0):
            return jsonify({
                "error": "Access Denied by Aegis Core WAF",
                "reason": "Temporary IP ban active due to security violation."
            }), 403
        else:
            BLOCKED_IPS.remove(client_ip)
            del blocked_until[client_ip]

    req_payload = str(request.get_json(silent=True) or request.form.to_dict())
    target_data = request.full_path + " " + req_payload
    
    threat_type = analyze_payload(target_data)
    
    if threat_type:
        BLOCKED_IPS.add(client_ip)
        blocked_until[client_ip] = current_time + BLOCK_DURATION
        patch_advice = generate_ai_patch_advice(threat_type)
        timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(current_time))
        
        log_entry = {
            "timestamp": timestamp_str,
            "ip": client_ip,
            "path": path,
            "threat": threat_type,
            "ai_patch": patch_advice.get("developer_fix", ""),
            "client_domain": "general"
        }
        
        try:
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO security_logs (timestamp, ip, path, threat, ai_patch, client_domain) VALUES (%s, %s, %s, %s, %s, %s)",
                    (timestamp_str, client_ip, path, threat_type, log_entry["ai_patch"], "general")
                )
                conn.commit()
                cursor.close()
                conn.close()
        except Exception as e:
            print("DB Log Error:", e)
            
        send_discord_alert(log_entry)
        
        return jsonify({
            "error": "Web Application Firewall Triggered",
            "threat_detected": threat_type,
            "action": "IP Blocked & Forensic Logged",
            "ai_developer_advisor": patch_advice
        }), 403

# --- Reverse Proxy Route ---
@app.route('/proxy/<path:full_path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def reverse_proxy(full_path):
    parts = full_path.split('/', 1)
    client_domain = parts[0]
    subpath = parts[1] if len(parts) > 1 else ""

    origin_url = None
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT origin_ip FROM customers WHERE domain ILIKE %s OR domain ILIKE %s", (client_domain, f"%{client_domain}%"))
            row = cursor.fetchone()
            if row:
                origin_url = row[0]
            cursor.close()
            conn.close()
    except Exception as e:
        print("Proxy DB Error:", e)

    if not origin_url:
        return jsonify({"error": f"Target Client Domain '{client_domain}' Not Registered in Aegis Core"}), 404
        
    target_url = f"{origin_url.rstrip('/')}/{subpath}"
    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers={key: value for (key, value) in request.headers if key != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10
        )
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        return Response(resp.content, resp.status_code, headers)
    except Exception as e:
        return jsonify({"error": "Origin Server Unreachable", "details": str(e)}), 502

# --- Routes: Public Landing ---
@app.route('/')
def landing_page():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Aegis Core - Enterprise WAF & Security SaaS</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans">
        <nav class="border-b border-slate-800 bg-slate-900/50 backdrop-blur sticky top-0 z-50 px-6 py-4 flex justify-between items-center">
            <div class="flex items-center space-x-3">
                <div class="bg-cyan-500/10 border border-cyan-500/30 p-2 rounded-lg text-cyan-400">
                    <i class="fa-solid fa-shield-halved text-xl"></i>
                </div>
                <h1 class="font-bold text-lg tracking-wide text-cyan-400">AEGIS CORE</h1>
            </div>
            <div class="space-x-4">
                <a href="/client/login" class="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-4 py-2 rounded-lg border border-slate-700 transition">Client Portal</a>
                <a href="/admin/login" class="text-xs bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-4 py-2 rounded-lg transition">Admin Login</a>
            </div>
        </nav>
        <main class="p-12 max-w-5xl mx-auto text-center space-y-8">
            <div class="space-y-4">
                <span class="bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-3 py-1 rounded-full text-xs font-semibold">Enterprise Web Application Firewall</span>
                <h2 class="text-4xl md:text-6xl font-extrabold tracking-tight text-white">Next-Gen Security & <span class="text-cyan-400">AI Patch Advisor</span></h2>
                <p class="text-slate-400 max-w-2xl mx-auto text-sm">Protect your web applications from SQL Injection, XSS, and automated cyber threats with our multi-tenant cloud WAF.</p>
            </div>
        </main>
    </body>
    </html>
    """)

# --- Routes: Admin Login & Panel ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        user_input = request.form.get('username')
        pass_input = request.form.get('password')
        if (user_input == ADMIN_USER or user_input == ADMIN_EMAIL) and pass_input == ADMIN_PASS:
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Invalid Admin Credentials"
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Admin Login - Aegis Core</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 flex items-center justify-center h-screen">
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl shadow-2xl w-96 space-y-4">
            <h2 class="text-xl font-bold text-cyan-400 text-center"><i class="fa-solid fa-lock"></i> Master Admin Portal</h2>
            {% if error %}
            <p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>
            {% endif %}
            <input type="text" name="username" placeholder="Username or Email (ibr@him)" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <button type="submit" class="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold p-3 rounded text-sm transition">Login</button>
        </form>
    </body>
    </html>
    """, error=error)

@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    
    success_msg = None
    error_msg = None
    if request.method == 'POST':
        client_name = request.form.get('client_name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        domain = request.form.get('domain')
        api_key = request.form.get('api_key')
        origin_ip = request.form.get('origin_ip')
        plan = request.form.get('plan')
        
        try:
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO customers (api_key, username, email, password, client_name, domain, plan, origin_ip) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (api_key, username, email, password, client_name, domain, plan, origin_ip)
                )
                conn.commit()
                cursor.close()
                conn.close()
                success_msg = f"Client {client_name} added successfully!"
        except Exception as e:
            error_msg = f"Database Error: {e}"

    customers = []
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT api_key, username, email, client_name, domain, plan, origin_ip FROM customers")
            customers = cursor.fetchall()
            cursor.close()
            conn.close()
    except Exception as e:
        print("Admin DB Error:", e)

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Master Admin Dashboard - Aegis Core</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans">
        <nav class="border-b border-slate-800 bg-slate-900 px-6 py-4 flex justify-between items-center">
            <h1 class="font-bold text-cyan-400">AEGIS CORE • MASTER ADMIN (ibr@him)</h1>
            <a href="/admin/logout" class="text-xs text-red-400 hover:underline">Logout</a>
        </nav>
        <main class="p-6 max-w-7xl mx-auto space-y-6">
            {% if success_msg %}
            <div class="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 p-4 rounded-lg text-sm">{{ success_msg }}</div>
            {% endif %}
            {% if error_msg %}
            <div class="bg-red-500/10 border border-red-500/30 text-red-400 p-4 rounded-lg text-sm">{{ error_msg }}</div>
            {% endif %}
            
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <h2 class="text-lg font-bold text-cyan-400"><i class="fa-solid fa-user-plus mr-2"></i> Onboard New Client</h2>
                <form method="POST" class="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <input type="text" name="client_name" placeholder="Company Name" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="username" placeholder="Client Username" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="email" name="email" placeholder="Client Email" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="password" name="password" placeholder="Client Password" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="domain" placeholder="domain.com" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="api_key" placeholder="API Key (e.g. aegis_key_123)" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="origin_ip" placeholder="Origin URL (https://site.com)" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <select name="plan" class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                        <option>Starter</option>
                        <option>Pro</option>
                        <option>Enterprise</option>
                    </select>
                    <button type="submit" class="md:col-span-4 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold p-2.5 rounded text-xs transition">Create Client Account</button>
                </form>
            </div>

            <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
                <h2 class="text-lg font-bold text-cyan-400"><i class="fa-solid fa-users mr-2"></i> Registered Clients</h2>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs border-collapse">
                        <thead>
                            <tr class="border-b border-slate-800 text-slate-400 uppercase bg-slate-950">
                                <th class="p-3">Company</th>
                                <th class="p-3">Username</th>
                                <th class="p-3">Email</th>
                                <th class="p-3">Domain</th>
                                <th class="p-3">API Key</th>
                                <th class="p-3">Plan</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-800">
                            {% for c in customers %}
                            <tr>
                                <td class="p-3 font-semibold">{{ c[3] }}</td>
                                <td class="p-3 text-cyan-400">{{ c[1] }}</td>
                                <td class="p-3 text-slate-300">{{ c[2] }}</td>
                                <td class="p-3 text-cyan-400">{{ c[4] }}</td>
                                <td class="p-3 font-mono text-slate-400">{{ c[0] }}</td>
                                <td class="p-3">{{ c[5] }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </main>
    </body>
    </html>
    """, success_msg=success_msg, error_msg=error_msg, customers=customers)

@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    return redirect(url_for('admin_login'))

# --- Routes: Client Login & Portal ---
@app.route('/client/login', methods=['GET', 'POST'])
def client_login():
    error = None
    if request.method == 'POST':
        identity = request.form.get('identity')
        password = request.form.get('password')
        try:
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT client_name, domain, plan FROM customers WHERE (username = %s OR email = %s OR api_key = %s) AND password = %s",
                    (identity, identity, identity, password)
                )
                client = cursor.fetchone()
                cursor.close()
                conn.close()
                if client:
                    session['client_name'] = client[0]
                    session['client_domain'] = client[1]
                    return redirect(url_for('client_dashboard'))
        except Exception as e:
            print("Login error:", e)
        error = "Invalid Credentials or API Key"
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Client Portal Login - Aegis Core</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 flex items-center justify-center h-screen">
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl shadow-2xl w-96 space-y-4">
            <h2 class="text-xl font-bold text-cyan-400 text-center"><i class="fa-solid fa-shield"></i> Client Portal Login</h2>
            {% if error %}
            <p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>
            {% endif %}
            <input type="text" name="identity" placeholder="Username, Email or API Key" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <button type="submit" class="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold p-3 rounded text-sm transition">Access Portal</button>
        </form>
    </body>
    </html>
    """, error=error)

@app.route('/client/dashboard')
def client_dashboard():
    if not session.get('client_name'):
        return redirect(url_for('client_login'))
    
    client_name = session.get('client_name')
    client_domain = session.get('client_domain')
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Client Dashboard - Aegis Core</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans">
        <nav class="border-b border-slate-800 bg-slate-900 px-6 py-4 flex justify-between items-center">
            <h1 class="font-bold text-cyan-400">AEGIS CORE • CLIENT PORTAL ({{ client_name }})</h1>
            <a href="/client/logout" class="text-xs text-red-400 hover:underline">Logout</a>
        </nav>
        <main class="p-6 max-w-5xl mx-auto space-y-6">
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <h2 class="text-lg font-bold text-cyan-400"><i class="fa-solid fa-server mr-2"></i> Your Proxy Endpoint</h2>
                <p class="text-xs text-slate-400">Route your application traffic through this secure gateway:</p>
                <code class="bg-slate-950 p-3 rounded block text-xs text-cyan-300 font-mono">https://<span id="hostName"></span>/proxy/{{ client_domain }}/path</code>
            </div>
        </main>
        <script>
            document.getElementById('hostName').innerText = window.location.host;
        </script>
    </body>
    </html>
    """, client_name=client_name, client_domain=client_domain)

@app.route('/client/logout')
def client_logout():
    session.clear()
    return redirect(url_for('client_login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
