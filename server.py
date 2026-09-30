import os
import time
import re
import requests
from flask import Flask, jsonify, request, render_template_string, Response, redirect, url_for, session
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "aegis_super_secret_key_2026")

# মেমোরিতে ক্লায়েন্ট ডেটা সেভ করার জন্য লিস্ট (এক্সপায়ারি ডেট সহ)
CUSTOMERS_DB = [
    {
        "api_key": "aegis_live_key_999",
        "username": "ibr@him",
        "email": "admin@firewall.com",
        "password": "muhib5869@",
        "client_name": "My Main Server",
        "domain": "mysite.com",
        "plan": "Enterprise",
        "origin_ip": "https://your-actual-website.com",
        "expiry_date": "2027-12-31"
    }
]

ADMIN_USER = "ibr@him"
ADMIN_EMAIL = "admin@firewall.com"
ADMIN_PASS = "muhib5869@"

BLOCKED_IPS = set()
blocked_until = {}
BLOCK_DURATION = 300

SQLI_PATTERNS = [
    (r"union\s+select", "SQL Injection"),
    (r"or\s+1\s*=\s*1", "SQL Injection"),
    (r"drop\s+table", "SQL Injection"),
    (r"(\%27)|(\')", "SQL Injection")
]

XSS_PATTERNS = [
    (r"<script[^>]*>[\s\S]*?</script>", "XSS Attack"),
    (r"javascript\s*:", "XSS Attack"),
    (r"onerror\s*=", "XSS Attack")
]

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

@app.before_request
def aegis_firewall_middleware():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    path = request.path
    
    if path.startswith('/admin') or path.startswith('/client') or path == '/' or path.startswith('/proxy/'):
        return
        
    if client_ip in BLOCKED_IPS:
        if current_time < blocked_until.get(client_ip, 0):
            return jsonify({
                "error": "Access Denied by Aegis WAF",
                "reason": "Temporary IP ban due to security violation."
            }), 403
        else:
            BLOCKED_IPS.remove(client_ip)
            del blocked_until[client_ip]

    req_payload = str(request.full_path) + " " + str(request.get_json(silent=True) or request.form.to_dict())
    threat_type = analyze_payload(req_payload)
    
    if threat_type:
        BLOCKED_IPS.add(client_ip)
        blocked_until[client_ip] = current_time + BLOCK_DURATION
        return jsonify({
            "error": "Web Application Firewall Triggered",
            "threat_detected": threat_type,
            "action": "IP Blocked"
        }), 403

# --- Reverse Proxy Route (License Expiry Check সহ) ---
@app.route('/proxy/<path:full_path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def reverse_proxy(full_path):
    parts = full_path.split('/', 1)
    client_domain = parts[0]
    subpath = parts[1] if len(parts) > 1 else ""

    matched_client = None
    for c in CUSTOMERS_DB:
        if c['domain'].lower() == client_domain.lower() or client_domain.lower() in c['domain'].lower():
            matched_client = c
            break

    if not matched_client:
        return jsonify({"error": f"Target Domain '{client_domain}' Not Registered in Aegis Core"}), 404
        
    # লাইসেন্সের মেয়াদ শেষ হয়ে গেছে কিনা চেক করা
    expiry_date_str = matched_client.get('expiry_date')
    if expiry_date_str:
        try:
            expiry_date = datetime.strptime(expiry_date_str, "%Y-%m-%d")
            if datetime.now() > expiry_date:
                return jsonify({"error": "License Expired", "message": "This server's license has expired. Please contact admin."}), 403
        except Exception:
            pass

    origin_url = matched_client['origin_ip']
    target_url = f"{origin_url.rstrip('/')}/{subpath}"
    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers={key: value for (key, value) in request.headers if key != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=15
        )
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        return Response(resp.content, resp.status_code, headers)
    except Exception as e:
        return jsonify({"error": "Origin Server Unreachable", "details": str(e)}), 502

# --- Landing Page ---
@app.route('/')
def landing_page():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Aegis Core - WAF Security</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 flex flex-col items-center justify-center h-screen space-y-4">
        <h1 class="text-3xl font-bold text-cyan-400">🛡️ Aegis Core WAF Active</h1>
        <p class="text-slate-400 text-sm">Protected Web Application Firewall Gateway</p>
        <div class="space-x-4">
            <a href="/client/login" class="bg-slate-800 border border-slate-700 px-4 py-2 rounded text-xs text-slate-200">Client Login</a>
            <a href="/admin/login" class="bg-cyan-500 font-bold px-4 py-2 rounded text-xs text-slate-950">Admin Login</a>
        </div>
    </body>
    </html>
    """)

# --- Admin Login ---
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
        <title>Admin Login</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 flex items-center justify-center h-screen">
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl shadow-2xl w-96 space-y-4">
            <h2 class="text-xl font-bold text-cyan-400 text-center">Master Admin Portal</h2>
            {% if error %}
            <p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>
            {% endif %}
            <input type="text" name="username" placeholder="Username or Email" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <button type="submit" class="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold p-3 rounded text-sm transition">Login</button>
        </form>
    </body>
    </html>
    """, error=error)

# --- Admin Dashboard, Client Creator & Delete Option ---
@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    
    success_msg = None
    error_msg = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        # ক্লায়েন্ট ডিলিট করার লজিক
        if action == 'delete':
            api_key_to_delete = request.form.get('api_key')
            global CUSTOMERS_DB
            CUSTOMERS_DB = [c for c in CUSTOMERS_DB if c['api_key'] != api_key_to_delete]
            success_msg = "Client/License deleted successfully!"
            
        # নতুন ক্লায়েন্ট বা লাইসেন্স ক্রিয়েট করার লজিক
        elif action == 'create':
            client_name = request.form.get('client_name')
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            domain = request.form.get('domain')
            api_key = request.form.get('api_key')
            origin_ip = request.form.get('origin_ip')
            plan = request.form.get('plan')
            expiry_date = request.form.get('expiry_date') # এখানে ডেট রিসিভ হচ্ছে
            
            try:
                new_client = {
                    "api_key": api_key,
                    "username": username,
                    "email": email,
                    "password": password,
                    "client_name": client_name,
                    "domain": domain,
                    "plan": plan,
                    "origin_ip": origin_ip,
                    "expiry_date": expiry_date
                }
                CUSTOMERS_DB.append(new_client)
                success_msg = f"Client '{client_name}' created successfully!"
            except Exception as e:
                error_msg = f"Error: {e}"

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Admin Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans">
        <nav class="border-b border-slate-800 bg-slate-900 px-6 py-4 flex justify-between items-center">
            <h1 class="font-bold text-cyan-400">AEGIS CORE • ADMIN PANEL</h1>
            <a href="/admin/logout" class="text-xs text-red-400 hover:underline">Logout</a>
        </nav>
        <main class="p-6 max-w-7xl mx-auto space-y-6">
            {% if success_msg %}
            <div class="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 p-4 rounded text-sm">{{ success_msg }}</div>
            {% endif %}
            {% if error_msg %}
            <div class="bg-red-500/10 border border-red-500/30 text-red-400 p-4 rounded text-sm">{{ error_msg }}</div>
            {% endif %}
            
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <h2 class="text-lg font-bold text-cyan-400"><i class="fa-solid fa-user-plus mr-2"></i> Create Server/Client & License Date</h2>
                <form method="POST" class="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <input type="hidden" name="action" value="create">
                    <input type="text" name="client_name" placeholder="Server Name" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="username" placeholder="Username" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="email" name="email" placeholder="Email" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="password" name="password" placeholder="Password" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="domain" placeholder="domain.com (Proxy path)" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="api_key" placeholder="API Key (Unique)" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="origin_ip" placeholder="Origin URL (https://mysite.com)" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <div class="flex flex-col space-y-1">
                        <label class="text-[10px] text-slate-400">License Expiry Date:</label>
                        <input type="date" name="expiry_date" required class="bg-slate-950 border border-slate-800 p-2 rounded text-xs text-slate-200">
                    </div>
                    <select name="plan" class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs md:col-span-3">
                        <option>Standard</option>
                        <option>Enterprise</option>
                    </select>
                    <button type="submit" class="md:col-span-4 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold p-2.5 rounded text-xs transition">Save & Create License</button>
                </form>
            </div>

            <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
                <h2 class="text-lg font-bold text-cyan-400"><i class="fa-solid fa-server mr-2"></i> Registered Clients / Licenses</h2>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs border-collapse">
                        <thead>
                            <tr class="border-b border-slate-800 text-slate-400 uppercase bg-slate-950">
                                <th class="p-3">Name</th>
                                <th class="p-3">Username</th>
                                <th class="p-3">Domain</th>
                                <th class="p-3">Origin URL</th>
                                <th class="p-3">Expiry Date</th>
                                <th class="p-3">API Key</th>
                                <th class="p-3 text-center">Action</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-800">
                            {% for c in customers %}
                            <tr>
                                <td class="p-3 font-semibold">{{ c.client_name }}</td>
                                <td class="p-3 text-cyan-400">{{ c.username }}</td>
                                <td class="p-3 text-cyan-400">{{ c.domain }}</td>
                                <td class="p-3 text-slate-400 truncate max-w-xs">{{ c.origin_ip }}</td>
                                <td class="p-3 text-amber-400 font-semibold">{{ c.expiry_date }}</td>
                                <td class="p-3 font-mono text-slate-400">{{ c.api_key }}</td>
                                <td class="p-3 text-center">
                                    <form method="POST" onsubmit="return confirm('Are you sure you want to delete this license?');" style="display:inline;">
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="api_key" value="{{ c.api_key }}">
                                        <button type="submit" class="bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500 hover:text-white px-2.5 py-1 rounded transition text-[10px]">
                                            <i class="fa-solid fa-trash mr-1"></i> Delete
                                        </button>
                                    </form>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </main>
    </body>
    </html>
    """, success_msg=success_msg, error_msg=error_msg, customers=CUSTOMERS_DB)

@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    return redirect(url_for('admin_login'))

# --- Client Login ---
@app.route('/client/login', methods=['GET', 'POST'])
def client_login():
    error = None
    if request.method == 'POST':
        identity = request.form.get('identity')
        password = request.form.get('password')
        
        logged_client = None
        for c in CUSTOMERS_DB:
            if (c['username'] == identity or c['email'] == identity or c['api_key'] == identity) and c['password'] == password:
                logged_client = c
                break
                
        if logged_client:
            session['client_name'] = logged_client['client_name']
            session['client_domain'] = logged_client['domain']
            session['client_expiry'] = logged_client.get('expiry_date', 'N/A')
            return redirect(url_for('client_dashboard'))
        else:
            error = "Invalid Credentials or API Key"
            
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Client Portal Login</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 flex items-center justify-center h-screen">
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl shadow-2xl w-96 space-y-4">
            <h2 class="text-xl font-bold text-cyan-400 text-center">Client Portal Login</h2>
            {% if error %}
            <p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>
            {% endif %}
            <input type="text" name="identity" placeholder="Username, Email or API Key" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <button type="submit" class="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold p-3 rounded text-sm transition">Login</button>
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
    client_expiry = session.get('client_expiry')
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Client Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans">
        <nav class="border-b border-slate-800 bg-slate-900 px-6 py-4 flex justify-between items-center">
            <h1 class="font-bold text-cyan-400">CLIENT PORTAL ({{ client_name }})</h1>
            <a href="/client/logout" class="text-xs text-red-400 hover:underline">Logout</a>
        </nav>
        <main class="p-6 max-w-4xl mx-auto space-y-6">
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-3">
                <h2 class="text-lg font-bold text-cyan-400">License Status & Proxy Link</h2>
                <p class="text-xs text-slate-400">License Expiry Date: <span class="text-amber-400 font-bold">{{ client_expiry }}</span></p>
                <p class="text-xs text-slate-400 mt-2">Your protected proxy endpoint:</p>
                <code class="bg-slate-950 p-3 rounded block text-xs text-cyan-300 font-mono">https://<span id="hostName"></span>/proxy/{{ client_domain }}/path</code>
            </div>
        </main>
        <script>
            document.getElementById('hostName').innerText = window.location.host;
        </script>
    </body>
    </html>
    """, client_name=client_name, client_domain=client_domain, client_expiry=client_expiry)

@app.route('/client/logout')
def client_logout():
    session.clear()
    return redirect(url_for('client_login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
