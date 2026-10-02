import os
import time
import re
import requests
from urllib.parse import unquote
from flask import Flask, jsonify, request, render_template_string, Response, redirect, url_for, session
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "aegis_absolute_complete_2026")

# স্ট্রাইক এবং ব্লক ট্র্যাকিং
strike_records = {}
blocked_ips = {}
MAX_STRIKES = 4  
BLOCK_TIME = 1800  # ৩০ মিনিট

# রিয়েল ক্লায়েন্ট ডাটাবেজ
CUSTOMERS_DB = [
    {
        "api_key": "aegis_live_key_999",
        "username": "ibr@him",
        "email": "admin@firewall.com",
        "password": "muhib5869@",
        "client_name": "My Main Server",
        "domains": ["iss-antivirus-cloud.onrender.com"],
        "plan": "Enterprise",
        "origin_ip": "https://iss-antivirus-cloud.onrender.com",
        "expiry_date": "2027-12-31"
    }
]

ADMIN_USER = "ibr@him"
ADMIN_EMAIL = "admin@firewall.com"
ADMIN_PASS = "muhib5869@"

# --- Connected Real-Time WAF Engine ---
@app.before_request
def connected_waf_inspection():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    
    # অ্যাডমিন বা ক্লায়েন্ট লগইন পেজে ফায়ারওয়াল ব্লক করবে না
    if request.path.startswith('/admin') or request.path.startswith('/client') or request.path == '/my-profile':
        return

    # আইপি ব্লক স্ট্যাটাস চেক
    if client_ip in blocked_ips:
        if current_time < blocked_ips[client_ip]:
            return jsonify({
                "error": "Aegis WAF - IP Banned",
                "message": "Your IP has been blocked due to repeated payload injection attacks."
            }), 403
        else:
            del blocked_ips[client_ip]
            if client_ip in strike_records:
                del strike_records[client_ip]

    # ডাটাবেজ ডোমেইনের সাথে বাইন্ডিং চেক
    host_header = request.host.lower()
    target_param = request.args.get('target', '').lower()
    
    is_registered_domain = False
    for client in CUSTOMERS_DB:
        for d in client['domains']:
            if d.lower() in host_header or d.lower() in target_param:
                is_registered_domain = True
                break
        if is_registered_domain:
            break

    # স্ক্যানিং টার্গেট তৈরি
    raw_full_path = request.full_path
    decoded_url = unquote(raw_full_path)
    
    body_content = ""
    try:
        body_content = unquote(request.get_data(as_text=True))
    except Exception:
        pass

    inspection_target = f"{decoded_url} {body_content}"

    # ডেঞ্জারাস অ্যাটাক প্যাটার্ন (SQLi, XSS)
    sqli_pattern = r"union\s+select|or\s+1\s*=\s*1|drop\s+table|--|#|information_schema|benchmark\s*\(|exec\s*\("
    xss_pattern = r"<script.*?>.*?</script>|javascript:|onerror\s*=|onload\s*="

    is_threat = False
    threat_name = ""

    if re.search(sqli_pattern, inspection_target, re.IGNORECASE):
        is_threat = True
        threat_name = "SQL Injection (SQLi)"
    elif re.search(xss_pattern, inspection_target, re.IGNORECASE):
        is_threat = True
        threat_name = "Cross-Site Scripting (XSS)"

    if is_threat:
        if client_ip not in strike_records:
            strike_records[client_ip] = 0
        
        strike_records[client_ip] += 1
        current_strikes = strike_records[client_ip]
        
        if current_strikes >= MAX_STRIKES:
            blocked_ips[client_ip] = current_time + BLOCK_TIME
            return jsonify({
                "error": "Aegis WAF - Critical Security Violation",
                "threat_detected": threat_name,
                "strikes": f"{current_strikes}/{MAX_STRIKES}",
                "action": "IP BANNED for 30 minutes. Access completely terminated!"
            }), 403
        else:
            return jsonify({
                "error": "Aegis WAF - Malicious Payload Blocked",
                "threat_detected": threat_name,
                "database_connected": True,
                "strikes_count": f"{current_strikes}/{MAX_STRIKES}",
                "message": f"Payload detected and blocked! {MAX_STRIkes - current_strikes} attempts left."
            }), 400

# --- Reverse Proxy Route ---
@app.route('/proxy', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def reverse_proxy():
    target = request.args.get('target', '').strip('/')
    if not target:
        return jsonify({"error": "Invalid Proxy Target Format. Use /proxy?target=domain.com/path"}), 400
        
    parts = target.split('/', 1)
    client_domain = parts[0]
    subpath = parts[1] if len(parts) > 1 else ""

    matched_client = None
    for c in CUSTOMERS_DB:
        if any(client_domain.lower() in d.lower() or d.lower() in client_domain.lower() for d in c['domains']):
            matched_client = c
            break

    if not matched_client:
        return jsonify({"error": f"Target Domain '{client_domain}' Not Registered in Firewall Database"}), 404
        
    origin_url = matched_client['origin_ip']
    target_url = f"{origin_url.rstrip('/')}/{subpath}"
    
    try:
        req_headers = {key: value for (key, value) in request.headers if key.lower() not in ['host', 'accept-encoding']}
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=req_headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=15
        )
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded_headers]
        return Response(resp.content, resp.status_code, headers)
    except Exception as e:
        return jsonify({"error": "Origin Server Unreachable", "details": str(e)}), 502

# --- Complete Landing Page (With Images, Plans, & Social Links) ---
@app.route('/')
def landing_page():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Aegis Core - Connected Web Application Firewall</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500 selection:text-slate-950">
        <!-- Navigation -->
        <nav class="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-8 py-4 flex justify-between items-center">
            <div class="flex items-center space-x-2">
                <i class="fa-solid fa-shield-cat text-cyan-400 text-xl"></i>
                <span class="font-bold text-lg tracking-wider text-cyan-400">AEGIS CORE WAF</span>
            </div>
            <div class="space-x-4">
                <a href="#plans" class="text-xs text-slate-300 hover:text-cyan-400 font-medium transition">Pricing</a>
                <a href="/client/login" class="text-xs text-slate-300 hover:text-cyan-400 font-medium transition">Client Login</a>
                <a href="/my-profile" class="bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500 hover:text-slate-950 font-bold px-4 py-2 rounded text-xs transition">Admin Portal</a>
            </div>
        </nav>

        <!-- Hero Section -->
        <header class="max-w-6xl mx-auto px-6 py-16 text-center space-y-6">
            <span class="bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs px-3 py-1 rounded-full uppercase tracking-widest font-semibold">Zero-Tolerance Connected Firewall Active</span>
            <h1 class="text-4xl md:text-6xl font-extrabold tracking-tight text-white">Ultimate Defense for Your <span class="text-cyan-400">Web Servers & Infrastructure</span></h1>
            <p class="text-slate-400 text-sm md:text-base max-w-2xl mx-auto">Protecting your web assets, client links, and proxies from SQL Injections, XSS, and malicious payload threats in real-time.</p>
        </header>

        <!-- Image Gallery Section -->
        <section class="max-w-6xl mx-auto px-6 py-8 space-y-6 text-center">
            <h2 class="text-2xl font-bold text-cyan-400">Security Infrastructure Overview</h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
                <div class="bg-slate-900 border border-slate-800 p-2 rounded-xl">
                    <img src="https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&auto=format&fit=crop&q=80" alt="Cloud Security" class="w-full h-40 object-cover rounded-lg border border-slate-800">
                </div>
                <div class="bg-slate-900 border border-slate-800 p-2 rounded-xl">
                    <img src="https://images.unsplash.com/photo-1563986768609-322da13575f3?w=600&auto=format&fit=crop&q=80" alt="Network Wall" class="w-full h-40 object-cover rounded-lg border border-slate-800">
                </div>
                <div class="bg-slate-900 border border-slate-800 p-2 rounded-xl">
                    <img src="https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=600&auto=format&fit=crop&q=80" alt="Malware Defense" class="w-full h-40 object-cover rounded-lg border border-slate-800">
                </div>
                <div class="bg-slate-900 border border-slate-800 p-2 rounded-xl">
                    <img src="https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=600&auto=format&fit=crop&q=80" alt="Traffic Routing" class="w-full h-40 object-cover rounded-lg border border-slate-800">
                </div>
            </div>
        </section>

        <!-- Pricing Section -->
        <section id="plans" class="max-w-6xl mx-auto px-6 py-16 space-y-8">
            <div class="text-center space-y-3">
                <h2 class="text-3xl font-bold text-white">Choose Your <span class="text-cyan-400">Protection Plan</span></h2>
                <p class="text-slate-400 text-sm">Flexible pricing plans designed to secure websites and applications of any scale.</p>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div class="bg-slate-900 border border-slate-800 p-8 rounded-2xl space-y-6 flex flex-col justify-between">
                    <div class="space-y-4">
                        <span class="text-xs bg-slate-800 text-cyan-400 px-3 py-1 rounded-full font-semibold">Standard Plan</span>
                        <h3 class="text-2xl font-bold text-white">$19<span class="text-xs text-slate-400 font-normal"> /month</span></h3>
                        <ul class="text-xs space-y-2 text-slate-300">
                            <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i> 1 Domain Protected</li>
                            <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i> Basic SQLi & XSS Defense</li>
                        </ul>
                    </div>
                    <a href="/client/login" class="w-full block text-center bg-slate-800 hover:bg-cyan-500 hover:text-slate-950 font-bold py-2.5 rounded text-xs transition">Get Standard</a>
                </div>

                <div class="bg-slate-900 border border-cyan-500 p-8 rounded-2xl space-y-6 flex flex-col justify-between relative shadow-lg shadow-cyan-500/10">
                    <div class="absolute -top-3 right-6 bg-cyan-500 text-slate-950 text-[10px] font-extrabold px-3 py-0.5 rounded-full uppercase">Popular</div>
                    <div class="space-y-4">
                        <span class="text-xs bg-cyan-500/20 text-cyan-400 px-3 py-1 rounded-full font-semibold">Professional Plan</span>
                        <h3 class="text-2xl font-bold text-white">$49<span class="text-xs text-slate-400 font-normal"> /month</span></h3>
                        <ul class="text-xs space-y-2 text-slate-300">
                            <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i> Up to 5 Domains Protected</li>
                            <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i> Advanced Smart Strike System</li>
                        </ul>
                    </div>
                    <a href="/client/login" class="w-full block text-center bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold py-2.5 rounded text-xs transition">Get Professional</a>
                </div>

                <div class="bg-slate-900 border border-slate-800 p-8 rounded-2xl space-y-6 flex flex-col justify-between">
                    <div class="space-y-4">
                        <span class="text-xs bg-slate-800 text-purple-400 px-3 py-1 rounded-full font-semibold">Enterprise Plan</span>
                        <h3 class="text-2xl font-bold text-white">$99<span class="text-xs text-slate-400 font-normal"> /month</span></h3>
                        <ul class="text-xs space-y-2 text-slate-300">
                            <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i> Up to 10 Domains Protected</li>
                            <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i> Custom Shield & Priority Support</li>
                        </ul>
                    </div>
                    <a href="/client/login" class="w-full block text-center bg-slate-800 hover:bg-cyan-500 hover:text-slate-950 font-bold py-2.5 rounded text-xs transition">Get Enterprise</a>
                </div>
            </div>
        </section>

        <!-- Social Links & Footer Section -->
        <footer class="border-t border-slate-800 py-10 bg-slate-900/40 text-center space-y-4">
            <div class="flex justify-center space-x-6 text-slate-400 text-lg">
                <a href="https://instagram.com/mrshadow6000" target="_blank" class="hover:text-cyan-400 transition" title="Instagram"><i class="fa-brands fa-instagram"></i></a>
                <a href="https://discord.gg/mxRgm2R3ud" target="_blank" class="hover:text-cyan-400 transition" title="Discord"><i class="fa-brands fa-discord"></i></a>
                <a href="https://linkedin.com" target="_blank" class="hover:text-cyan-400 transition" title="LinkedIn"><i class="fa-brands fa-linkedin"></i></a>
                <a href="https://medium.com" target="_blank" class="hover:text-cyan-400 transition" title="Medium"><i class="fa-brands fa-medium"></i></a>
            </div>
            <p class="text-xs text-slate-500">&copy; 2026 Aegis Core WAF Security System. All rights reserved.</p>
        </footer>
    </body>
    </html>
    """)

# --- Admin Portal & Dashboard ---
@app.route('/my-profile', methods=['GET', 'POST'])
def my_profile():
    error = None
    if request.args.get('logout'):
        session.pop('is_admin', None)
        return redirect(url_for('my_profile'))
    if request.method == 'POST':
        if (request.form.get('username') == ADMIN_USER or request.form.get('username') == ADMIN_EMAIL) and request.form.get('password') == ADMIN_PASS:
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Invalid Master Credentials"
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 flex items-center justify-center h-screen">
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl w-96 space-y-4 shadow-2xl">
            <h2 class="text-xl font-bold text-cyan-400 text-center">Admin Portal</h2>
            {% if error %}<p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>{% endif %}
            <input type="text" name="username" placeholder="Username or Email" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <button type="submit" class="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold p-3 rounded text-sm transition">Login</button>
        </form>
    </body></html>
    """, error=error)

@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('is_admin'): return redirect(url_for('my_profile'))
    global CUSTOMERS_DB
    success_msg = None
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'delete':
            api_key = request.form.get('api_key')
            CUSTOMERS_DB = [c for c in CUSTOMERS_DB if c['api_key'] != api_key]
            success_msg = "Client deleted!"
        elif action == 'create':
            try:
                new_client = {
                    "api_key": request.form.get('api_key'),
                    "username": request.form.get('username'),
                    "email": request.form.get('email'),
                    "password": request.form.get('password'),
                    "client_name": request.form.get('client_name'),
                    "domains": [request.form.get('domain')] if request.form.get('domain') else [],
                    "plan": request.form.get('plan'),
                    "origin_ip": request.form.get('origin_ip'),
                    "expiry_date": request.form.get('expiry_date')
                }
                CUSTOMERS_DB.append(new_client)
                success_msg = "Client created!"
            except Exception:
                pass
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 p-6 space-y-6 font-sans">
        <nav class="border-b border-slate-800 bg-slate-900 px-6 py-4 flex justify-between items-center rounded-xl">
            <h1 class="font-bold text-cyan-400">ADMIN DASHBOARD</h1>
            <a href="/my-profile?logout=true" class="text-xs text-red-400 hover:underline">Logout</a>
        </nav>
        <main class="max-w-6xl mx-auto space-y-6">
            {% if success_msg %}<div class="bg-emerald-500/10 text-emerald-400 p-3 rounded text-xs">{{ success_msg }}</div>{% endif %}
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <h2 class="text-sm font-bold text-cyan-400">Add New Client License</h2>
                <form method="POST" class="grid grid-cols-1 md:grid-cols-4 gap-3">
                    <input type="hidden" name="action" value="create">
                    <input type="text" name="client_name" placeholder="Server Name" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="username" placeholder="Username" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="email" name="email" placeholder="Email" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="password" name="password" placeholder="Password" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="domain" placeholder="Domain (e.g. site.com)" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="api_key" placeholder="API Key" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="origin_ip" placeholder="Origin URL" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="date" name="expiry_date" required class="bg-slate-950 border border-slate-800 p-2 rounded text-xs text-slate-200">
                    <select name="plan" class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs md:col-span-3">
                        <option value="Standard">Standard</option>
                        <option value="Professional">Professional</option>
                        <option value="Enterprise">Enterprise</option>
                    </select>
                    <button type="submit" class="md:col-span-4 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold p-2.5 rounded text-xs transition">Create Client</button>
                </form>
            </div>
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <h2 class="text-sm font-bold text-cyan-400">Registered Clients</h2>
                <div class="space-y-2">
                    {% for client in customers %}
                    <div class="bg-slate-950 border border-slate-800 p-3 rounded-lg flex justify-between items-center text-xs">
                        <div>
                            <p class="font-bold text-white">{{ client.client_name }} (<span class="text-cyan-400">{{ client.username }}</span>)</p>
                            <p class="text-slate-400">Domains: {{ client.domains | join(', ') }} | Plan: {{ client.plan }}</p>
                        </div>
                        <form method="POST" onsubmit="return confirm('Delete?');">
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="api_key" value="{{ client.api_key }}">
                            <button type="submit" class="bg-red-500/10 text-red-400 hover:bg-red-500 hover:text-white px-3 py-1.5 rounded transition">Delete</button>
                        </form>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </main>
    </body></html>
    """, success_msg=success_msg, customers=CUSTOMERS_DB)

# --- Client Login & Dashboard ---
@app.route('/client/login', methods=['GET', 'POST'])
def client_login():
    error = None
    if request.method == 'POST':
        identity = request.form.get('identity')
        password = request.form.get('password')
        client = next((c for c in CUSTOMERS_DB if (c['username'] == identity or c['email'] == identity or c['api_key'] == identity) and c['password'] == password), None)
        if client:
            session['client_username'] = client['username']
            return redirect(url_for('client_dashboard'))
        else:
            error = "Invalid Credentials"
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 flex items-center justify-center h-screen">
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl w-96 space-y-4 shadow-2xl">
            <h2 class="text-xl font-bold text-cyan-400 text-center">Client Portal Login</h2>
            {% if error %}<p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>{% endif %}
            <input type="text" name="identity" placeholder="Username, Email or API Key" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <button type="submit" class="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold p-3 rounded text-sm transition">Login</button>
        </form>
    </body></html>
    """, error=error)

@app.route('/client/dashboard', methods=['GET', 'POST'])
def client_dashboard():
    username = session.get('client_username')
    if not username: return redirect(url_for('client_login'))
    current_client = next((c for c in CUSTOMERS_DB if c['username'] == username), None)
    if not current_client: return redirect(url_for('client_login'))
    
    success_msg = None
    limit_map = {"Standard": 1, "Professional": 5, "Enterprise": 10}
    max_slots = limit_map.get(current_client['plan'], 1)

    if request.method == 'POST':
        new_domains = [request.form.get(f'domain_{i}').strip() for i in range(max_slots) if request.form.get(f'domain_{i}')]
        current_client['domains'] = new_domains
        success_msg = "Domains updated!"

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 font-sans p-6 space-y-6">
        <nav class="border-b border-slate-800 bg-slate-900 px-6 py-4 flex justify-between items-center rounded-xl">
            <h1 class="font-bold text-cyan-400">CLIENT PORTAL ({{ client.client_name }})</h1>
            <a href="/client/logout" class="text-xs text-red-400 hover:underline">Logout</a>
        </nav>
        <main class="max-w-4xl mx-auto space-y-6">
            {% if success_msg %}<div class="bg-emerald-500/10 text-emerald-400 p-3 rounded text-xs">{{ success_msg }}</div>{% endif %}
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <h2 class="text-sm font-bold text-cyan-400">Configure Protected Domain Slots (Plan: {{ client.plan }})</h2>
                <form method="POST" class="space-y-3">
                    {% for i in range(max_slots) %}
                    <input type="text" name="domain_{{ i }}" value="{{ client.domains[i] if i < client.domains|length else '' }}" placeholder="mysite.com" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded text-xs text-slate-200">
                    {% endfor %}
                    <button type="submit" class="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-6 py-2 rounded text-xs transition">Save Domains</button>
                </form>
            </div>
        </main>
    </body></html>
    """, client=current_client, max_slots=max_slots, success_msg=success_msg)

@app.route('/client/logout')
def client_logout():
    session.pop('client_username', None)
    return redirect(url_for('client_login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
