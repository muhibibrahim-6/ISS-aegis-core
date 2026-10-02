import os
import time
import re
import requests
from urllib.parse import unquote
from flask import Flask, jsonify, request, render_template_string, Response, redirect, url_for, session
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "aegis_complete_secret_2026")

# স্ট্রাইক এবং ব্লক ট্র্যাকিং ডিকশনারি
strike_records = {}
blocked_ips = {}
MAX_STRIKES = 4  # ৪ বার হলে ব্লক
BLOCK_TIME = 1800  # ৩০ মিনিট

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

# --- Final Zero-Tolerance WAF Layer ---
@app.before_request
def final_waf_protection():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    path = request.path

    # আইপি ব্লক চেক
    if client_ip in blocked_ips:
        if current_time < blocked_ips[client_ip]:
            return jsonify({
                "error": "Aegis WAF - IP Blocked",
                "message": "Your IP has been blocked due to continuous payload injection attempts."
            }), 403
        else:
            del blocked_ips[client_ip]
            if client_ip in strike_records:
                del strike_records[client_ip]

    # পুরো রিকোয়েস্ট ডিকোড করে স্ক্যান করা (ইউআরএল, প্যারামিটার এবং বডি)
    raw_full_path = request.full_path
    decoded_url = unquote(raw_full_path)
    
    body_content = ""
    try:
        body_content = unquote(request.get_data(as_text=True))
    except Exception:
        pass

    inspection_target = f"{decoded_url} {body_content}"

    # অ্যাটাক প্যাটার্ন (SQLi, XSS)
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
                "error": "Aegis WAF - Security Violation",
                "threat_detected": threat_name,
                "strikes": f"{current_strikes}/{MAX_STRIKES}",
                "action": "Blocked completely. IP suspended for 30 minutes!"
            }), 403
        else:
            return jsonify({
                "error": "Aegis WAF - Malicious Payload Blocked",
                "threat_detected": threat_name,
                "strikes_count": f"{current_strikes}/{MAX_STRIKES}",
                "message": f"Payload detected and blocked! Website access denied. {MAX_STRIKES - current_strikes} attempts remaining before IP ban."
            }), 400

# --- Reverse Proxy Route ---
@app.route('/proxy', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def reverse_proxy():
    target = request.args.get('target', '').strip('/')
    if not target:
        return jsonify({"error": "Invalid Proxy URL Format"}), 400
        
    parts = target.split('/', 1)
    client_domain = parts[0]
    subpath = parts[1] if len(parts) > 1 else ""

    matched_client = None
    for c in CUSTOMERS_DB:
        if any(client_domain.lower() in d.lower() or d.lower() in client_domain.lower() for d in c['domains']):
            matched_client = c
            break

    if not matched_client:
        return jsonify({"error": f"Target Domain Not Registered"}), 404
        
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

# --- Complete Landing Page with Subscription Plans & Social Links ---
@app.route('/')
def landing_page():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Aegis Core - Smart WAF & Protection</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500 selection:text-slate-950">
        <!-- Navigation -->
        <nav class="border-b border-slate-800 bg-slate-900/50 backdrop-blur fixed w-full z-50 px-8 py-4 flex justify-between items-center">
            <div class="flex items-center space-x-2">
                <i class="fa-solid fa-shield-halved text-cyan-400 text-xl"></i>
                <span class="font-bold tracking-wider text-cyan-400">AEGIS CORE WAF</span>
            </div>
            <div class="space-x-6 text-sm flex items-center">
                <a href="#plans" class="text-slate-300 hover:text-cyan-400 transition">Plans</a>
                <a href="/client/login" class="text-slate-300 hover:text-cyan-400 transition">Client Portal</a>
                <a href="/my-profile" class="bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 px-4 py-2 rounded-lg text-xs font-semibold hover:bg-cyan-500/20 transition">Admin Portal</a>
            </div>
        </nav>

        <!-- Hero Section -->
        <section class="max-w-6xl mx-auto px-6 pt-32 pb-20 text-center space-y-6">
            <div class="inline-flex items-center space-x-2 bg-cyan-500/10 border border-cyan-500/20 px-3 py-1 rounded-full text-cyan-400 text-xs font-mono">
                <span class="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
                <span>Zero-Tolerance Multi-Layer Protection Active</span>
            </div>
            <h1 class="text-5xl md:text-6xl font-extrabold tracking-tight text-white">
                Next-Gen <span class="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">Cloud Security Firewall</span>
            </h1>
            <p class="text-slate-400 max-w-2xl mx-auto text-base">
                Protecting your web assets, client website links, and proxies from sophisticated SQLi and XSS injection attacks in real-time.
            </p>
        </section>

        <!-- Subscription Plans Section -->
        <section id="plans" class="max-w-6xl mx-auto px-6 py-16">
            <h2 class="text-2xl font-bold text-center mb-10 text-white">Subscription & Protection Plans</h2>
            <div class="grid md:grid-cols-3 gap-8">
                <!-- Basic Plan -->
                <div class="bg-slate-900 border border-slate-800 p-8 rounded-2xl space-y-6">
                    <h3 class="text-lg font-bold text-slate-200">Standard</h3>
                    <p class="text-3xl font-extrabold text-cyan-400">$29<span class="text-xs text-slate-400 font-normal">/month</span></p>
                    <ul class="space-y-3 text-xs text-slate-300">
                        <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i>Basic URL Filtering</li>
                        <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i>Single Domain Protection</li>
                        <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i>Standard Rate Limiting</li>
                    </ul>
                    <a href="/client/login" class="block text-center bg-slate-800 hover:bg-slate-700 text-white font-bold py-2.5 rounded-xl text-xs transition">Get Started</a>
                </div>
                <!-- Enterprise Plan -->
                <div class="bg-slate-900 border border-cyan-500/50 p-8 rounded-2xl space-y-6 relative shadow-2xl shadow-cyan-500/10">
                    <span class="absolute -top-3 right-6 bg-cyan-500 text-slate-950 font-bold px-3 py-0.5 rounded-full text-[10px]">POPULAR</span>
                    <h3 class="text-lg font-bold text-white">Enterprise</h3>
                    <p class="text-3xl font-extrabold text-cyan-400">$99<span class="text-xs text-slate-400 font-normal">/month</span></p>
                    <ul class="space-y-3 text-xs text-slate-300">
                        <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i>Multi-Layer Deep Inspection</li>
                        <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i>Unlimited Website Links</li>
                        <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i>Instant IP Ban System</li>
                    </ul>
                    <a href="/client/login" class="block text-center bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold py-2.5 rounded-xl text-xs transition">Deploy Now</a>
                </div>
                <!-- Ultimate Plan -->
                <div class="bg-slate-900 border border-slate-800 p-8 rounded-2xl space-y-6">
                    <h3 class="text-lg font-bold text-slate-200">Custom Shield</h3>
                    <p class="text-3xl font-extrabold text-cyan-400">Custom</p>
                    <ul class="space-y-3 text-xs text-slate-300">
                        <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i>Dedicated Firewall Node</li>
                        <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i>Custom WAF Rules</li>
                        <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i>24/7 Priority Support</li>
                    </ul>
                    <a href="/client/login" class="block text-center bg-slate-800 hover:bg-slate-700 text-white font-bold py-2.5 rounded-xl text-xs transition">Contact Sales</a>
                </div>
            </div>
        </section>

        <!-- Footer with Social Media Links -->
        <footer class="border-t border-slate-800 mt-20 py-10 bg-slate-900/35">
            <div class="max-w-6xl mx-auto px-6 flex flex-col md:flex-row justify-between items-center space-y-4 md:space-y-0">
                <p class="text-xs text-slate-500">&copy; 2026 Aegis Security Core. All rights reserved.</p>
                <div class="flex space-x-6 text-slate-400">
                    <a href="https://github.com" target="_blank" class="hover:text-cyan-400 transition"><i class="fa-brands fa-github text-lg"></i></a>
                    <a href="https://twitter.com" target="_blank" class="hover:text-cyan-400 transition"><i class="fa-brands fa-twitter text-lg"></i></a>
                    <a href="https://discord.com" target="_blank" class="hover:text-cyan-400 transition"><i class="fa-brands fa-discord text-lg"></i></a>
                    <a href="https://linkedin.com" target="_blank" class="hover:text-cyan-400 transition"><i class="fa-brands fa-linkedin text-lg"></i></a>
                </div>
            </div>
        </footer>
    </body>
    </html>
    """)

# --- Admin Login & Dashboard ---
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
            error = "Invalid Credentials"
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 flex items-center justify-center h-screen">
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl w-96 space-y-4">
            <h2 class="text-xl font-bold text-cyan-400 text-center">Admin Portal</h2>
            {% if error %}<p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>{% endif %}
            <input type="text" name="username" placeholder="Username or Email" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <button type="submit" class="w-full bg-cyan-500 text-slate-950 font-bold p-3 rounded text-sm">Login</button>
        </form>
    </body></html>
    """, error=error)

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'): return redirect(url_for('my_profile'))
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 p-8">
        <h1 class="text-2xl font-bold text-cyan-400">Admin Dashboard - Active</h1>
        <a href="/my-profile?logout=true" class="text-xs text-red-400 underline">Logout</a>
    </body></html>
    """)

# --- Client Portal & Website Links Management ---
@app.route('/client/login', methods=['GET', 'POST'])
def client_login():
    error = None
    if request.method == 'POST':
        identity = request.form.get('identity')
        password = request.form.get('password')
        client = next((c for c in CUSTOMERS_DB if (c['username'] == identity or c['email'] == identity) and c['password'] == password), None)
        if client:
            session['client_username'] = client['username']
            return redirect(url_for('client_dashboard'))
        else:
            error = "Invalid Credentials"
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 flex items-center justify-center h-screen">
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl w-96 space-y-4">
            <h2 class="text-xl font-bold text-cyan-400 text-center">Client Portal Login</h2>
            {% if error %}<p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>{% endif %}
            <input type="text" name="identity" placeholder="Username or Email" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <button type="submit" class="w-full bg-cyan-500 text-slate-950 font-bold p-3 rounded text-sm">Login</button>
        </form>
    </body></html>
    """, error=error)

@app.route('/client/dashboard')
def client_dashboard():
    username = session.get('client_username')
    if not username: return redirect(url_for('client_login'))
    current_client = next((c for c in CUSTOMERS_DB if c['username'] == username), None)
    
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 p-8 space-y-6">
        <div class="flex justify-between items-center border-b border-slate-800 pb-4">
            <h1 class="text-xl font-bold text-cyan-400">Client Portal - Website Links & Protection</h1>
            <a href="/client/logout" class="text-xs text-red-400 underline">Logout</a>
        </div>
        <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
            <h2 class="text-sm font-bold text-white">Protected Website Links (Proxy Targets)</h2>
            <p class="text-xs text-slate-400">Your registered website links are secured under Aegis WAF. Any payload injection on these links will be blocked instantly.</p>
            <div class="space-y-2">
                {% for domain in client.domains %}
                <div class="bg-slate-950 border border-slate-800 p-3 rounded text-xs flex justify-between items-center">
                    <span class="text-cyan-400 font-mono">https://{{ domain }}</span>
                    <span class="bg-emerald-500/10 text-emerald-400 px-2 py-1 rounded text-[10px]">Protected by WAF</span>
                </div>
                {% endfor %}
            </div>
        </div>
    </body></html>
    """, client=current_client)

@app.route('/client/logout')
def client_logout():
    session.pop('client_username', None)
    return redirect(url_for('client_login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
