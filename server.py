import os
import time
import re
import requests
from urllib.parse import unquote
from flask import Flask, jsonify, request, render_template_string, Response, redirect, url_for, session
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "aegis_final_secret_2026")

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
        
        # ৪ থেকে ৫ বার হলে আইপি ব্লক এবং ওয়েবসাইট বা প্রক্সিতে ঢুকতে দেওয়া হবে না
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

# --- Landing Page with Client Portal Links ---
@app.route('/')
def landing_page():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Aegis Core - Final Firewall</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans">
        <nav class="border-b border-slate-800 bg-slate-900 px-8 py-4 flex justify-between items-center">
            <span class="font-bold text-cyan-400">AEGIS FIREWALL SYSTEM</span>
            <div class="space-x-4">
                <a href="/client/login" class="text-xs text-slate-300 hover:text-cyan-400">Client Portal & Website Links</a>
                <a href="/my-profile" class="bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 px-3 py-1.5 rounded text-xs">Admin</a>
            </div>
        </nav>
        <div class="max-w-4xl mx-auto px-6 py-20 text-center space-y-6">
            <h1 class="text-4xl font-extrabold text-white">Zero-Tolerance <span class="text-cyan-400">WAF Protection</span></h1>
            <p class="text-slate-400 text-sm">All payloads are blocked instantly at the gate. Website links are fully protected.</p>
        </div>
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
