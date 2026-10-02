import os
import time
import re
import requests
from urllib.parse import unquote
from flask import Flask, jsonify, request, render_template_string, Response, redirect, url_for, session
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "aegis_connected_waf_2026")

# স্ট্রাইক এবং ব্লক ট্র্যাকিং
strike_records = {}
blocked_ips = {}
MAX_STRIKES = 4  
BLOCK_TIME = 1800  # ৩০ মিনিট

# রিয়েল ক্লায়েন্ট ডাটাবেজ (যেখানে আপনার ডোমেইনগুলো কানেক্টেড থাকবে)
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
    
    # অ্যাডমিন বা ক্লায়েন্ট লগইন পেজে ফায়ারওয়াল ব্লক করবে না (যাতে আপনি নিজে লকআউট না হন)
    if request.path.startswith('/admin') or request.path.startswith('/client') or request.path == '/my-profile':
        return

    # আইপি ব্লক স্ট্যাটাস চেক
    if client_ip in blocked_ips:
        if current_time < blocked_ips[client_ip]:
            return jsonify({
                "error": "Aegis WAF - IP Banned",
                "message": "Your IP has been blocked due to repeated payload injection attempts."
            }), 403
        else:
            del blocked_ips[client_ip]
            if client_ip in strike_records:
                del strike_records[client_ip]

    # এখানে চেক করা হচ্ছে রিকোয়েস্টটি আমাদের রেজিস্টার্ড ডোমেইনের সাথে মিলে কি না
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

    # যদি হোমপেজ বা সাধারণ রিকোয়েস্ট হয়, তবুও সিকিউরিটি স্ক্যান রান করবে
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
                "message": f"Payload detected on registered domain and blocked! {MAX_STRIKES - current_strikes} attempts left."
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

# --- Landing Page ---
@app.route('/')
def landing_page():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Aegis Core - Connected WAF</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500">
        <nav class="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-8 py-4 flex justify-between items-center">
            <div class="flex items-center space-x-2">
                <i class="fa-solid fa-shield-cat text-cyan-400 text-xl"></i>
                <span class="font-bold text-lg tracking-wider text-cyan-400">AEGIS CORE WAF (Connected)</span>
            </div>
            <div class="space-x-4">
                <a href="/client/login" class="text-xs text-slate-300 hover:text-cyan-400">Client Login</a>
                <a href="/my-profile" class="bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 px-4 py-2 rounded text-xs">Admin Portal</a>
            </div>
        </nav>
        <header class="max-w-4xl mx-auto px-6 py-20 text-center space-y-6">
            <span class="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs px-3 py-1 rounded-full">Firewall Database & WAF Engine Connected Successfully</span>
            <h1 class="text-4xl font-extrabold text-white">Real-Time Protection is Now Active</h1>
            <p class="text-slate-400 text-sm">Your database domains and security firewall are now fully linked together.</p>
        </header>
    </body>
    </html>
    """)

# --- Admin Portal ---
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
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl w-96 space-y-4">
            <h2 class="text-xl font-bold text-cyan-400 text-center">Admin Portal</h2>
            {% if error %}<p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>{% endif %}
            <input type="text" name="username" placeholder="Username or Email" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <button type="submit" class="w-full bg-cyan-500 text-slate-950 font-bold p-3 rounded text-sm">Login</button>
        </form>
    </body></html>
    """, error=error)

@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('is_admin'): return redirect(url_for('my_profile'))
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 p-8 space-y-6">
        <h1 class="text-xl font-bold text-cyan-400">Admin Dashboard - WAF Active & Connected</h1>
        <a href="/my-profile?logout=true" class="text-xs text-red-400 underline">Logout</a>
    </body></html>
    """)

@app.route('/client/login', methods=['GET', 'POST'])
def client_login():
    return "Client Login Page Active"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
