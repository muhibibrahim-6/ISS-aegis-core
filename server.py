import os
import time
import re
import requests
from urllib.parse import unquote
from flask import Flask, jsonify, request, render_template_string, Response, redirect, url_for, session
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "aegis_complete_bot_api_2026")

# আপনার ডিসকর্ড ওয়েহুক ইউআরএল
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1555750516338856006/-riimewpBbXexc7WKO_2bl-7JCIDOsQTIORvEUs1dTNRqpi6A97ClD-D4rw73DGQITwR"

def send_discord_alert(threat_type, client_ip, path, license_key):
    if not DISCORD_WEBHOOK_URL:
        return
    payload = {
        "embeds": [{
            "title": "🚨 Aegis WAF - Threat Blocked & Logged",
            "color": 16711680,
            "fields": [
                {"name": "🛡️ Threat / Payload", "value": str(threat_type), "inline": True},
                {"name": "🌐 Attacker IP", "value": str(client_ip), "inline": True},
                {"name": "🔑 Client License Key", "value": f"`{license_key}`", "inline": False},
                {"name": "📂 Target Website / Path", "value": str(path), "inline": False},
                {"name": "⏱ Time", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "inline": False}
            ]
        }]
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
    except Exception:
        pass

# নতুন এপিআই কি তৈরি হওয়ার সাথে সাথে ডিসকর্ডে শুধু এপিআই কি পাঠানোর ফাংশন
def send_discord_new_apikey(api_key):
    if not DISCORD_WEBHOOK_URL:
        return
    payload = {
        "content": f"🔑 **New API Key Generated:** `{api_key}`"
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
    except Exception:
        pass

# স্ট্রাইক, ব্লক এবং থ্রেট লগ ট্র্যাকিং ডিকশনারি
strike_records = {}
blocked_ips = {}
THREAT_LOGS = [] 
MAX_STRIKES = 4  
BLOCK_TIME = 1800  # ৩০ মিনিট

# ক্লায়েন্ট ডাটাবেজ
CUSTOMERS_DB = [
    {
        "api_key": "aegis_live_key_999",
        "username": "ibr@him",
        "email": "admin@firewall.com",
        "password": "muhib5869@",
        "client_name": "My Main Server",
        "urls": ["https://iss-antivirus-cloud.onrender.com"],
        "plan": "Enterprise",
        "origin_ip": "https://iss-antivirus-cloud.onrender.com",
        "expiry_date": "2027-12-31"
    }
]

ADMIN_USER = "ibr@him"
ADMIN_EMAIL = "admin@firewall.com"
ADMIN_PASS = "muhib5869@"

# --- ফায়ারওয়াল ইনসপেকশন ও লগ সেভিং ---
@app.before_request
def firewall_inspection():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    
    if request.path.startswith('/admin') or request.path.startswith('/client') or request.path == '/my-profile' or request.path.startswith('/api/'):
        return

    if client_ip in blocked_ips:
        if current_time < blocked_ips[client_ip]:
            return jsonify({"error": "Aegis WAF - IP Banned due to security violations."}), 403
        else:
            del blocked_ips[client_ip]
            if client_ip in strike_records:
                del strike_records[client_ip]

    target_param = request.args.get('target', '').lower()
    host_header = request.host.lower()
    
    matched_license_key = "aegis_live_key_999"
    is_protected_target = False

    for client in CUSTOMERS_DB:
        for u in client.get('urls', []):
            clean_u = u.lower().replace('https://', '').replace('http://', '').strip('/')
            if clean_u in host_header or clean_u in target_param or host_header in clean_u:
                matched_license_key = client['api_key']
                is_protected_target = True
                break
        if is_protected_target:
            break

    raw_full_path = request.full_path
    decoded_url = unquote(raw_full_path)
    body_content = ""
    try:
        body_content = unquote(request.get_data(as_text=True))
    except Exception:
        pass

    inspection_target = f"{decoded_url} {body_content}"

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
        
        log_entry = {
            "license_key": matched_license_key,
            "threat_type": threat_name,
            "attacker_ip": client_ip,
            "path": decoded_url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        THREAT_LOGS.append(log_entry)

        send_discord_alert(threat_name, client_ip, decoded_url, matched_license_key)

        if current_strikes >= MAX_STRIKES:
            blocked_ips[client_ip] = current_time + BLOCK_TIME
            return jsonify({"error": "Aegis WAF - IP Banned for 30 minutes!"}), 403
        else:
            return jsonify({"error": "Aegis WAF - Malicious Payload Blocked", "threat": threat_name, "license_key": matched_license_key}), 400

# --- Discord Bot API Endpoints ---
@app.route('/api/report', methods=['GET'])
def api_report():
    license_key = request.args.get('license_key', '').strip()
    if not license_key:
        return jsonify({"error": "License key required"}), 400
    
    client = next((c for c in CUSTOMERS_DB if c['api_key'] == license_key), None)
    if not client:
        return jsonify({"error": "Invalid License Key"}), 404

    client_logs = [log for log in THREAT_LOGS if log['license_key'] == license_key]
    return jsonify({
        "client_name": client['client_name'],
        "license_key": license_key,
        "recent_threats": client_logs[-5:]
    })

@app.route('/api/weekly_report', methods=['GET'])
def api_weekly_report():
    license_key = request.args.get('license_key', '').strip()
    if not license_key:
        return jsonify({"error": "License key required"}), 400
    
    client = next((c for c in CUSTOMERS_DB if c['api_key'] == license_key), None)
    if not client:
        return jsonify({"error": "Invalid License Key"}), 404

    client_logs = [log for log in THREAT_LOGS if log['license_key'] == license_key]
    return jsonify({
        "client_name": client['client_name'],
        "license_key": license_key,
        "total_threats_this_week": len(client_logs),
        "all_threats": client_logs
    })

# --- Reverse Proxy Route ---
@app.route('/proxy', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def reverse_proxy():
    target = request.args.get('target', '').strip('/')
    if not target:
        return jsonify({"error": "Invalid Proxy URL Format"}), 400
        
    matched_client = None
    for c in CUSTOMERS_DB:
        for u in c.get('urls', []):
            clean_u = u.lower().replace('https://', '').replace('http://', '').strip('/')
            if clean_u in target.lower():
                matched_client = c
                break
        if matched_client:
            break

    if not matched_client:
        return jsonify({"error": "Target Website URL Not Registered"}), 404
        
    origin_url = matched_client['origin_ip']
    try:
        req_headers = {key: value for (key, value) in request.headers if key.lower() not in ['host', 'accept-encoding']}
        resp = requests.request(
            method=request.method,
            url=f"{origin_url.rstrip('/')}/{target.split('/', 1)[1] if '/' in target else ''}",
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
    <head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 font-sans p-10 text-center space-y-4">
        <h1 class="text-3xl font-bold text-cyan-400">Aegis Core WAF & API Server Active</h1>
        <p class="text-sm text-slate-400">Connected with Discord Bot API Endpoints & Auto API Key Notifier</p>
        <div>
            <a href="/client/login" class="bg-cyan-500 text-slate-950 px-4 py-2 rounded text-xs font-bold">Client Login</a>
            <a href="/my-profile" class="bg-slate-800 text-cyan-400 px-4 py-2 rounded text-xs font-bold ml-2">Admin Portal</a>
        </div>
    </body>
    </html>
    """)

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
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl w-96 space-y-4 shadow-2xl">
            <h2 class="text-xl font-bold text-cyan-400 text-center">Admin Portal</h2>
            {% if error %}<p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>{% endif %}
            <input type="text" name="username" placeholder="Username" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <button type="submit" class="w-full bg-cyan-500 text-slate-950 font-bold p-3 rounded text-sm">Login</button>
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
                new_api_key = request.form.get('api_key')
                new_client = {
                    "api_key": new_api_key,
                    "username": request.form.get('username'),
                    "email": request.form.get('email'),
                    "password": request.form.get('password'),
                    "client_name": request.form.get('client_name'),
                    "urls": [request.form.get('url')] if request.form.get('url') else [],
                    "plan": request.form.get('plan'),
                    "origin_ip": request.form.get('origin_ip'),
                    "expiry_date": request.form.get('expiry_date')
                }
                CUSTOMERS_DB.append(new_client)
                
                # নতুন এপিআই তৈরি হওয়ার সাথে সাথে ডিসকর্ডে শুধু এপিআই কি পাঠানো
                send_discord_new_apikey(new_api_key)
                
                success_msg = "Client created and API Key sent to Discord!"
            except Exception:
                pass

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 p-6 space-y-6">
        <nav class="border-b border-slate-800 bg-slate-900 px-6 py-4 flex justify-between items-center rounded-xl">
            <h1 class="font-bold text-cyan-400">ADMIN DASHBOARD</h1>
            <a href="/my-profile?logout=true" class="text-xs text-red-400">Logout</a>
        </nav>
        <main class="max-w-6xl mx-auto space-y-6">
            {% if success_msg %}<div class="bg-emerald-500/10 text-emerald-400 p-3 rounded text-xs">{{ success_msg }}</div>{% endif %}
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <h2 class="text-sm font-bold text-cyan-400">Add New Client License</h2>
                <form method="POST" class="grid grid-cols-1 md:grid-cols-4 gap-3">
                    <input type="hidden" name="action" value="create">
                    <input type="text" name="client_name" placeholder="Server Name" required class="bg-slate-950 border border-slate-800 p-2 rounded text-xs">
                    <input type="text" name="username" placeholder="Username" required class="bg-slate-950 border border-slate-800 p-2 rounded text-xs">
                    <input type="email" name="email" placeholder="Email" required class="bg-slate-950 border border-slate-800 p-2 rounded text-xs">
                    <input type="password" name="password" placeholder="Password" required class="bg-slate-950 border border-slate-800 p-2 rounded text-xs">
                    <input type="text" name="url" placeholder="Website Link" required class="bg-slate-950 border border-slate-800 p-2 rounded text-xs">
                    <input type="text" name="api_key" placeholder="API Key (Unique)" required class="bg-slate-950 border border-slate-800 p-2 rounded text-xs">
                    <input type="text" name="origin_ip" placeholder="Origin URL" required class="bg-slate-950 border border-slate-800 p-2 rounded text-xs">
                    <input type="date" name="expiry_date" required class="bg-slate-950 border border-slate-800 p-2 rounded text-xs text-slate-200">
                    <select name="plan" class="bg-slate-950 border border-slate-800 p-2 rounded text-xs md:col-span-3">
                        <option value="Standard">Standard</option>
                        <option value="Professional">Professional</option>
                        <option value="Enterprise">Enterprise</option>
                        <option value="Unlimited">Unlimited</option>
                    </select>
                    <button type="submit" class="md:col-span-4 bg-cyan-500 text-slate-950 font-bold p-2.5 rounded text-xs">Create Client & Notify Discord</button>
                </form>
            </div>
        </main>
    </body></html>
    """, success_msg=success_msg)

@app.route('/client/login', methods=['GET', 'POST'])
def client_login():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 flex items-center justify-center h-screen">
        <div class="bg-slate-900 p-6 rounded text-center space-y-2">
            <h2 class="text-cyan-400 font-bold">Client Portal</h2>
            <a href="/" class="text-xs text-cyan-300 underline">Home</a>
        </div>
    </body></html>
    """)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
