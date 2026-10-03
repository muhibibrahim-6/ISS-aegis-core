import os
import time
import re
import requests
from urllib.parse import unquote
from flask import Flask, jsonify, request, render_template_string, Response, redirect, url_for, session
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "aegis_bulletproof_production_2026")

# ডিসকর্ড ওয়েহুক ইউআরএল
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1555750516338856006/-riimewpBbXexc7WKO_2bl-7JCIDOsQTIORvEUs1dTNRqpi6A97ClD-D4rw73DGQITwR"

def send_discord_alert(threat_type, client_ip, path, license_key, action_taken):
    if not DISCORD_WEBHOOK_URL:
        return
    payload = {
        "embeds": [{
            "title": f"🚨 Aegis WAF Alert - [{action_taken}]",
            "color": 16711680 if "Banned" in action_taken else 16776960,
            "fields": [
                {"name": "🛡️ Threat Detected", "value": str(threat_type), "inline": True},
                {"name": "🌐 Attacker IP", "value": str(client_ip), "inline": True},
                {"name": "⚙️ Action Status", "value": str(action_taken), "inline": False},
                {"name": "🔑 License Key", "value": f"`{license_key}`", "inline": False},
                {"name": "📂 Target Path", "value": str(path), "inline": False},
                {"name": "⏱ Time", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "inline": False}
            ]
        }]
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
    except Exception:
        pass

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

# মেমোরি ডাটাবেজ ও ট্র্যাকিং
strike_records = {}
blocked_ips = {}
THREAT_LOGS = [] 
MAX_STRIKES = 4  # ৪ বার আক্রমণ হলে তবেই ব্লক
BLOCK_TIME = 1800  # ৩০ মিনিট

CUSTOMERS_DB = [
    {
        "api_key": "aegis_live_key_999",
        "username": "ibr@him",
        "email": "admin@firewall.com",
        "password": "muhib5869@",
        "client_name": "My Main Server",
        "urls": ["https://iss-antivirus-cloud.onrender.com"],
        "plan": "Unlimited",
        "origin_ip": "https://iss-antivirus-cloud.onrender.com",
        "expiry_date": "2027-12-31"
    }
]

ADMIN_USER = "ibr@him"
ADMIN_EMAIL = "admin@firewall.com"
ADMIN_PASS = "muhib5869@"

# --- ফায়ারওয়াল লজিক: শুরুতে ব্লক নয়, শুধু ডিসকর্ডে নোটিফিকেশন ---
@app.before_request
def firewall_inspection():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    
    if request.path.startswith('/admin') or request.path.startswith('/client') or request.path == '/my-profile' or request.path.startswith('/api/'):
        return

    if client_ip in blocked_ips:
        if current_time < blocked_ips[client_ip]:
            return jsonify({"error": "Aegis WAF - IP Banned due to repeated security violations."}), 403
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
    path_traversal = r"\.\./|\.\.\\"

    is_threat = False
    threat_name = ""

    if re.search(sqli_pattern, inspection_target, re.IGNORECASE):
        is_threat = True
        threat_name = "SQL Injection (SQLi)"
    elif re.search(xss_pattern, inspection_target, re.IGNORECASE):
        is_threat = True
        threat_name = "Cross-Site Scripting (XSS)"
    elif re.search(path_traversal, inspection_target, re.IGNORECASE):
        is_threat = True
        threat_name = "Path Traversal"

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

        if current_strikes >= MAX_STRIKES:
            blocked_ips[client_ip] = current_time + BLOCK_TIME
            send_discord_alert(threat_name, client_ip, decoded_url, matched_license_key, f"IP Banned ({current_strikes}/{MAX_STRIKES} Strikes)")
            return jsonify({"error": "Aegis WAF - IP Banned due to continuous attacks!"}), 403
        else:
            send_discord_alert(threat_name, client_ip, decoded_url, matched_license_key, f"Threat Logged (Strike {current_strikes}/{MAX_STRIKES}) - Allowed")
            return

# --- ডিসকর্ড বট এপিআই এন্ডপয়েন্ট ---
@app.route('/api/report', methods=['GET'])
def api_report():
    license_key = request.args.get('license_key', '').strip()
    if not license_key: return jsonify({"error": "License key required"}), 400
    client = next((c for c in CUSTOMERS_DB if c['api_key'] == license_key), None)
    if not client: return jsonify({"error": "Invalid License Key"}), 404

    client_logs = [log for log in THREAT_LOGS if log['license_key'] == license_key]
    return jsonify({
        "client_name": client['client_name'],
        "license_key": license_key,
        "recent_threats": client_logs[-5:]
    })

@app.route('/api/weekly_report', methods=['GET'])
def api_weekly_report():
    license_key = request.args.get('license_key', '').strip()
    if not license_key: return jsonify({"error": "License key required"}), 400
    client = next((c for c in CUSTOMERS_DB if c['api_key'] == license_key), None)
    if not client: return jsonify({"error": "Invalid License Key"}), 404

    client_logs = [log for log in THREAT_LOGS if log['license_key'] == license_key]
    return jsonify({
        "client_name": client['client_name'],
        "license_key": license_key,
        "total_threats_this_week": len(client_logs),
        "all_threats": client_logs
    })

# --- 랜딩 পেজ (সোশ্যাল লিংক ও ফুটারসহ) ---
@app.route('/')
def landing_page():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500 selection:text-slate-950">
        <nav class="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-8 py-4 flex justify-between items-center">
            <div class="flex items-center space-x-2"><i class="fa-solid fa-shield-cat text-cyan-400 text-xl"></i><span class="font-bold text-lg text-cyan-400">AEGIS CORE WAF</span></div>
            <div class="space-x-4">
                <a href="/client/login" class="text-xs text-slate-300 hover:text-cyan-400 font-medium">Client Login</a>
                <a href="/my-profile" class="bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 px-4 py-2 rounded text-xs font-bold">Admin Portal</a>
            </div>
        </nav>
        <header class="max-w-4xl mx-auto px-6 py-20 text-center space-y-6">
            <span class="bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs px-3 py-1 rounded-full uppercase tracking-widest font-semibold">Real-Time Notification & Protection</span>
            <h1 class="text-4xl md:text-6xl font-extrabold text-white">Next-Gen <span class="text-cyan-400">Security Firewall & Analytics</span></h1>
            <p class="text-slate-400 text-sm max-w-xl mx-auto">Automated Discord alerts, multi-tier protection plans, and client management system.</p>
        </header>

        <!-- ফুটার ও সোশ্যাল লিংক -->
        <footer class="border-t border-slate-800 bg-slate-900/50 py-8 text-center text-xs text-slate-400 space-y-4">
            <div class="flex justify-center space-x-6 text-lg">
                <a href="https://discord.com" target="_blank" class="hover:text-cyan-400"><i class="fa-brands fa-discord"></i></a>
                <a href="https://github.com" target="_blank" class="hover:text-cyan-400"><i class="fa-brands fa-github"></i></a>
                <a href="https://linkedin.com" target="_blank" class="hover:text-cyan-400"><i class="fa-brands fa-linkedin"></i></a>
            </div>
            <p>&copy; 2026 ISS Enterprise & Cloud Security. All rights reserved.</p>
        </footer>
    </body>
    </html>
    """)

# --- অ্যাডমিন পোর্টাল ---
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
        else: error = "Invalid Master Credentials"
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 flex items-center justify-center h-screen">
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl w-96 space-y-4 shadow-2xl">
            <h2 class="text-xl font-bold text-cyan-400 text-center">Admin Portal Login</h2>
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
    global CUSTOMERS_DB
    success_msg = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'delete':
            api_key = request.form.get('api_key')
            CUSTOMERS_DB = [c for c in CUSTOMERS_DB if c['api_key'] != api_key]
            success_msg = "Client deleted successfully!"
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
                send_discord_new_apikey(new_api_key)
                success_msg = "New client created and API key broadcasted to Discord!"
            except Exception: pass

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 p-6 space-y-6">
        <nav class="border-b border-slate-800 bg-slate-900 px-6 py-4 flex justify-between items-center rounded-xl">
            <h1 class="font-bold text-cyan-400">ADMIN CONTROL CENTER</h1>
            <a href="/my-profile?logout=true" class="text-xs text-red-400">Logout</a>
        </nav>
        <main class="max-w-6xl mx-auto space-y-6">
            {% if success_msg %}<div class="bg-emerald-500/10 text-emerald-400 p-3 rounded text-xs">{{ success_msg }}</div>{% endif %}
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <h2 class="text-sm font-bold text-cyan-400">Add New Client License Key & Select Plan</h2>
                <form method="POST" class="grid grid-cols-1 md:grid-cols-4 gap-3">
                    <input type="hidden" name="action" value="create">
                    <input type="text" name="client_name" placeholder="Client Name" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="username" placeholder="Username" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="email" name="email" placeholder="Email" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="password" name="password" placeholder="Password" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="url" placeholder="Protected Website Link" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="api_key" placeholder="Unique API / License Key" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="origin_ip" placeholder="Origin Server URL" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="date" name="expiry_date" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs text-slate-200">
                    
                    <!-- প্রিমিয়াম প্ল্যান সিলেকশন অপশন -->
                    <select name="plan" class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs md:col-span-3 text-cyan-300 font-semibold">
                        <option value="Standard">Standard Plan</option>
                        <option value="Professional">Professional Plan</option>
                        <option value="Enterprise">Enterprise Plan</option>
                        <option value="Unlimited">Unlimited / VIP Premium Plan</option>
                    </select>
                    <button type="submit" class="md:col-span-4 bg-cyan-500 text-slate-950 font-bold p-2.5 rounded text-xs">Generate & Notify Discord</button>
                </form>
            </div>
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <h2 class="text-sm font-bold text-cyan-400">Active Registered Clients</h2>
                <div class="space-y-2">
                    {% for client in customers %}
                    <div class="bg-slate-950 border border-slate-800 p-3 rounded-lg flex justify-between items-center text-xs">
                        <div>
                            <p class="font-bold text-white">{{ client.client_name }} (<span class="text-cyan-400">{{ client.username }}</span>)</p>
                            <p class="text-slate-400">URLs: {{ client.urls | join(', ') }} | Plan: <span class="text-yellow-400 font-bold">{{ client.plan }}</span> | Key: <code class="text-cyan-300">{{ client.api_key }}</code></p>
                        </div>
                        <form method="POST" onsubmit="return confirm('Delete this client?');">
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="api_key" value="{{ client.api_key }}">
                            <button type="submit" class="bg-red-500/10 text-red-400 px-3 py-1.5 rounded">Delete</button>
                        </form>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </main>
    </body></html>
    """, success_msg=success_msg, customers=CUSTOMERS_DB)

# --- ক্লায়েন্ট পোর্টাল ---
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
        else: error = "Invalid Credentials"
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 flex items-center justify-center h-screen">
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl w-96 space-y-4 shadow-2xl">
            <h2 class="text-xl font-bold text-cyan-400 text-center">Client Portal Login</h2>
            {% if error %}<p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>{% endif %}
            <input type="text" name="identity" placeholder="Username, Email or API Key" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <button type="submit" class="w-full bg-cyan-500 text-slate-950 font-bold p-3 rounded text-sm">Login</button>
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
    if request.method == 'POST':
        urls = request.form.getlist('website_urls')
        current_client['urls'] = [u.strip() for u in urls if u.strip()]
        success_msg = "Website URLs and Plan Settings updated successfully!"

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 p-6 space-y-6">
        <nav class="border-b border-slate-800 bg-slate-900 px-6 py-4 flex justify-between items-center rounded-xl">
            <h1 class="font-bold text-cyan-400">CLIENT DASHBOARD ({{ client.client_name }})</h1>
            <a href="/client/logout" class="text-xs text-red-400">Logout</a>
        </nav>
        <main class="max-w-4xl mx-auto space-y-6">
            {% if success_msg %}<div class="bg-emerald-500/10 text-emerald-400 p-3 rounded text-xs">{{ success_msg }}</div>{% endif %}
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <div class="flex justify-between items-center">
                    <h2 class="text-sm font-bold text-cyan-400">Active Subscription Plan: <span class="text-yellow-400">{{ client.plan }}</span></h2>
                    <span class="text-xs text-slate-400">Key: <code class="text-cyan-300 font-mono">{{ client.api_key }}</code></span>
                </div>
                <form method="POST" class="space-y-4">
                    <label class="text-xs text-slate-400 block">Protected Website URLs:</label>
                    {% for url in client.urls %}
                    <input type="text" name="website_urls" value="{{ url }}" required class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded text-xs text-slate-200">
                    {% endfor %}
                    <button type="submit" class="bg-cyan-500 text-slate-950 font-bold px-6 py-2 rounded text-xs">Save Changes</button>
                </form>
            </div>
        </main>
    </body></html>
    """, client=current_client, success_msg=success_msg)

@app.route('/client/logout')
def client_logout():
    session.pop('client_username', None)
    return redirect(url_for('client_login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
