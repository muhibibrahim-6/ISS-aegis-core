from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify
import time
import requests

app = Flask(__name__)
app.secret_key = "your_secure_secret_key_here"  # আপনার সিক্রেট কি এখানে দিন

# --- Global Databases & Configurations ---
BLOCKED_IPS = set()
blocked_until = {}
BLOCK_DURATION = 300  # ৫ মিনিট ব্লক সময় (সেকেন্ডে)

# ডিসকর্ড ওয়েহুক ইউআরএল (আপনার ডিসকর্ড ওয়েহুক লিংকটি এখানে বসানো আছে)
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1346765582967277638/7x_U4N_YOUR_WEBHOOK_URL_HERE"

# কাস্টমার ডাটাবেস
CUSTOMERS_DB = [
    {
        "id": 1,
        "client_name": "রহিম উদ্দিন",
        "username": "rahim",
        "password": "123",
        "plan": "Standard",
        "expiry_date": "2026-12-31",
        "domains": ["example.com"],
        "api_key": "api_key_rahim_12345"
    },
    {
        "id": 2,
        "client_name": "করিম সাহেব",
        "username": "karim",
        "password": "123",
        "plan": "Professional",
        "expiry_date": "2027-06-30",
        "domains": ["mysite.com", "shop.net"],
        "api_key": "api_key_karim_67890"
    }
]

# --- Discord Alert Function ---
def send_discord_alert(threat_type, attacker_ip, target_path):
    if not DISCORD_WEBHOOK_URL or "YOUR_WEBHOOK_URL" in DISCORD_WEBHOOK_URL:
        return
    
    payload = {
        "embeds": [
            {
                "title": "🚨 Aegis WAF - Security Alert",
                "color": 15158332,  # লাল রঙ
                "fields": [
                    {"name": "Threat Type", "value": threat_type, "inline": True},
                    {"name": "Attacker IP", "value": attacker_ip, "inline": True},
                    {"name": "Target Path", "value": target_path, "inline": False},
                    {"name": "Action Taken", "value": "IP Temporarily Blocked (5 mins)", "inline": False}
                ],
                "footer": {"text": "ISS Antivirus Cloud Protection"}
            }
        ]
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=3)
    except Exception as e:
        print(f"Discord webhook error: {e}")

# --- Threat Analysis Engine ---
def analyze_payload(payload):
    payload_lower = payload.lower()
    
    # SQL Injection Patterns
    sql_keywords = ["union select", "or 1=1", "drop table", "exec(", "information_schema", "' or '1'='1"]
    for kw in sql_keywords:
        if kw in payload_lower:
            return "SQL Injection Attack"
            
    # XSS Attack Patterns
    xss_keywords = ["<script>", "javascript:", "onerror=", "onload="]
    for kw in xss_keywords:
        if kw in payload_lower:
            return "Cross-Site Scripting (XSS)"
            
    return None

# --- WAF Firewall Middleware ---
@app.before_request
def aegis_firewall_middleware():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    path = request.path
    
    # অ্যাডমিন বা নির্দিষ্ট কিছু পেজ ফায়ারওয়াল চেকের বাইরে রাখতে চাইলে
    if path.startswith('/admin') or path.startswith('/client') or path == '/my-profile' or path.startswith('/proxy/'):
        return
        
    # ব্লক করা আইপি চেক
    if client_ip in BLOCKED_IPS:
        if current_time < blocked_until.get(client_ip, 0):
            return jsonify({
                "error": "Access Denied by Aegis WAF",
                "reason": "Temporary IP ban due to security violation."
            }), 403
        else:
            BLOCKED_IPS.remove(client_ip)
            del blocked_until[client_ip]

    # কুয়েরি স্ট্রিং এবং পেলোড একসাথে স্ক্যান করা
    req_payload = str(request.full_path) + " " + str(request.args.to_dict()) + " " + str(request.get_json(silent=True) or request.form.to_dict())
    threat_type = analyze_payload(req_payload)
    
    if threat_type:
        BLOCKED_IPS.add(client_ip)
        blocked_until[client_ip] = current_time + BLOCK_DURATION
        
        # ডিসকর্ডে ইনস্ট্যান্ট অ্যালার্ট পাঠানো
        send_discord_alert(threat_type, client_ip, path)
        
        return jsonify({
            "error": "Web Application Firewall Triggered",
            "threat_detected": threat_type,
            "action": "IP Blocked"
        }), 403

# --- Public Home Route ---
@app.route('/')
def home():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>ISS Antivirus Cloud - WAF Protected</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 flex flex-col items-center justify-center min-h-screen">
        <div class="text-center space-y-4 p-8 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl max-w-lg">
            <h1 class="text-2xl font-bold text-cyan-400">ISS Antivirus Cloud WAF</h1>
            <p class="text-xs text-slate-400">System is active, secured and protected with advanced threat detection.</p>
            <div class="pt-4 flex justify-center space-x-4">
                <a href="/client/login" class="bg-cyan-500 hover:bg-cyan-400 text-slate-950 px-4 py-2 rounded text-xs font-bold transition">Client Login</a>
                <a href="/admin/login" class="bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-2 rounded text-xs font-bold transition">Admin Portal</a>
            </div>
        </div>
    </body>
    </html>
    """)

# --- Client Login Route ---
@app.route('/client/login', methods=['GET', 'POST'])
def client_login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        for c in CUSTOMERS_DB:
            if c['username'] == username and c['password'] == password:
                session['client_username'] = username
                return redirect(url_for('client_dashboard'))
        error = " ভুল ইউজারনেম অথবা পাসওয়ার্ড!"
        
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Client Login</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 flex items-center justify-center min-h-screen">
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-2xl w-96 space-y-4 shadow-xl">
            <h2 class="text-lg font-bold text-cyan-400 text-center">ক্লীয়েণ্ট লগইন</h2>
            {% if error %}<p class="text-xs text-red-400 text-center">{{ error }}</p>{% endif %}
            <div>
                <label class="text-xs text-slate-400">ইউজারনেম</label>
                <input type="text" name="username" required class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded text-xs text-slate-200 focus:outline-none focus:border-cyan-500 mt-1">
            </div>
            <div>
                <label class="text-xs text-slate-400">পাসওয়ার্ড</label>
                <input type="password" name="password" required class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded text-xs text-slate-200 focus:outline-none focus:border-cyan-500 mt-1">
            </div>
            <button type="submit" class="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold py-2.5 rounded text-xs transition">লগইন করুন</button>
        </form>
    </body>
    </html>
    """, error=error)

# --- Client Dashboard ---
@app.route('/client/dashboard', methods=['GET', 'POST'])
def client_dashboard():
    username = session.get('client_username')
    if not username:
        return redirect(url_for('client_login'))
    
    current_client = None
    for c in CUSTOMERS_DB:
        if c['username'] == username:
            current_client = c
            break
            
    if not current_client:
        return redirect(url_for('client_login'))

    success_msg = None
    limit_map = {"Standard": 1, "Professional": 5, "Enterprise": 10}
    max_slots = limit_map.get(current_client['plan'], 1)

    if request.method == 'POST':
        new_domains = []
        for i in range(max_slots):
            val = request.form.get(f'domain_{i}')
            if val and val.strip():
                new_domains.append(val.strip())
        current_client['domains'] = new_domains
        success_msg = "আপনার ডোমেন সফলভাবে আপডেট করা হয়েছে!"

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Client Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans p-6">
        <div class="max-w-2xl mx-auto space-y-6">
            <div class="flex justify-between items-center bg-slate-900 border border-slate-800 p-4 rounded-xl">
                <h1 class="text-sm font-bold text-cyan-400">স্বাগতম, {{ client.client_name }}</h1>
                <a href="/client/logout" class="text-xs text-red-400 hover:underline">লগআউট</a>
            </div>
            {% if success_msg %}
            <div class="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 p-3 rounded text-xs">{{ success_msg }}</div>
            {% endif %}
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <h2 class="text-sm font-bold text-cyan-400">ডোমেন ম্যানেজমেন্ট (প্ল্যান: {{ client.plan }})</h2>
                <form method="POST" class="space-y-4">
                    {% for i in range(max_slots) %}
                    <div>
                        <label class="text-[11px] text-slate-400">স্লট #{{ i + 1 }}</label>
                        <input type="text" name="domain_{{ i }}" value="{{ client.domains[i] if i < client.domains|length else '' }}" class="w-full bg-slate-950 border border-slate-800 p-2 rounded text-xs text-slate-200 mt-1">
                    </div>
                    {% endfor %}
                    <button type="submit" class="bg-cyan-500 text-slate-950 font-bold px-4 py-2 rounded text-xs">সেভ করুন</button>
                </form>
            </div>
        </div>
    </body>
    </html>
    """, client=current_client, max_slots=max_slots, success_msg=success_msg)

# --- Client Logout ---
@app.route('/client/logout')
def client_logout():
    session.pop('client_username', None)
    return redirect(url_for('client_login'))

# --- Admin Login & Dashboard (Basic placeholders) ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form.get('password') == 'admin123':
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
    return '<form method="POST"><input type="password" name="password" placeholder="Admin Password"><button type="submit">Login</button></form>'

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    return 'Admin Dashboard - All Clients Control Panel'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
