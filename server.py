import os
import time
import re
import requests
from flask import Flask, jsonify, request, render_template_string, Response, redirect, url_for, session
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "aegis_super_secret_key_2026")

# আপনার ডিসকর্ড ওয়েহুক ইউআরএল
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1555088247137509379/YruglLjphIlnSc1718YSWF7mJnEiDJ-Zzc_7Gq01BTjX4LxFxCFZbCIKrv5A4dXAmkIP"

def send_discord_alert(threat_type, client_ip, path):
    if not DISCORD_WEBHOOK_URL or DISCORD_WEBHOOK_URL == "YOUR_DISCORD_WEBHOOK_URL_HERE":
        return
    
    payload = {
        "embeds": [{
            "title": "🚨 Aegis WAF - Advanced Security Threat Blocked!",
            "color": 16711680,
            "fields": [
                {"name": "🛡️ Threat Type", "value": str(threat_type), "inline": True},
                {"name": "🌐 Attacker IP", "value": str(client_ip), "inline": True},
                {"name": "📂 Target Path", "value": str(path), "inline": False},
                {"name": "⚡ Action Taken", "value": "IP Temporarily Blocked (5 Mins) & Logged", "inline": False}
            ],
            "timestamp": datetime.utcnow().isoformat()
        }]
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
    except Exception as e:
        print(f"Discord webhook error: {e}")

# মেমোরিতে ক্লায়েন্ট ডেটা সেভ করার জন্য লিস্ট
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

BLOCKED_IPS = set()
blocked_until = {}
BLOCK_DURATION = 300

# রেট লিমিটিং ট্র্যাকিং ডিকশনারি
request_counts = {}
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_ALLOWED = 100

# --- উন্নত ফায়ারওয়াল প্যাটার্ন লিস্ট (Advanced WAF Rules) ---
SQLI_PATTERNS = [
    (r"union\s+(all\s+)?select", "SQL Injection"),
    (r"or\s+1\s*=\s*1", "SQL Injection"),
    (r"drop\s+table", "SQL Injection"),
    (r"exec\s*\(", "SQL Injection"),
    (r"information_schema", "SQL Injection"),
    (r"(\%27)|(\')|(\-\-)|(\#)", "SQL Injection / Suspicious Char")
]

XSS_PATTERNS = [
    (r"<script[^>]*>[\s\S]*?</script>", "XSS Attack"),
    (r"javascript\s*:", "XSS Attack"),
    (r"onerror\s*=", "XSS Attack"),
    (r"onload\s*=", "XSS Attack"),
    (r"<img[^>]+src\s*=\s*[\"']?x[\"']?", "XSS Attack")
]

SUSPICIOUS_AGENTS = ["sqlmap", "nikto", "havij", "nmap", "masscan", "acunetix"]

def analyze_payload(text, user_agent=""):
    if not text:
        text = ""
    text_lower = str(text).lower()
    
    if user_agent:
        ua_lower = user_agent.lower()
        for bot in SUSPICIOUS_AGENTS:
            if bot in ua_lower:
                return f"Malicious Bot / Scanner ({bot.upper()})"

    for pattern, desc in SQLI_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return desc
            
    for pattern, desc in XSS_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return desc
            
    return None

# --- Aegis WAF Firewall Middleware ---
@app.before_request
def aegis_firewall_middleware():
    path = request.path
    
    # প্রক্সি রিকোয়েস্ট অথবা এডমিন/ক্লিনিক পেজ হলে WAF স্কিপ করবে
    if path.startswith('/proxy') or path.startswith('/admin') or path.startswith('/client') or path == '/' or path == '/my-profile':
        return

    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    user_agent = request.headers.get('User-Agent', '')
        
    if client_ip in BLOCKED_IPS:
        if current_time < blocked_until.get(client_ip, 0):
            return jsonify({
                "error": "Access Denied by Aegis WAF",
                "reason": "Temporary IP ban due to security violation."
            }), 403
        else:
            BLOCKED_IPS.remove(client_ip)
            if client_ip in blocked_until:
                del blocked_until[client_ip]

    if client_ip not in request_counts:
        request_counts[client_ip] = {"count": 1, "start_time": current_time}
    else:
        if current_time - request_counts[client_ip]["start_time"] < RATE_LIMIT_WINDOW:
            request_counts[client_ip]["count"] += 1
            if request_counts[client_ip]["count"] > MAX_REQUESTS_ALLOWED:
                BLOCKED_IPS.add(client_ip)
                blocked_until[client_ip] = current_time + BLOCK_DURATION
                send_discord_alert("Rate Limit Exceeded (DDoS / Flood)", client_ip, path)
                return jsonify({"error": "Aegis WAF - Rate Limit Exceeded. IP Blocked."}), 403
        else:
            request_counts[client_ip] = {"count": 1, "start_time": current_time}

    req_payload = str(request.full_path) + " " + str(request.args.to_dict()) + " " + str(request.get_json(silent=True) or request.form.to_dict())
    threat_type = analyze_payload(req_payload, user_agent)
    
    if threat_type:
        BLOCKED_IPS.add(client_ip)
        blocked_until[client_ip] = current_time + BLOCK_DURATION
        send_discord_alert(threat_type, client_ip, path)
        return jsonify({
            "error": "Web Application Firewall Triggered",
            "threat_detected": threat_type,
            "action": "IP Blocked"
        }), 403

# --- Reverse Proxy Route (Query Parameter Based & Bulletproof) ---
@app.route('/proxy', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def reverse_proxy():
    target = request.args.get('target', '').strip('/')
    if not target:
        return jsonify({"error": "Invalid Proxy URL Format. Use /proxy?target=domain.com/path"}), 400
        
    parts = target.split('/', 1)
    client_domain = parts[0]
    subpath = parts[1] if len(parts) > 1 else ""

    matched_client = None
    for c in CUSTOMERS_DB:
        if any(client_domain.lower() in d.lower() or d.lower() in client_domain.lower() for d in c['domains']):
            matched_client = c
            break

    if not matched_client:
        return jsonify({"error": f"Target Domain '{client_domain}' Not Registered in Aegis Core"}), 404
        
    expiry_date_str = matched_client.get('expiry_date')
    if expiry_date_str:
        try:
            expiry_date = datetime.strptime(expiry_date_str, "%Y-%m-%d")
            if datetime.now() > expiry_date:
                return jsonify({"error": "License Expired", "message": "This server's license has expired."}), 403
        except Exception:
            pass

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
        headers = [(name, value) for (name, value) in resp.raw.items() if name.lower() not in excluded_headers] if hasattr(resp.raw, 'items') else [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded_headers]
        
        return Response(resp.content, resp.status_code, headers)
    except Exception as e:
        return jsonify({"error": "Origin Server Unreachable", "details": str(e)}), 502

# --- Landing Page (Home) ---
@app.route('/')
def landing_page():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Aegis Core - Advanced Web Application Firewall</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500 selection:text-slate-950">
        <nav class="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-8 py-4 flex justify-between items-center">
            <div class="flex items-center space-x-2">
                <i class="fa-solid fa-shield-cat text-cyan-400 text-xl"></i>
                <span class="font-bold text-lg tracking-wider text-cyan-400">AEGIS CORE WAF</span>
            </div>
            <div class="space-x-4">
                <a href="/client/login" class="text-xs text-slate-300 hover:text-cyan-400 font-medium transition">Client Login</a>
                <a href="/my-profile" class="bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500 hover:text-slate-950 font-bold px-4 py-2 rounded text-xs transition">My Profile</a>
            </div>
        </nav>
        <header class="max-w-6xl mx-auto px-6 py-16 text-center space-y-6">
            <span class="bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs px-3 py-1 rounded-full uppercase tracking-widest font-semibold">Next-Gen Cybersecurity Protection</span>
            <h1 class="text-4xl md:text-6xl font-extrabold tracking-tight text-white">Ultimate Defense for Your <span class="text-cyan-400">Web Servers & Infrastructure</span></h1>
        </header>
        <footer class="border-t border-slate-800 py-6 text-center text-xs text-slate-500 mt-20">
            &copy; 2026 Aegis Core WAF Security System. All rights reserved.
        </footer>
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
        user_input = request.form.get('username')
        pass_input = request.form.get('password')
        if (user_input == ADMIN_USER or user_input == ADMIN_EMAIL) and pass_input == ADMIN_PASS:
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Invalid Master Credentials"

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Admin Login</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 flex flex-col items-center justify-center h-screen">
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl shadow-2xl w-96 space-y-4">
            <h2 class="text-xl font-bold text-cyan-400 text-center">Admin Portal</h2>
            {% if error %}
            <p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>
            {% endif %}
            <input type="text" name="username" placeholder="Username or Email" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <button type="submit" class="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold p-3 rounded text-sm">Login</button>
        </form>
    </body>
    </html>
    """, error=error)

@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('my_profile'))
    return "Admin Dashboard Active"

@app.route('/client/login', methods=['GET', 'POST'])
def client_login():
    return "Client Login Page"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
