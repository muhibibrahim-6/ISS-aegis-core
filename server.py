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
            "title": "🚨 Aegis WAF - Security Threat Blocked!",
            "color": 16711680,
            "fields": [
                {"name": "🛡️ Threat Type", "value": str(threat_type), "inline": True},
                {"name": "🌐 Attacker IP", "value": str(client_ip), "inline": True},
                {"name": "📂 Target Path", "value": str(path), "inline": False},
                {"name": "⚡ Action Taken", "value": "IP Automatically Blocked for 10 Minutes", "inline": False}
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
BLOCK_DURATION = 600  # ১০ মিনিট (600 সেকেন্ড)

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
    
    # এডমিন বা লগইন পেজ বাদ দিয়ে বাকি সব জায়গায় সিকিউরিটি চেক হবে
    if path.startswith('/admin') or path.startswith('/client') or path == '/' or path == '/my-profile':
        return
        
    if client_ip in BLOCKED_IPS:
        if current_time < blocked_until.get(client_ip, 0):
            return jsonify({
                "error": "Access Denied by Aegis WAF",
                "reason": "Your IP has been blocked for 10 minutes due to a security violation."
            }), 403
        else:
            BLOCKED_IPS.remove(client_ip)
            del blocked_until[client_ip]

    req_payload = str(request.full_path) + " " + str(request.get_json(silent=True) or request.form.to_dict())
    threat_type = analyze_payload(req_payload)
    
    if threat_type:
        BLOCKED_IPS.add(client_ip)
        blocked_until[client_ip] = current_time + BLOCK_DURATION
        
        # ডিসকর্ডে অ্যালার্ট পাঠানো
        send_discord_alert(threat_type, client_ip, path)
        
        return jsonify({
            "error": "Web Application Firewall Triggered",
            "threat_detected": threat_type,
            "action": "IP Automatically Blocked for 10 Minutes"
        }), 403

# --- Landing Page (Home) ---
@app.route('/')
def landing_page():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Aegis Core - WAF</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 flex flex-col items-center justify-center h-screen">
        <h1 class="text-3xl font-bold text-cyan-400">AEGIS CORE WAF ACTIVE</h1>
        <p class="text-slate-400 text-sm mt-2">Protected against malicious attacks with 10-minute automatic IP blocking.</p>
    </body>
    </html>
    """)

@app.route('/my-profile', methods=['GET', 'POST'])
def my_profile():
    return "Admin Portal"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
