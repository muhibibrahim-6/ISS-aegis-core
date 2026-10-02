import os
import time
import re
import requests
from flask import Flask, jsonify, request, render_template_string
from datetime import datetime

app = Flask(__name__)

# আপনার ডিসকর্ড ওয়েহুক ইউআরএল
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1555088247137509379/YruglLjphIlnSc1718YSWF7mJnEiDJ-Zzc_7Gq01BTjX4LxFxCFZbCIKrv5A4dXAmkIP"

# স্ট্রাইক এবং ব্লক ট্র্যাকিং ডিকশনারি
strike_records = {}
blocked_ips = {}
MAX_STRIKES = 4  # ৪ বার অ্যাটাক করলে ব্লক হবে
BLOCK_TIME = 1800  # ৩০ মিনিট (সেকেন্ডে)

def send_discord_alert(client_ip, threat_type, strikes):
    if not DISCORD_WEBHOOK_URL:
        return
    payload = {
        "embeds": [{
            "title": "🚨 Aegis WAF - IP Blocked Due to Repeated Attacks",
            "color": 16711680,
            "fields": [
                {"name": "🛡️ Threat Type", "value": threat_type, "inline": True},
                {"name": "🌐 Attacker IP", "value": client_ip, "inline": True},
                {"name": "⚠️ Total Strikes", "value": f"{strikes} / {MAX_STRIKES}", "inline": True},
                {"name": "⚡ Action", "value": "IP Blocked for 30 Minutes", "inline": False}
            ],
            "timestamp": datetime.utcnow().isoformat()
        }]
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=3)
    except Exception:
        pass

@app.before_request
def waf_protection():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    
    # স্ট্যাটিক ফাইল বা ব্রাউজারের আইকন রিকোয়েস্ট ইগনোর করার জন্য
    if 'favicon.ico' in request.path:
        return

    # চেক করা আইপি অলরেডি ব্লকড কি না
    if client_ip in blocked_ips:
        if current_time < blocked_ips[client_ip]:
            return jsonify({
                "error": "Aegis WAF - Access Denied",
                "message": "Your IP is blocked for 30 minutes due to repeated malicious requests."
            }), 403
        else:
            del blocked_ips[client_ip]
            if client_ip in strike_records:
                del strike_records[client_ip]

    # পুরো রিকোয়েস্ট ইউআরএল এবং প্যারামিটার চেক করা
    full_url = request.full_path
    
    # SQL Injection বা XSS প্যাটার্ন চেক
    is_threat = False
    threat_name = ""
    
    if re.search(r"union\s+select|or\s+1\s*=\s*1|drop\s+table|--|#", full_url, re.IGNORECASE):
        is_threat = True
        threat_name = "SQL Injection (SQLi)"
    elif re.search(r"<script.*?>.*?</script>|javascript:|onerror=", full_url, re.IGNORECASE):
        is_threat = True
        threat_name = "Cross-Site Scripting (XSS)"

    if is_threat:
        if client_ip not in strike_records:
            strike_records[client_ip] = 0
        
        strike_records[client_ip] += 1
        current_strikes = strike_records[client_ip]
        
        if current_strikes >= MAX_STRIKES:
            blocked_ips[client_ip] = current_time + BLOCK_TIME
            send_discord_alert(client_ip, threat_name, current_strikes)
            return jsonify({
                "error": "Web Application Firewall Triggered",
                "threat_detected": threat_name,
                "strikes": f"{current_strikes}/{MAX_STRIKES}",
                "action": "IP Blocked for 30 Minutes!"
            }), 403
        else:
            return jsonify({
                "warning": "Aegis WAF - Suspicious Activity Detected",
                "threat_detected": threat_name,
                "strikes_count": f"{current_strikes}/{MAX_STRIKES}",
                "message": f"Warning! {MAX_STRIKES - current_strikes} more attempts will result in a 30-minute IP block."
            }), 400

@app.route('/')
def home():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Aegis WAF Protected Site</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-white flex flex-col items-center justify-center h-screen space-y-4">
        <h1 class="text-3xl font-bold text-cyan-400">Aegis WAF is Active 🛡️</h1>
        <p class="text-sm text-slate-400">This site is protected against SQLi and XSS attacks with Strike-based IP Blocking.</p>
    </body>
    </html>
    """)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
