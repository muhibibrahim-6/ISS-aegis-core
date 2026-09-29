from flask import request, jsonify
import time
import re
from collections import defaultdict

# ট্র্যাকিং ডিকশনারি
request_history = defaultdict(list)
BLOCKED_IPS = set()
blocked_until = {}

MAX_REQUESTS_PER_MINUTE = 40
BLOCK_DURATION = 300  # ৫ মিনিট ব্লক

# SQL Injection এবং XSS শনাক্ত করার প্যাটার্নসমূহ
SQLI_PATTERNS = [
    r"(\%27)|(\')",
    r"(\%23)|(#)",
    r"(union\s+select)",
    r"(or\s+1\s*=\s*1)",
    r"(drop\s+table)",
    r"(exec\s*\()",
]

XSS_PATTERNS = [
    r"<script[^>]*>[\s\S]*?</script>",
    r"javascript\s*:",
    r"onerror\s*=",
    r"onload\s*=",
]

def check_malicious_payload(data_string):
    if not data_string:
        return False
    
    data_lower = str(data_string).lower()
    
    # SQL Injection চেক
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, data_lower, re.IGNORECASE):
            return "SQL Injection Attempt Detected"
            
    # XSS চেক
    for pattern in XSS_PATTERNS:
        if re.search(pattern, data_lower, re.IGNORECASE):
            return "XSS (Cross-Site Scripting) Attempt Detected"
            
    return None

def aegis_advanced_firewall():
    client_ip = request.remote_addr
    current_time = time.time()
    
    # ১. আইপি ব্লকলিস্ট স্ট্যাটাস চেক
    if client_ip in BLOCKED_IPS:
        if current_time < blocked_until.get(client_ip, 0):
            return jsonify({
                "error": "Access Denied by Aegis Core WAF",
                "reason": "IP is temporarily blocked due to security violations.",
                "ip": client_ip
            }), 403
        else:
            BLOCKED_IPS.remove(client_ip)
            del blocked_until[client_ip]

    # ২. রিকোয়েস্ট প্যারামিটার বা পে-লোড ইনস্পেকশন (WAF Core)
    full_path_and_args = request.full_path
    req_body = ""
    
    if request.method in ['POST', 'PUT', 'PATCH']:
        if request.is_json:
            req_body = str(request.get_json(silent=True))
        else:
            req_body = str(request.form.to_dict())

    # পে-লোডে ক্ষতিকর প্যাটার্ন আছে কি না যাচাই
    threat_reason = check_malicious_payload(full_path_and_args) or check_malicious_payload(req_body)
    
    if threat_reason:
        BLOCKED_IPS.add(client_ip)
        blocked_until[client_ip] = current_time + BLOCK_DURATION
        return jsonify({
            "error": "Web Application Firewall (WAF) Triggered",
            "reason": threat_reason,
            "action": "IP Blocked"
        }), 403

    # ৩. স্ক্যানার ইউজার-এজেন্ট চেক
    user_agent = request.headers.get('User-Agent', '').lower()
    suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'burpsuite', 'acunetix', 'scanner']
    for agent in suspicious_agents:
        if agent in user_agent:
            BLOCKED_IPS.add(client_ip)
            blocked_until[client_ip] = current_time + BLOCK_DURATION
            return jsonify({
                "error": "Security Alert",
                "reason": f"Automated scanner signature detected: {agent}"
            }), 403

    # ৪. রেট লিমিটিং ও ফ্লাডিং প্রটেকশন
    request_history[client_ip] = [t for t in request_history[client_ip] if current_time - t < 60]
    request_history[client_ip].append(current_time)

    if len(request_history[client_ip]) > MAX_REQUESTS_PER_MINUTE:
        BLOCKED_IPS.add(client_ip)
        blocked_until[client_ip] = current_time + BLOCK_DURATION
        return jsonify({
            "error": "Rate Limit Exceeded",
            "reason": "Too many requests. Temporary IP ban enforced."
        }), 429
