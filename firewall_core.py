from flask import request, jsonify
import time
import re
from collections import defaultdict

request_history = defaultdict(list)
BLOCKED_IPS = set()
blocked_until = {}

MAX_REQUESTS_PER_MINUTE = 50
BLOCK_DURATION = 300  # ৫ মিনিট

# সিকিউরিটি প্যাটার্নস (SQLi & XSS)
SQLI_PATTERNS = [r"union\s+select", r"or\s+1\s*=\s*1", r"drop\s+table", r"(\%27)|(\')"]
XSS_PATTERNS = [r"<script[^>]*>[\s\S]*?</script>", r"javascript\s*:", r"onerror\s*="]

def analyze_payload(text):
    if not text:
        return None
    text_lower = str(text).lower()
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return "SQL Injection Detected"
    for pattern in XSS_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return "XSS Attack Detected"
    return None

def aegis_firewall_middleware():
    client_ip = request.remote_addr
    current_time = time.time()
    
    # ১. ব্লক লিস্ট চেক
    if client_ip in BLOCKED_IPS:
        if current_time < blocked_until.get(client_ip, 0):
            return jsonify({"error": "Blocked by Aegis Core", "reason": "Temporary IP ban active"}), 403
        else:
            BLOCKED_IPS.remove(client_ip)
            del blocked_until[client_ip]

    # ২. পে-লোড ও রিকোয়েস্ট ইনস্পেকশন
    target_data = request.full_path + str(request.get_json(silent=True) or request.form.to_dict())
    threat = analyze_payload(target_data)
    
    if threat:
        BLOCKED_IPS.add(client_ip)
        blocked_until[client_ip] = current_time + BLOCK_DURATION
        return jsonify({"error": "WAF Blocked", "threat": threat}), 403

    # ৩. রেট লিমিটিং
    request_history[client_ip] = [t for t in request_history[client_ip] if current_time - t < 60]
    request_history[client_ip].append(current_time)
    
    if len(request_history[client_ip]) > MAX_REQUESTS_PER_MINUTE:
        BLOCKED_IPS.add(client_ip)
        blocked_until[client_ip] = current_time + BLOCK_DURATION
        return jsonify({"error": "Rate Limit Exceeded", "reason": "Too many requests"}), 429
