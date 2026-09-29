from flask import request, jsonify
import time
import re
from collections import defaultdict

request_history = defaultdict(list)
BLOCKED_IPS = set()
blocked_until = {}
SECURITY_LOGS = []

MAX_REQUESTS_PER_MINUTE = 60
BLOCK_DURATION = 300  # ৫ মিনিট ব্লক

SQLI_PATTERNS = [
    (r"union\s+select", "SQL Injection (UNION based)"),
    (r"or\s+1\s*=\s*1", "SQL Injection (Boolean based tautology)"),
    (r"drop\s+table", "SQL Injection (Destructive DROP command)"),
    (r"(\%27)|(\')", "SQL Injection (Single quote anomaly)")
]

XSS_PATTERNS = [
    (r"<script[^>]*>[\s\S]*?</script>", "Cross-Site Scripting (Script tag injection)"),
    (r"javascript\s*:", "Cross-Site Scripting (JS pseudo-protocol)"),
    (r"onerror\s*=", "Cross-Site Scripting (Event handler injection)")
]

def generate_ai_patch_advice(threat_type):
    if "SQL Injection" in threat_type:
        return {
            "vulnerability": "SQL Injection",
            "risk_level": "CRITICAL",
            "developer_fix": "Use Parameterized Queries or ORM (like SQLAlchemy) instead of concatenating raw strings.",
            "secure_code_example": "cursor.execute('SELECT * FROM users WHERE username = %s', (username,))"
        }
    elif "Cross-Site Scripting" in threat_type:
        return {
            "vulnerability": "XSS (Cross-Site Scripting)",
            "risk_level": "HIGH",
            "developer_fix": "Always escape user inputs before rendering them in HTML templates.",
            "secure_code_example": "{{ user_input | escape }}"
        }
    return {
        "vulnerability": "General Web Attack",
        "risk_level": "MEDIUM",
        "developer_fix": "Ensure all input parameters are strictly validated."
    }

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

def aegis_firewall_middleware():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    path = request.path
    
    if client_ip in BLOCKED_IPS:
        if current_time < blocked_until.get(client_ip, 0):
            return jsonify({
                "error": "Access Denied by Aegis Core",
                "reason": "Temporary IP ban active due to security violation."
            }), 403
        else:
            BLOCKED_IPS.remove(client_ip)
            del blocked_until[client_ip]

    req_payload = str(request.get_json(silent=True) or request.form.to_dict())
    target_data = request.full_path + " " + req_payload
    
    threat_type = analyze_payload(target_data)
    
    if threat_type:
        BLOCKED_IPS.add(client_ip)
        blocked_until[client_ip] = current_time + BLOCK_DURATION
        patch_advice = generate_ai_patch_advice(threat_type)
        
        log_entry = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(current_time)),
            "ip": client_ip,
            "path": path,
            "threat": threat_type,
            "ai_patch_advisor": patch_advice
        }
        SECURITY_LOGS.insert(0, log_entry)
        
        return jsonify({
            "error": "Web Application Firewall Triggered",
            "threat_detected": threat_type,
            "action": "IP Blocked & Forensic Logged",
            "ai_developer_advisor": patch_advice
        }), 403

    request_history[client_ip] = [t for t in request_history[client_ip] if current_time - t < 60]
    request_history[client_ip].append(current_time)
    
    if len(request_history[client_ip]) > MAX_REQUESTS_PER_MINUTE:
        BLOCKED_IPS.add(client_ip)
        blocked_until[client_ip] = current_time + BLOCK_DURATION
        return jsonify({
            "error": "Rate Limit Exceeded",
            "reason": "Too many requests per minute."
        }), 429
