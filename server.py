import os
import time
import re
import requests
from flask import Flask, request, Response, jsonify

app = Flask(__name__)

# আপনার আসল বা মেইন সার্ভার/ওয়েবসাইটের লিংক এখানে বসিয়ে দিন 
# (অথবা রেন্ডার এনভায়রনমেন্ট ভেরিয়েবলে ORIGIN_SERVER_URL নামে দিতে পারেন)
ORIGIN_SERVER_URL = os.environ.get("ORIGIN_SERVER_URL", "https://your-actual-website.com")

# ক্ষতিকর আইপি ব্লক লিস্ট
BLOCKED_IPS = set()
blocked_until = {}
BLOCK_DURATION = 300  # ৫ মিনিটের জন্য ব্লক

# আক্রমণ শনাক্তকরণের প্যাটার্ন (SQLi এবং XSS)
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
def waf_security_check():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    
    # আইপি ব্লক চেক
    if client_ip in BLOCKED_IPS:
        if current_time < blocked_until.get(client_ip, 0):
            return jsonify({
                "error": "Access Denied by WAF",
                "reason": "Temporary IP ban due to security violation."
            }), 403
        else:
            BLOCKED_IPS.remove(client_ip)
            del blocked_until[client_ip]

    # রিকোয়েস্ট পেলোড চেক
    req_payload = str(request.full_path) + " " + str(request.get_json(silent=True) or request.form.to_dict())
    threat_type = analyze_payload(req_payload)
    
    if threat_type:
        BLOCKED_IPS.add(client_ip)
        blocked_until[client_ip] = current_time + BLOCK_DURATION
        return jsonify({
            "error": "Web Application Firewall Triggered",
            "threat_detected": threat_type,
            "action": "IP Blocked"
        }), 403

# সমস্ত রিকোয়েস্ট স্ক্যান করে অরিজিন সার্ভারে ফরোয়ার্ড করা
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy_to_origin(path):
    target_url = f"{ORIGIN_SERVER_URL.rstrip('/')}/{path}"
    
    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers={key: value for (key, value) in request.headers if key != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=15
        )
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        
        return Response(resp.content, resp.status_code, headers)
    except Exception as e:
        return jsonify({"error": "Origin Server Unreachable", "details": str(e)}), 502

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
