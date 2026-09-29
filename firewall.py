from flask import request, jsonify, abort
import time
from collections import defaultdict

# ট্রাফিক ট্র্যাক করার জন্য স্টোরেজ (আইপি এবং তাদের রিকোয়েস্টের সময়)
request_history = defaultdict(list)
BLOCKED_IPS = set()

# ফায়ারওয়াল কনফিগারেশন
MAX_REQUESTS_PER_MINUTE = 30  # ১ মিনিটে সর্বোচ্চ কয়টি রিকোয়েস্ট করা যাবে
BLOCK_DURATION = 300          # ব্লক থাকার সময় (সেকেন্ডে, যেমন ৫ মিনিট)
blocked_until = {}            # কোন আইপি কতক্ষণ পর্যন্ত ব্লক থাকবে

def aegis_core_firewall():
    client_ip = request.remote_addr
    current_time = time.time()

    # ১. আইপি যদি অলরেডি ব্লকলিস্টে থাকে
    if client_ip in BLOCKED_IPS:
        # ব্লকের মেয়াদ শেষ হয়েছে কি না চেক করা
        if current_time < blocked_until.get(client_ip, 0):
            return jsonify({
                "error": "Access Denied by Aegis Core Firewall",
                "reason": "IP is temporarily blocked due to suspicious activity or rate-limit breach.",
                "ip": client_ip
            }), 403
        else:
            # মেয়াদ শেষ হলে আনব্লক করে দেওয়া
            BLOCKED_IPS.remove(client_ip)
            del blocked_until[client_ip]

    # ২. রেট লিমিটিং ও ডিডস (DDoS) প্রটেকশন চেক
    # পুরানো রিকোয়েস্টের রেকর্ড বাদ দেওয়া (গত ১ মিনিটের বেশি আগের)
    request_history[client_ip] = [t for t in request_history[client_ip] if current_time - t < 60]
    
    # নতুন রিকোয়েস্ট যোগ করা
    request_history[client_ip].append(current_time)

    # লিমিট ক্রস করলে আইপি ব্লক করে দেওয়া
    if len(request_history[client_ip]) > MAX_REQUESTS_PER_MINUTE:
        BLOCKED_IPS.add(client_ip)
        blocked_until[client_ip] = current_time + BLOCK_DURATION
        return jsonify({
            "error": "Rate Limit Exceeded",
            "reason": "Too many requests detected by Aegis Core. You have been blocked temporarily.",
            "retry_after_seconds": BLOCK_DURATION
        }), 429

    # ৩. সন্দেহজনক ইউজার এজেন্ট (User-Agent) বা স্ক্যানার ব্লক করা
    user_agent = request.headers.get('User-Agent', '').lower()
    suspicious_keywords = ['sqlmap', 'nikto', 'nmap', 'burpsuite', 'scanner']
    for keyword in suspicious_keywords:
        if keyword in user_agent:
            BLOCKED_IPS.add(client_ip)
            return jsonify({
                "error": "Threat Detected",
                "reason": "Malicious scanner signature identified by Aegis Core Firewall."
            }), 403
