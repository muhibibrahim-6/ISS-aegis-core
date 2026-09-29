from flask import Flask, jsonify
from firewall_core import aegis_firewall_middleware, SECURITY_LOGS

app = Flask(__name__)

# ফায়ারওয়াল মিডলওয়্যার যুক্ত করা
app.before_request(aegis_firewall_middleware)

@app.route('/')
def index():
    return jsonify({
        "service": "Aegis Core Enterprise WAF",
        "status": "Operational",
        "exclusive_features": [
            "Real-time AI Patch Advisor",
            "Advanced Forensic Logging",
            "Zero-Gated Basic Security"
        ]
    })

# ইউনিক ফিচার: লাইভ সিকিউরিটি ফরেনসিক ও এআই অ্যাডভাইজর লগ দেখার এন্ডপয়েন্ট
@app.route('/api/v1/security/logs', methods=['GET'])
def get_security_logs():
    return jsonify({
        "total_threats_intercepted": len(SECURITY_LOGS),
        "recent_forensic_logs": SECURITY_LOGS[:10]  # শেষ ১০টি থ্রেট লগ
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
