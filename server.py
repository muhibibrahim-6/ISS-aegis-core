from flask import Flask, jsonify, render_template
from firewall_core import aegis_firewall_middleware, SECURITY_LOGS

app = Flask(__name__)

# ফায়ারওয়াল মিডলওয়্যার যুক্ত করা
app.before_request(aegis_firewall_middleware)

# ড্যাশবোর্ড ইউআই রুট
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

# সিকিউরিটি লগ এপিআই
@app.route('/api/v1/security/logs', methods=['GET'])
def get_security_logs():
    return jsonify({
        "total_threats_intercepted": len(SECURITY_LOGS),
        "recent_forensic_logs": SECURITY_LOGS[:15]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
