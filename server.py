import os
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
    # রেন্ডার বা ক্লাউড সার্ভারের ডাইনামিক পোর্ট ও লোকালের জন্য পোর্ট ৫০০০
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
