from flask import Flask, jsonify
from firewall_core import aegis_firewall_middleware

app = Flask(__name__)

# মিডলওয়্যার যুক্ত করা
app.before_request(aegis_firewall_middleware)

@app.route('/')
def index():
    return jsonify({
        "service": "Aegis Core Enterprise Firewall",
        "status": "Operational",
        "security": "Active WAF Protection"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
