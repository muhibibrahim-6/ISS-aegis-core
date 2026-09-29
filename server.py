from flask import Flask, request, jsonify
from advanced_firewall import aegis_advanced_firewall

app = Flask(__name__)

# Aegis Core WAF Middleware সক্রিয় করা
app.before_request(aegis_advanced_firewall)

@app.route('/')
def firewall_home():
    return jsonify({
        "product": "Aegis Core Firewall & WAF",
        "organization": "International System Security (ISS)",
        "status": "Active & Protecting",
        "version": "1.0.0"
    })

@app.route('/api/protect', methods=['POST'])
def protect_endpoint():
    # এটি ক্লায়েন্টদের অ্যাপ্লিকেশনের প্রটেকশন এপিআই এন্ডপয়েন্ট হতে পারে
    data = request.get_json(silent=True) or request.form.to_dict()
    return jsonify({
        "status": "secure",
        "message": "Payload verified and passed safely through Aegis Core WAF.",
        "data": data
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
