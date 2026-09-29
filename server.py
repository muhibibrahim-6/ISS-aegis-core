from flask import Flask, request, jsonify
from advanced_firewall import aegis_advanced_firewall

app = Flask(__name__)

# সার্ভারে যেকোনো রিকোয়েস্ট ঢোকার আগেই Aegis WAF ফায়ারওয়াল চেক করবে
app.before_request(aegis_advanced_firewall)

@app.route('/')
def home():
    return jsonify({
        "status": "online",
        "system": "ISS CyberDefense Suite",
        "protection": "Aegis Core WAF Active",
        "message": "Welcome to ISS-Sentinel & Aegis Core platform."
    })

@app.route('/login', methods=['POST'])
def login():
    # ইউজার ইনপুট বা ফর্ম ডাটা এখানে রিসিভ হবে এবং ফায়ারওয়াল তা প্রটেক্ট করবে
    data = request.get_json(silent=True) or request.form.to_dict()
    return jsonify({
        "status": "success",
        "message": "Request passed through Aegis Core WAF safely.",
        "received_data": data
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
