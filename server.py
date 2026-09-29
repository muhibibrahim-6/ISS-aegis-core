from flask import Flask
from firewall import aegis_core_firewall  # উপরের কোডটি আলাদা ফাইলে রাখলে

app = Flask(__name__)

# সার্ভারে প্রতিটা রিকোয়েস্ট আসার আগে ফায়ারওয়াল চেক করবে
app.before_request(def() {
    # ফায়ারওয়াল ফাংশন কল
    return aegis_core_firewall()
})

@app.route('/')
def home():
    return "Welcome to ISS CyberDefense Suite - Protected by Aegis Core Firewall!"

if __name__ == '__main__':
    app.run(debug=True)
