import os
import time
import re
import requests
from flask import Flask, jsonify, request, render_template_string, Response, redirect, url_for, session
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "aegis_super_secret_key_2026")

# আপনার ডিসকর্ড ওয়েহুক ইউআরএল
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1555088247137509379/YruglLjphIlnSc1718YSWF7mJnEiDJ-Zzc_7Gq01BTjX4LxFxCFZbCIKrv5A4dXAmkIP"

# স্ট্রাইক এবং ব্লক ট্র্যাকিং ডিকশনারি
strike_records = {}
blocked_ips = {}
MAX_STRIKES = 4  # ৪ বার অ্যাটাক করলে ব্লক হবে
BLOCK_TIME = 1800  # ৩০ মিনিট (সেকেন্ডে)

def send_discord_alert(client_ip, threat_type, strikes, path):
    if not DISCORD_WEBHOOK_URL:
        return
    payload = {
        "embeds": [{
            "title": "🚨 Aegis WAF - IP Blocked Due to Repeated Attacks",
            "color": 16711680,
            "fields": [
                {"name": "🛡 Threat Type", "value": str(threat_type), "inline": True},
                {"name": "🌐 Attacker IP", "value": str(client_ip), "inline": True},
                {"name": "⚠️ Total Strikes", "value": f"{strikes} / {MAX_STRIKES}", "inline": True},
                {"name": "📂 Target Path", "value": str(path), "inline": False},
                {"name": "⚡ Action", "value": "IP Blocked for 30 Minutes", "inline": False}
            ],
            "timestamp": datetime.utcnow().isoformat()
        }]
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=3)
    except Exception:
        pass

# মেমোরিতে ক্লায়েন্ট ডেটা সেভ করার জন্য লিস্ট
CUSTOMERS_DB = [
    {
        "api_key": "aegis_live_key_999",
        "username": "ibr@him",
        "email": "admin@firewall.com",
        "password": "muhib5869@",
        "client_name": "My Main Server",
        "domains": ["iss-antivirus-cloud.onrender.com"],
        "plan": "Enterprise",
        "origin_ip": "https://iss-antivirus-cloud.onrender.com",
        "expiry_date": "2027-12-31"
    }
]

ADMIN_USER = "ibr@him"
ADMIN_EMAIL = "admin@firewall.com"
ADMIN_PASS = "muhib5869@"

# --- Aegis WAF Firewall Middleware with Strike System ---
@app.before_request
def waf_protection():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    path = request.path
    
    # স্ট্যাটিক ফাইল, ব্রাউজারের আইকন বা এডমিন/ক্লায়েন্ট প্যানেল বাইপাস করার জন্য
    if 'favicon.ico' in path or path.startswith('/admin') or path.startswith('/client') or path == '/my-profile' or path.startswith('/proxy'):
        return

    # চেক করা আইপি অলরেডি ব্লকড কি না
    if client_ip in blocked_ips:
        if current_time < blocked_ips[client_ip]:
            return jsonify({
                "error": "Aegis WAF - Access Denied",
                "message": "Your IP is blocked for 30 minutes due to repeated malicious requests."
            }), 403
        else:
            del blocked_ips[client_ip]
            if client_ip in strike_records:
                del strike_records[client_ip]

    # পুরো রিকোয়েস্ট ইউআরএল এবং প্যারামিটার চেক করা
    full_url = request.full_path
    
    # SQL Injection বা XSS প্যাটার্ন চেক
    is_threat = False
    threat_name = ""
    
    if re.search(r"union\s+select|or\s+1\s*=\s*1|drop\s+table|--|#", full_url, re.IGNORECASE):
        is_threat = True
        threat_name = "SQL Injection (SQLi)"
    elif re.search(r"<script.*?>.*?</script>|javascript:|onerror=", full_url, re.IGNORECASE):
        is_threat = True
        threat_name = "Cross-Site Scripting (XSS)"

    if is_threat:
        if client_ip not in strike_records:
            strike_records[client_ip] = 0
        
        strike_records[client_ip] += 1
        current_strikes = strike_records[client_ip]
        
        if current_strikes >= MAX_STRIKES:
            blocked_ips[client_ip] = current_time + BLOCK_TIME
            send_discord_alert(client_ip, threat_name, current_strikes, path)
            return jsonify({
                "error": "Web Application Firewall Triggered",
                "threat_detected": threat_name,
                "strikes": f"{current_strikes}/{MAX_STRIKES}",
                "action": "IP Blocked for 30 Minutes!"
            }), 403
        else:
            return jsonify({
                "warning": "Aegis WAF - Suspicious Activity Detected",
                "threat_detected": threat_name,
                "strikes_count": f"{current_strikes}/{MAX_STRIKES}",
                "message": f"Warning! {MAX_STRIKES - current_strikes} more attempts will result in a 30-minute IP block."
            }), 400

# --- Reverse Proxy Route ---
@app.route('/proxy', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def reverse_proxy():
    target = request.args.get('target', '').strip('/')
    if not target:
        return jsonify({"error": "Invalid Proxy URL Format. Use /proxy?target=domain.com/path"}), 400
        
    parts = target.split('/', 1)
    client_domain = parts[0]
    subpath = parts[1] if len(parts) > 1 else ""

    matched_client = None
    for c in CUSTOMERS_DB:
        if any(client_domain.lower() in d.lower() or d.lower() in client_domain.lower() for d in c['domains']):
            matched_client = c
            break

    if not matched_client:
        return jsonify({"error": f"Target Domain '{client_domain}' Not Registered in Aegis Core"}), 404
        
    origin_url = matched_client['origin_ip']
    target_url = f"{origin_url.rstrip('/')}/{subpath}"
    
    try:
        req_headers = {key: value for (key, value) in request.headers if key.lower() not in ['host', 'accept-encoding']}
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=req_headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=15
        )
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded_headers]
        return Response(resp.content, resp.status_code, headers)
    except Exception as e:
        return jsonify({"error": "Origin Server Unreachable", "details": str(e)}), 502

# --- Landing Page (Home with Images & Premium Plans) ---
@app.route('/')
def landing_page():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Aegis Core - Advanced Web Application Firewall & Plans</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500 selection:text-slate-950">
        <nav class="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-8 py-4 flex justify-between items-center">
            <div class="flex items-center space-x-2">
                <i class="fa-solid fa-shield-cat text-cyan-400 text-xl"></i>
                <span class="font-bold text-lg tracking-wider text-cyan-400">AEGIS CORE WAF</span>
            </div>
            <div class="space-x-4">
                <a href="#plans" class="text-xs text-slate-300 hover:text-cyan-400 font-medium transition">Pricing Plans</a>
                <a href="/client/login" class="text-xs text-slate-300 hover:text-cyan-400 font-medium transition">Client Login</a>
                <a href="/my-profile" class="bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500 hover:text-slate-950 font-bold px-4 py-2 rounded text-xs transition">My Profile</a>
            </div>
        </nav>

        <header class="max-w-6xl mx-auto px-6 py-16 text-center space-y-6">
            <span class="bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs px-3 py-1 rounded-full uppercase tracking-widest font-semibold">Next-Gen Cybersecurity Protection</span>
            <h1 class="text-4xl md:text-6xl font-extrabold tracking-tight text-white">Ultimate Defense for Your <span class="text-cyan-400">Web Servers & Infrastructure</span></h1>
            <p class="text-slate-400 text-sm md:text-base max-w-2xl mx-auto">Protect your web applications from SQL Injections, XSS attacks, DDoS, and malicious malware threats in real-time with enterprise-grade reverse proxy firewall.</p>
        </header>

        <!-- Image Gallery Section -->
        <section class="max-w-6xl mx-auto px-6 py-8 space-y-6 text-center">
            <h2 class="text-2xl font-bold text-cyan-400">Security Infrastructure Overview</h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
                <div class="bg-slate-900 border border-slate-800 p-2 rounded-xl">
                    <img src="https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&auto=format&fit=crop&q=80" alt="Cloud Security" class="w-full h-40 object-cover rounded-lg border border-slate-800">
                </div>
                <div class="bg-slate-900 border border-slate-800 p-2 rounded-xl">
                    <img src="https://images.unsplash.com/photo-1563986768609-322da13575f3?w=600&auto=format&fit=crop&q=80" alt="Network Wall" class="w-full h-40 object-cover rounded-lg border border-slate-800">
                </div>
                <div class="bg-slate-900 border border-slate-800 p-2 rounded-xl">
                    <img src="https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=600&auto=format&fit=crop&q=80" alt="Malware Defense" class="w-full h-40 object-cover rounded-lg border border-slate-800">
                </div>
                <div class="bg-slate-900 border border-slate-800 p-2 rounded-xl">
                    <img src="https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=600&auto=format&fit=crop&q=80" alt="Traffic Routing" class="w-full h-40 object-cover rounded-lg border border-slate-800">
                </div>
            </div>
        </section>

        <!-- Premium Plans & Pricing Section -->
        <section id="plans" class="max-w-6xl mx-auto px-6 py-16 space-y-8">
            <div class="text-center space-y-3">
                <h2 class="text-3xl font-bold text-white">Choose Your <span class="text-cyan-400">Protection Plan</span></h2>
                <p class="text-slate-400 text-sm">Flexible pricing plans designed to secure websites and applications of any scale.</p>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <!-- Standard Plan -->
                <div class="bg-slate-900 border border-slate-800 p-8 rounded-2xl space-y-6 flex flex-col justify-between hover:border-cyan-500/50 transition">
                    <div class="space-y-4">
                        <span class="text-xs bg-slate-800 text-cyan-400 px-3 py-1 rounded-full font-semibold">Standard Plan</span>
                        <h3 class="text-2xl font-bold text-white">$19<span class="text-xs text-slate-400 font-normal"> /month</span></h3>
                        <p class="text-xs text-slate-400">Ideal for personal blogs and small portfolio websites.</p>
                        <ul class="text-xs space-y-2 text-slate-300">
                            <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i> 1 Domain Protected</li>
                            <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i> Basic SQLi & XSS Defense</li>
                            <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i> Standard Reverse Proxy</li>
                        </ul>
                    </div>
                    <a href="/client/login" class="w-full block text-center bg-slate-800 hover:bg-cyan-500 hover:text-slate-950 font-bold py-2.5 rounded text-xs transition">Get Standard</a>
                </div>

                <!-- Professional Plan -->
                <div class="bg-slate-900 border border-cyan-500 p-8 rounded-2xl space-y-6 flex flex-col justify-between relative shadow-lg shadow-cyan-500/10">
                    <div class="absolute -top-3 right-6 bg-cyan-500 text-slate-950 text-[10px] font-extrabold px-3 py-0.5 rounded-full uppercase">Popular</div>
                    <div class="space-y-4">
                        <span class="text-xs bg-cyan-500/20 text-cyan-400 px-3 py-1 rounded-full font-semibold">Professional Plan</span>
                        <h3 class="text-2xl font-bold text-white">$49<span class="text-xs text-slate-400 font-normal"> /month</span></h3>
                        <p class="text-xs text-slate-400">Perfect for growing business websites and apps.</p>
                        <ul class="text-xs space-y-2 text-slate-300">
                            <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i> Up to 5 Domains Protected</li>
                            <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i> Advanced Strike & IP Blocking</li>
                            <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i> Real-time Discord Alerts</li>
                        </ul>
                    </div>
                    <a href="/client/login" class="w-full block text-center bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold py-2.5 rounded text-xs transition">Get Professional</a>
                </div>

                <!-- Enterprise Plan -->
                <div class="bg-slate-900 border border-slate-800 p-8 rounded-2xl space-y-6 flex flex-col justify-between hover:border-cyan-500/50 transition">
                    <div class="space-y-4">
                        <span class="text-xs bg-slate-800 text-purple-400 px-3 py-1 rounded-full font-semibold">Enterprise Plan</span>
                        <h3 class="text-2xl font-bold text-white">$99<span class="text-xs text-slate-400 font-normal"> /month</span></h3>
                        <p class="text-xs text-slate-400">Maximum protection for corporate high-traffic servers.</p>
                        <ul class="text-xs space-y-2 text-slate-300">
                            <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i> Up to 10 Domains Protected</li>
                            <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i> Custom WAF Rules & Shield</li>
                            <li><i class="fa-solid fa-check text-cyan-400 mr-2"></i> 24/7 Priority Support</li>
                        </ul>
                    </div>
                    <a href="/client/login" class="w-full block text-center bg-slate-800 hover:bg-cyan-500 hover:text-slate-950 font-bold py-2.5 rounded text-xs transition">Get Enterprise</a>
                </div>
            </div>
        </section>

        <footer class="border-t border-slate-800 py-6 text-center text-xs text-slate-500">
            &copy; 2026 Aegis Core WAF Security System. All rights reserved.
        </footer>
    </body>
    </html>
    """)

# --- My Profile / Admin Login ---
@app.route('/my-profile', methods=['GET', 'POST'])
def my_profile():
    error = None
    if request.args.get('logout'):
        session.pop('is_admin', None)
        return redirect(url_for('my_profile'))

    if request.method == 'POST':
        user_input = request.form.get('username')
        pass_input = request.form.get('password')
        if (user_input == ADMIN_USER or user_input == ADMIN_EMAIL) and pass_input == ADMIN_PASS:
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Invalid Master Credentials"

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>My Profile & Admin Login</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-950 text-slate-100 flex flex-col items-center justify-center h-screen">
        <div class="absolute top-6 left-6">
            <a href="/" class="text-xs text-cyan-400 hover:underline"><i class="fa-solid fa-arrow-left mr-1"></i> Back to Home</a>
        </div>
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl shadow-2xl w-96 space-y-4">
            <h2 class="text-xl font-bold text-cyan-400 text-center"><i class="fa-solid fa-user-shield mr-2"></i> Admin Portal</h2>
            {% if error %}
            <p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>
            {% endif %}
            <input type="text" name="username" placeholder="Username or Email" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <button type="submit" class="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold p-3 rounded text-sm transition">Authenticate & Enter</button>
        </form>
    </body>
    </html>
    """, error=error)

# --- Admin Dashboard ---
@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('my_profile'))
    
    success_msg = None
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'delete':
            api_key_to_delete = request.form.get('api_key')
            global CUSTOMERS_DB
            CUSTOMERS_DB = [c for c in CUSTOMERS_DB if c['api_key'] != api_key_to_delete]
            success_msg = "Client deleted successfully!"
        elif action == 'create':
            try:
                new_client = {
                    "api_key": request.form.get('api_key'),
                    "username": request.form.get('username'),
                    "email": request.form.get('email'),
                    "password": request.form.get('password'),
                    "client_name": request.form.get('client_name'),
                    "domains": [request.form.get('domain')] if request.form.get('domain') else [],
                    "plan": request.form.get('plan'),
                    "origin_ip": request.form.get('origin_ip'),
                    "expiry_date": request.form.get('expiry_date')
                }
                CUSTOMERS_DB.append(new_client)
                success_msg = "Client created successfully!"
            except Exception as e:
                pass

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Admin Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans">
        <nav class="border-b border-slate-800 bg-slate-900 px-6 py-4 flex justify-between items-center">
            <h1 class="font-bold text-cyan-400">AEGIS CORE • ADMIN PANEL</h1>
            <div class="space-x-4">
                <a href="/" target="_blank" class="text-xs text-cyan-400 hover:underline">View Website</a>
                <a href="/my-profile?logout=true" class="text-xs text-red-400 hover:underline">Logout</a>
            </div>
        </nav>
        <main class="p-6 max-w-7xl mx-auto space-y-6">
            {% if success_msg %}
            <div class="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 p-4 rounded text-sm">{{ success_msg }}</div>
            {% endif %}
            
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <h2 class="text-lg font-bold text-cyan-400"><i class="fa-solid fa-user-plus mr-2"></i> Create Server/Client & License</h2>
                <form method="POST" class="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <input type="hidden" name="action" value="create">
                    <input type="text" name="client_name" placeholder="Server Name" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="username" placeholder="Username" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="email" name="email" placeholder="Email" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="password" name="password" placeholder="Password" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="domain" placeholder="Main Domain" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="api_key" placeholder="API Key" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="origin_ip" placeholder="Origin URL" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="date" name="expiry_date" required class="bg-slate-950 border border-slate-800 p-2 rounded text-xs text-slate-200">
                    <select name="plan" class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs md:col-span-3">
                        <option value="Standard">Standard</option>
                        <option value="Professional">Professional</option>
                        <option value="Enterprise">Enterprise</option>
                    </select>
                    <button type="submit" class="md:col-span-4 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold p-2.5 rounded text-xs transition">Save & Create License</button>
                </form>
            </div>

            <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
                <h2 class="text-lg font-bold text-cyan-400"><i class="fa-solid fa-server mr-2"></i> Registered Clients / Licenses</h2>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs border-collapse">
                        <thead>
                            <tr class="border-b border-slate-800 text-slate-400 uppercase bg-slate-950">
                                <th class="p-3">Name</th>
                                <th class="p-3">Username</th>
                                <th class="p-3">Domains</th>
                                <th class="p-3">Plan</th>
                                <th class="p-3">Expiry Date</th>
                                <th class="p-3 text-center">Action</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-800">
                            {% for c in customers %}
                            <tr>
                                <td class="p-3 font-semibold">{{ c.client_name }}</td>
                                <td class="p-3 text-cyan-400">{{ c.username }}</td>
                                <td class="p-3 text-cyan-300">{{ c.domains | join(', ') }}</td>
                                <td class="p-3 text-purple-400 font-semibold">{{ c.plan }}</td>
                                <td class="p-3 text-amber-400 font-semibold">{{ c.expiry_date }}</td>
                                <td class="p-3 text-center">
                                    <form method="POST" onsubmit="return confirm('Delete this?');" style="display:inline;">
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="api_key" value="{{ c.api_key }}">
                                        <button type="submit" class="bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500 hover:text-white px-2 py-1 rounded transition text-[10px]">Delete</button>
                                    </form>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </main>
    </body>
    </html>
    """, success_msg=success_msg, customers=CUSTOMERS_DB)

# --- Client Login ---
@app.route('/client/login', methods=['GET', 'POST'])
def client_login():
    error = None
    if request.method == 'POST':
        identity = request.form.get('identity')
        password = request.form.get('password')
        logged_client = next((c for c in CUSTOMERS_DB if (c['username'] == identity or c['email'] == identity or c['api_key'] == identity) and c['password'] == password), None)
        if logged_client:
            session['client_username'] = logged_client['username']
            return redirect(url_for('client_dashboard'))
        else:
            error = "Invalid Credentials"
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Client Portal Login</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 flex flex-col items-center justify-center h-screen">
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl shadow-2xl w-96 space-y-4">
            <h2 class="text-xl font-bold text-cyan-400 text-center">Client Portal Login</h2>
            {% if error %}<p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>{% endif %}
            <input type="text" name="identity" placeholder="Username, Email or API Key" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm focus:outline-none focus:border-cyan-500">
            <button type="submit" class="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold p-3 rounded text-sm transition">Login</button>
        </form>
    </body>
    </html>
    """, error=error)

# --- Client Dashboard ---
@app.route('/client/dashboard', methods=['GET', 'POST'])
def client_dashboard():
    username = session.get('client_username')
    if not username: return redirect(url_for('client_login'))
    current_client = next((c for c in CUSTOMERS_DB if c['username'] == username), None)
    if not current_client: return redirect(url_for('client_login'))
    
    success_msg = None
    limit_map = {"Standard": 1, "Professional": 5, "Enterprise": 10}
    max_slots = limit_map.get(current_client['plan'], 1)

    if request.method == 'POST':
        new_domains = [request.form.get(f'domain_{i}').strip() for i in range(max_slots) if request.form.get(f'domain_{i}')]
        current_client['domains'] = new_domains
        success_msg = "Domains updated!"

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8"><title>Client Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans">
        <nav class="border-b border-slate-800 bg-slate-900 px-6 py-4 flex justify-between items-center">
            <h1 class="font-bold text-cyan-400">CLIENT PORTAL ({{ client.client_name }})</h1>
            <a href="/client/logout" class="text-xs text-red-400 hover:underline">Logout</a>
        </nav>
        <main class="p-6 max-w-4xl mx-auto space-y-6">
            {% if success_msg %}<div class="bg-emerald-500/10 text-emerald-400 p-4 rounded text-sm">{{ success_msg }}</div>{% endif %}
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-3">
                <h2 class="text-lg font-bold text-cyan-400">Subscription Details</h2>
                <p class="text-xs">Plan: <span class="text-purple-400">{{ client.plan }}</span> | Expiry: <span class="text-amber-400">{{ client.expiry_date }}</span></p>
            </div>
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <h2 class="text-lg font-bold text-cyan-400">Configure Domains</h2>
                <form method="POST" class="space-y-4">
                    {% for i in range(max_slots) %}
                    <input type="text" name="domain_{{ i }}" value="{{ client.domains[i] if i < client.domains|length else '' }}" placeholder="mysite.com" class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded text-xs text-slate-200">
                    {% endfor %}
                    <button type="submit" class="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-6 py-2 rounded text-xs">Save</button>
                </form>
            </div>
        </main>
    </body>
    </html>
    """, client=current_client, max_slots=max_slots, success_msg=success_msg)

@app.route('/client/logout')
def client_logout():
    session.pop('client_username', None)
    return redirect(url_for('client_login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
