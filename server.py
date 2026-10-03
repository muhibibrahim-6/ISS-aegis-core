import os
import time
import re
import requests
from urllib.parse import unquote
from flask import Flask, jsonify, request, render_template_string, Response, redirect, url_for, session
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "aegis_final_production_2026")

# আপনার নতুন ডিসকর্ড ওয়েহুক ইউআরএল এখানে আপডেট করা হলো
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1555750516338856006/-riimewpBbXexc7WKO_2bl-7JCIDOsQTIORvEUs1dTNRqpi6A97ClD-D4rw73DGQITwR"

def send_discord_alert(threat_type, client_ip, path, license_key):
    if not DISCORD_WEBHOOK_URL:
        return
    payload = {
        "embeds": [{
            "title": "🚨 Aegis WAF - Threat Blocked & Logged",
            "color": 16711680,
            "fields": [
                {"name": "🛡️ Threat / Payload", "value": str(threat_type), "inline": True},
                {"name": "🌐 Attacker IP", "value": str(client_ip), "inline": True},
                {"name": "🔑 Client License Key", "value": f"`{license_key}`", "inline": False},
                {"name": "📂 Target Website URL", "value": str(path), "inline": False},
                {"name": "⏱️ Time", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "inline": False}
            ]
        }]
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
    except Exception:
        pass

# স্ট্রাইক এবং ব্লক ট্র্যাকিং
strike_records = {}
blocked_ips = {}
MAX_STRIKES = 4  
BLOCK_TIME = 1800  # ৩০ মিনিট

# রিয়েল ক্লায়েন্ট ডাটাবেজ (এখানে 'domains' এর বদলে 'urls' ব্যবহার করা হয়েছে)
CUSTOMERS_DB = [
    {
        "api_key": "aegis_live_key_999",
        "username": "ibr@him",
        "email": "admin@firewall.com",
        "password": "muhib5869@",
        "client_name": "My Main Server",
        "urls": ["https://iss-antivirus-cloud.onrender.com"],
        "plan": "Enterprise",
        "origin_ip": "https://iss-antivirus-cloud.onrender.com",
        "expiry_date": "2027-12-31"
    }
]

ADMIN_USER = "ibr@him"
ADMIN_EMAIL = "admin@firewall.com"
ADMIN_PASS = "muhib5869@"

# --- WAF Engine with Direct URL & License Binding ---
@app.before_request
def firewall_inspection():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    
    if request.path.startswith('/admin') or request.path.startswith('/client') or request.path == '/my-profile':
        return

    if client_ip in blocked_ips:
        if current_time < blocked_ips[client_ip]:
            return jsonify({"error": "Aegis WAF - IP Banned due to security violations."}), 403
        else:
            del blocked_ips[client_ip]
            if client_ip in strike_records:
                del strike_records[client_ip]

    # কোন ক্লায়েন্টের ওয়েবসাইটের লিংকের সাথে রিকোয়েস্ট মিলেছে তা ট্র্যাক করা
    target_param = request.args.get('target', '').lower()
    host_header = request.host.lower()
    
    matched_license_key = "aegis_live_key_999" # ডিফল্ট
    for client in CUSTOMERS_DB:
        for u in client.get('urls', []):
            if host_header in u.lower() or u.lower() in target_param:
                matched_license_key = client['api_key']
                break

    raw_full_path = request.full_path
    decoded_url = unquote(raw_full_path)
    body_content = ""
    try:
        body_content = unquote(request.get_data(as_text=True))
    except Exception:
        pass

    inspection_target = f"{decoded_url} {body_content}"

    sqli_pattern = r"union\s+select|or\s+1\s*=\s*1|drop\s+table|--|#|information_schema|benchmark\s*\(|exec\s*\("
    xss_pattern = r"<script.*?>.*?</script>|javascript:|onerror\s*=|onload\s*="

    is_threat = False
    threat_name = ""

    if re.search(sqli_pattern, inspection_target, re.IGNORECASE):
        is_threat = True
        threat_name = "SQL Injection (SQLi)"
    elif re.search(xss_pattern, inspection_target, re.IGNORECASE):
        is_threat = True
        threat_name = "Cross-Site Scripting (XSS)"

    if is_threat:
        if client_ip not in strike_records:
            strike_records[client_ip] = 0
        strike_records[client_ip] += 1
        current_strikes = strike_records[client_ip]
        
        # ডিসকর্ডে লাইসেন্স কি সহ অ্যালার্ট পাঠানো
        send_discord_alert(threat_name, client_ip, decoded_url, matched_license_key)

        if current_strikes >= MAX_STRIKES:
            blocked_ips[client_ip] = current_time + BLOCK_TIME
            return jsonify({"error": "Aegis WAF - IP Banned for 30 minutes!"}), 403
        else:
            return jsonify({"error": "Aegis WAF - Malicious Payload Blocked", "threat": threat_name, "license_key": matched_license_key}), 400

# --- Reverse Proxy Route ---
@app.route('/proxy', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def reverse_proxy():
    target = request.args.get('target', '').strip('/')
    if not target:
        return jsonify({"error": "Invalid Proxy URL Format. Use /proxy?target=https://website.com/path"}), 400
        
    matched_client = None
    for c in CUSTOMERS_DB:
        if any(target.lower().startswith(u.lower().replace('https://', '').replace('http://', '')) for u in c.get('urls', [])):
            matched_client = c
            break

    if not matched_client:
        return jsonify({"error": "Target Website URL Not Registered in Firewall Database"}), 404
        
    origin_url = matched_client['origin_ip']
    
    try:
        req_headers = {key: value for (key, value) in request.headers if key.lower() not in ['host', 'accept-encoding']}
        resp = requests.request(
            method=request.method,
            url=origin_url,
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

# --- Complete Landing Page (Keeping all images, plans, and social links intact) ---
@app.route('/')
def landing_page():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Aegis Core - Connected Web Application Firewall</title>
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
                <a href="#plans" class="text-xs text-slate-300 hover:text-cyan-400 font-medium transition">Pricing</a>
                <a href="/client/login" class="text-xs text-slate-300 hover:text-cyan-400 font-medium transition">Client Login</a>
                <a href="/my-profile" class="bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500 hover:text-slate-950 font-bold px-4 py-2 rounded text-xs transition">Admin Portal</a>
            </div>
        </nav>

        <header class="max-w-6xl mx-auto px-6 py-16 text-center space-y-6">
            <span class="bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs px-3 py-1 rounded-full uppercase tracking-widest font-semibold">Zero-Tolerance Connected Firewall Active</span>
            <h1 class="text-4xl md:text-6xl font-extrabold tracking-tight text-white">Ultimate Defense for Your <span class="text-cyan-400">Web Servers & Infrastructure</span></h1>
            <p class="text-slate-400 text-sm md:text-base max-w-2xl mx-auto">Protecting your website links and proxies from SQL Injections, XSS, and malicious payload threats in real-time.</p>
        </header>

        <section class="max-w-6xl mx-auto px-6 py-8 space-y-6 text-center">
            <h2 class="text-2xl font-bold text-cyan-400">Security Infrastructure Overview</h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
                <div class="bg-slate-900 border border-slate-800 p-2 rounded-xl"><img src="https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&auto=format&fit=crop&q=80" class="w-full h-40 object-cover rounded-lg border border-slate-800"></div>
                <div class="bg-slate-900 border border-slate-800 p-2 rounded-xl"><img src="https://images.unsplash.com/photo-1563986768609-322da13575f3?w=600&auto=format&fit=crop&q=80" class="w-full h-40 object-cover rounded-lg border border-slate-800"></div>
                <div class="bg-slate-900 border border-slate-800 p-2 rounded-xl"><img src="https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=600&auto=format&fit=crop&q=80" class="w-full h-40 object-cover rounded-lg border border-slate-800"></div>
                <div class="bg-slate-900 border border-slate-800 p-2 rounded-xl"><img src="https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=600&auto=format&fit=crop&q=80" class="w-full h-40 object-cover rounded-lg border border-slate-800"></div>
            </div>
        </section>

        <section id="plans" class="max-w-6xl mx-auto px-6 py-16 space-y-8">
            <div class="text-center space-y-3">
                <h2 class="text-3xl font-bold text-white">Choose Your <span class="text-cyan-400">Protection Plan</span></h2>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
                <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-4 flex flex-col justify-between">
                    <div>
                        <span class="text-xs bg-slate-800 text-cyan-400 px-3 py-1 rounded-full font-semibold">Standard</span>
                        <h3 class="text-xl font-bold text-white mt-3">$19<span class="text-xs text-slate-400"> /mo</span></h3>
                        <p class="text-xs text-slate-400 mt-2">1 Website Link Protected</p>
                    </div>
                    <a href="/client/login" class="w-full block text-center bg-slate-800 hover:bg-cyan-500 hover:text-slate-950 font-bold py-2 rounded text-xs transition">Get Standard</a>
                </div>
                <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-4 flex flex-col justify-between">
                    <div>
                        <span class="text-xs bg-slate-800 text-cyan-400 px-3 py-1 rounded-full font-semibold">Professional</span>
                        <h3 class="text-xl font-bold text-white mt-3">$49<span class="text-xs text-slate-400"> /mo</span></h3>
                        <p class="text-xs text-slate-400 mt-2">Up to 5 Website Links</p>
                    </div>
                    <a href="/client/login" class="w-full block text-center bg-slate-800 hover:bg-cyan-500 hover:text-slate-950 font-bold py-2 rounded text-xs transition">Get Professional</a>
                </div>
                <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-4 flex flex-col justify-between">
                    <div>
                        <span class="text-xs bg-slate-800 text-purple-400 px-3 py-1 rounded-full font-semibold">Enterprise</span>
                        <h3 class="text-xl font-bold text-white mt-3">$99<span class="text-xs text-slate-400"> /mo</span></h3>
                        <p class="text-xs text-slate-400 mt-2">Up to 10 Website Links</p>
                    </div>
                    <a href="/client/login" class="w-full block text-center bg-slate-800 hover:bg-cyan-500 hover:text-slate-950 font-bold py-2 rounded text-xs transition">Get Enterprise</a>
                </div>
                <!-- নতুন আনলিমিটেড প্ল্যান -->
                <div class="bg-slate-900 border border-cyan-500 p-6 rounded-2xl space-y-4 flex flex-col justify-between shadow-lg shadow-cyan-500/10">
                    <div>
                        <span class="text-xs bg-cyan-500/20 text-cyan-400 px-3 py-1 rounded-full font-semibold">Unlimited Plan</span>
                        <h3 class="text-xl font-bold text-white mt-3">$199<span class="text-xs text-slate-400"> /mo</span></h3>
                        <p class="text-xs text-slate-400 mt-2">Unlimited Website Links with Dynamic Add New Support</p>
                    </div>
                    <a href="/client/login" class="w-full block text-center bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold py-2 rounded text-xs transition">Get Unlimited</a>
                </div>
            </div>
        </section>

        <footer class="border-t border-slate-800 py-10 bg-slate-900/40 text-center space-y-4">
            <div class="flex justify-center space-x-6 text-slate-400 text-lg">
                <a href="https://instagram.com/mrshadow6000" target="_blank" class="hover:text-cyan-400"><i class="fa-brands fa-instagram"></i></a>
                <a href="https://discord.gg/mxRgm2R3ud" target="_blank" class="hover:text-cyan-400"><i class="fa-brands fa-discord"></i></a>
                <a href="https://linkedin.com" target="_blank" class="hover:text-cyan-400"><i class="fa-brands fa-linkedin"></i></a>
            </div>
            <p class="text-xs text-slate-500">&copy; 2026 Aegis Core WAF Security System. All rights reserved.</p>
        </footer>
    </body>
    </html>
    """)

# --- Admin Portal & Dashboard ---
@app.route('/my-profile', methods=['GET', 'POST'])
def my_profile():
    error = None
    if request.args.get('logout'):
        session.pop('is_admin', None)
        return redirect(url_for('my_profile'))
    if request.method == 'POST':
        if (request.form.get('username') == ADMIN_USER or request.form.get('username') == ADMIN_EMAIL) and request.form.get('password') == ADMIN_PASS:
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Invalid Master Credentials"
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 flex items-center justify-center h-screen">
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl w-96 space-y-4 shadow-2xl">
            <h2 class="text-xl font-bold text-cyan-400 text-center">Admin Portal</h2>
            {% if error %}<p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>{% endif %}
            <input type="text" name="username" placeholder="Username or Email" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <button type="submit" class="w-full bg-cyan-500 text-slate-950 font-bold p-3 rounded text-sm">Login</button>
        </form>
    </body></html>
    """, error=error)

@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('is_admin'): return redirect(url_for('my_profile'))
    global CUSTOMERS_DB
    success_msg = None
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'delete':
            api_key = request.form.get('api_key')
            CUSTOMERS_DB = [c for c in CUSTOMERS_DB if c['api_key'] != api_key]
            success_msg = "Client deleted!"
        elif action == 'create':
            try:
                new_client = {
                    "api_key": request.form.get('api_key'),
                    "username": request.form.get('username'),
                    "email": request.form.get('email'),
                    "password": request.form.get('password'),
                    "client_name": request.form.get('client_name'),
                    "urls": [request.form.get('url')] if request.form.get('url') else [],
                    "plan": request.form.get('plan'),
                    "origin_ip": request.form.get('origin_ip'),
                    "expiry_date": request.form.get('expiry_date')
                }
                CUSTOMERS_DB.append(new_client)
                success_msg = "Client created with website URL binding!"
            except Exception:
                pass
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 p-6 space-y-6 font-sans">
        <nav class="border-b border-slate-800 bg-slate-900 px-6 py-4 flex justify-between items-center rounded-xl">
            <h1 class="font-bold text-cyan-400">ADMIN DASHBOARD</h1>
            <a href="/my-profile?logout=true" class="text-xs text-red-400">Logout</a>
        </nav>
        <main class="max-w-6xl mx-auto space-y-6">
            {% if success_msg %}<div class="bg-emerald-500/10 text-emerald-400 p-3 rounded text-xs">{{ success_msg }}</div>{% endif %}
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <h2 class="text-sm font-bold text-cyan-400">Add New Client License (Website Link Based)</h2>
                <form method="POST" class="grid grid-cols-1 md:grid-cols-4 gap-3">
                    <input type="hidden" name="action" value="create">
                    <input type="text" name="client_name" placeholder="Server Name" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="username" placeholder="Username" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="email" name="email" placeholder="Email" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="password" name="password" placeholder="Password" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="url" placeholder="Website Link (e.g. https://site.com)" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="api_key" placeholder="API Key / License Key" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="origin_ip" placeholder="Origin URL" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="date" name="expiry_date" required class="bg-slate-950 border border-slate-800 p-2 rounded text-xs text-slate-200">
                    <select name="plan" class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs md:col-span-3">
                        <option value="Standard">Standard</option>
                        <option value="Professional">Professional</option>
                        <option value="Enterprise">Enterprise</option>
                        <option value="Unlimited">Unlimited (Dynamic URL Slots)</option>
                    </select>
                    <button type="submit" class="md:col-span-4 bg-cyan-500 text-slate-950 font-bold p-2.5 rounded text-xs">Create Client</button>
                </form>
            </div>
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <h2 class="text-sm font-bold text-cyan-400">Registered Clients</h2>
                <div class="space-y-2">
                    {% for client in customers %}
                    <div class="bg-slate-950 border border-slate-800 p-3 rounded-lg flex justify-between items-center text-xs">
                        <div>
                            <p class="font-bold text-white">{{ client.client_name }} (<span class="text-cyan-400">{{ client.username }}</span>)</p>
                            <p class="text-slate-400">Links: {{ client.urls | join(', ') }} | Plan: {{ client.plan }} | Key: <code class="text-cyan-300">{{ client.api_key }}</code></p>
                        </div>
                        <form method="POST" onsubmit="return confirm('Delete?');">
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="api_key" value="{{ client.api_key }}">
                            <button type="submit" class="bg-red-500/10 text-red-400 px-3 py-1.5 rounded">Delete</button>
                        </form>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </main>
    </body></html>
    """, success_msg=success_msg, customers=CUSTOMERS_DB)

# --- Client Login & Dashboard (With Dynamic Add New URL slots for Unlimited plan) ---
@app.route('/client/login', methods=['GET', 'POST'])
def client_login():
    error = None
    if request.method == 'POST':
        identity = request.form.get('identity')
        password = request.form.get('password')
        client = next((c for c in CUSTOMERS_DB if (c['username'] == identity or c['email'] == identity or c['api_key'] == identity) and c['password'] == password), None)
        if client:
            session['client_username'] = client['username']
            return redirect(url_for('client_dashboard'))
        else:
            error = "Invalid Credentials"
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en"><head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-slate-950 text-slate-100 flex items-center justify-center h-screen">
        <form method="POST" class="bg-slate-900 border border-slate-800 p-8 rounded-xl w-96 space-y-4 shadow-2xl">
            <h2 class="text-xl font-bold text-cyan-400 text-center">Client Portal Login</h2>
            {% if error %}<p class="text-xs text-red-400 text-center bg-red-500/10 p-2 rounded">{{ error }}</p>{% endif %}
            <input type="text" name="identity" placeholder="Username, Email or API Key" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950 border border-slate-800 p-3 rounded text-sm">
            <button type="submit" class="w-full bg-cyan-500 text-slate-950 font-bold p-3 rounded text-sm">Login</button>
        </form>
    </body></html>
    """, error=error)

@app.route('/client/dashboard', methods=['GET', 'POST'])
def client_dashboard():
    username = session.get('client_username')
    if not username: return redirect(url_for('client_login'))
    current_client = next((c for c in CUSTOMERS_DB if c['username'] == username), None)
    if not current_client: return redirect(url_for('client_login'))
    
    success_msg = None
    if request.method == 'POST':
        # ডায়নামিক ফর্ম থেকে আসা সব ওয়েবসাইট লিংক সংগ্রহ করা
        urls = request.form.getlist('website_urls')
        current_client['urls'] = [u.strip() for u in urls if u.strip()]
        success_msg = "Website links updated and firewall protection bound instantly!"

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <script src="https://cdn.tailwindcss.com"></script>
        <script>
            function addUrlField() {
                const container = document.getElementById('url-container');
                const div = document.createElement('div');
                div.className = "flex gap-2 items-center";
                div.innerHTML = `<input type="text" name="website_urls" placeholder="https://mywebsite.com" required class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded text-xs text-slate-200"><button type="button" onclick="this.parentElement.remove()" class="bg-red-500/20 text-red-400 px-3 py-2 rounded text-xs">Remove</button>`;
                container.appendChild(div);
            }
        </script>
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans p-6 space-y-6">
        <nav class="border-b border-slate-800 bg-slate-900 px-6 py-4 flex justify-between items-center rounded-xl">
            <h1 class="font-bold text-cyan-400">CLIENT PORTAL ({{ client.client_name }})</h1>
            <a href="/client/logout" class="text-xs text-red-400">Logout</a>
        </nav>
        <main class="max-w-4xl mx-auto space-y-6">
            {% if success_msg %}<div class="bg-emerald-500/10 text-emerald-400 p-3 rounded text-xs">{{ success_msg }}</div>{% endif %}
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <div class="flex justify-between items-center">
                    <h2 class="text-sm font-bold text-cyan-400">Configure Protected Website Links (Plan: {{ client.plan }})</h2>
                    <span class="text-xs text-slate-400">License Key: <code class="text-cyan-300 font-mono">{{ client.api_key }}</code></span>
                </div>
                <form method="POST" class="space-y-4">
                    <div id="url-container" class="space-y-3">
                        {% if client.urls %}
                            {% for url in client.urls %}
                            <div class="flex gap-2 items-center">
                                <input type="text" name="website_urls" value="{{ url }}" placeholder="https://mywebsite.com" required class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded text-xs text-slate-200">
                                <button type="button" onclick="this.parentElement.remove()" class="bg-red-500/20 text-red-400 px-3 py-2 rounded text-xs">Remove</button>
                            </div>
                            {% endfor %}
                        {% else %}
                            <div class="flex gap-2 items-center">
                                <input type="text" name="website_urls" placeholder="https://mywebsite.com" required class="w-full bg-slate-950 border border-slate-800 p-2.5 rounded text-xs text-slate-200">
                            </div>
                        {% endif %}
                    </div>
                    {% if client.plan == 'Unlimited' %}
                    <button type="button" onclick="addUrlField()" class="bg-slate-800 text-cyan-400 px-4 py-2 rounded text-xs font-bold">+ Add New Website Link</button>
                    {% endif %}
                    <br>
                    <button type="submit" class="bg-cyan-500 text-slate-950 font-bold px-6 py-2 rounded text-xs">Save & Bind Firewall</button>
                </form>
            </div>
        </main>
    </body></html>
    """, client=current_client, success_msg=success_msg)

@app.route('/client/logout')
def client_logout():
    session.pop('client_username', None)
    return redirect(url_for('client_login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
