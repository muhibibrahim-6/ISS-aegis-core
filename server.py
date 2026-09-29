import os
import time
import re
import requests
from collections import defaultdict
from urllib.parse import urlparse
from flask import Flask, jsonify, request, render_template_string, Response

app = Flask(__name__)

# --- 1. Database Configuration (PostgreSQL Safety Wrapper) ---
DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db_connection():
    if not DATABASE_URL:
        return None
    try:
        url = urlparse(DATABASE_URL)
        conn = psycopg2.connect(
            database=url.path[1:],
            user=url.username,
            password=url.password,
            host=url.hostname,
            port=url.port
        )
        return conn
    except Exception as e:
        print("Database connection error:", e)
        return None

# psycopg2 ইমপোর্ট সেফ রাখা (যদি লোকাল বা অন্য এনভায়রনমেন্টে থাকে)
try:
    import psycopg2
except ImportError:
    psycopg2 = None

def init_db():
    if not psycopg2 or not DATABASE_URL:
        print("PostgreSQL is not configured. Running in memory-fallback mode.")
        return
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS customers (
                    api_key TEXT PRIMARY KEY,
                    client_name TEXT,
                    domain TEXT,
                    plan TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_logs (
                    id SERIAL PRIMARY KEY,
                    timestamp TEXT,
                    ip TEXT,
                    path TEXT,
                    threat TEXT,
                    ai_patch TEXT
                )
            ''')
            conn.commit()
            
            cursor.execute("SELECT COUNT(*) FROM customers")
            if cursor.fetchone()[0] == 0:
                cursor.execute(
                    "INSERT INTO customers (api_key, client_name, domain, plan) VALUES (%s, %s, %s, %s)",
                    ("aegis_live_key_999", "Acme Corp", "acme.com", "Enterprise")
                )
                conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            print("DB Init Error:", e)

try:
    init_db()
except Exception as e:
    print("Database initialization skipped:", e)

DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "YOUR_DISCORD_WEBHOOK_URL_HERE")

BLOCKED_IPS = set()
blocked_until = {}
BLOCK_DURATION = 300
FALLBACK_LOGS = [] # ডেটাবেজ না থাকলে মেমোরিতে লগ রাখার ব্যবস্থা

SQLI_PATTERNS = [
    (r"union\s+select", "SQL Injection (UNION based)"),
    (r"or\s+1\s*=\s*1", "SQL Injection (Boolean based tautology)"),
    (r"drop\s+table", "SQL Injection (Destructive DROP command)"),
    (r"(\%27)|(\')", "SQL Injection (Single quote anomaly)")
]

XSS_PATTERNS = [
    (r"<script[^>]*>[\s\S]*?</script>", "Cross-Site Scripting (Script tag injection)"),
    (r"javascript\s*:", "Cross-Site Scripting (JS pseudo-protocol)"),
    (r"onerror\s*=", "Cross-Site Scripting (Event handler injection)")
]

def generate_ai_patch_advice(threat_type):
    if "SQL Injection" in threat_type:
        return {
            "vulnerability": "SQL Injection",
            "risk_level": "CRITICAL",
            "developer_fix": "Use Parameterized Queries or ORM instead of raw string concatenation.",
            "secure_code_example": "cursor.execute('SELECT * FROM users WHERE username = %s', (username,))"
        }
    elif "Cross-Site Scripting" in threat_type:
        return {
            "vulnerability": "XSS (Cross-Site Scripting)",
            "risk_level": "HIGH",
            "developer_fix": "Always escape user inputs before rendering them in HTML templates.",
            "secure_code_example": "{{ user_input | escape }}"
        }
    return {
        "vulnerability": "General Web Attack",
        "risk_level": "MEDIUM",
        "developer_fix": "Ensure all input parameters are strictly validated."
    }

def analyze_payload(text):
    if not text:
        return None
    text_lower = str(text).lower()
    for pattern, desc in SQLI_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return desc
    for pattern, desc in XSS_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return desc
    return None

def send_discord_alert(threat_data):
    if "YOUR_DISCORD_WEBHOOK_URL" in DISCORD_WEBHOOK_URL:
        return
    payload = {
        "content": f"🚨 **Aegis Core WAF Alert!**\n"
                   f"• **Threat:** {threat_data['threat']}\n"
                   f"• **Attacker IP:** `{threat_data['ip']}`\n"
                   f"• **Target Path:** `{threat_data['path']}`\n"
                   f"• **Action:** IP Blocked & Logged"
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=3)
    except Exception as e:
        print("Discord alert failed:", e)

@app.before_request
def aegis_firewall_middleware():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    path = request.path
    
    if path == '/' or path == '/api/v1/security/logs' or path.startswith('/proxy/'):
        return
        
    if client_ip in BLOCKED_IPS:
        if current_time < blocked_until.get(client_ip, 0):
            return jsonify({
                "error": "Access Denied by Aegis Core WAF",
                "reason": "Temporary IP ban active due to security violation."
            }), 403
        else:
            BLOCKED_IPS.remove(client_ip)
            del blocked_until[client_ip]

    req_payload = str(request.get_json(silent=True) or request.form.to_dict())
    target_data = request.full_path + " " + req_payload
    
    threat_type = analyze_payload(target_data)
    
    if threat_type:
        BLOCKED_IPS.add(client_ip)
        blocked_until[client_ip] = current_time + BLOCK_DURATION
        patch_advice = generate_ai_patch_advice(threat_type)
        
        timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(current_time))
        
        log_entry = {
            "timestamp": timestamp_str,
            "ip": client_ip,
            "path": path,
            "threat": threat_type,
            "ai_patch": patch_advice.get("developer_fix", "")
        }
        
        # ডেটাবেজে সেভ করার চেষ্টা, ফেইল করলে মেমোরি লিস্টে রাখা
        saved_to_db = False
        try:
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO security_logs (timestamp, ip, path, threat, ai_patch) VALUES (%s, %s, %s, %s, %s)",
                    (timestamp_str, client_ip, path, threat_type, log_entry["ai_patch"])
                )
                conn.commit()
                cursor.close()
                conn.close()
                saved_to_db = True
        except Exception as e:
            print("DB Log Insert Error:", e)
            
        if not saved_to_db:
            FALLBACK_LOGS.insert(0, log_entry)
        
        send_discord_alert(log_entry)
        
        return jsonify({
            "error": "Web Application Firewall Triggered",
            "threat_detected": threat_type,
            "action": "IP Blocked & Forensic Logged",
            "ai_developer_advisor": patch_advice
        }), 403

ORIGIN_SERVER_MAP = {
    "acme.com": "http://192.168.1.50:8000",
}

@app.route('/proxy/<client_domain>/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def reverse_proxy(client_domain, subpath):
    if client_domain not in ORIGIN_SERVER_MAP:
        return jsonify({"error": "Target Client Domain Not Registered in Aegis Core"}), 404
        
    target_url = f"{ORIGIN_SERVER_MAP[client_domain]}/{subpath}"
    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers={key: value for (key, value) in request.headers if key != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10
        )
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        return Response(resp.content, resp.status_code, headers)
    except Exception as e:
        return jsonify({"error": "Origin Server Unreachable", "details": str(e)}), 502

@app.route('/')
def dashboard():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Aegis Core - Enterprise WAF & Database-Driven SaaS</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans antialiased">
        <nav class="border-b border-slate-800 bg-slate-900/50 backdrop-blur sticky top-0 z-50 px-6 py-4 flex justify-between items-center">
            <div class="flex items-center space-x-3">
                <div class="bg-cyan-500/10 border border-cyan-500/30 p-2 rounded-lg text-cyan-400">
                    <i class="fa-solid fa-shield-halved text-xl"></i>
                </div>
                <div>
                    <h1 class="font-bold text-lg tracking-wide text-cyan-400">AEGIS CORE</h1>
                    <p class="text-xs text-slate-400">PostgreSQL Powered • Enterprise WAF</p>
                </div>
            </div>
            <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <span class="w-2 h-2 mr-2 bg-emerald-400 rounded-full animate-pulse"></span> System Online
            </span>
        </nav>
        <main class="p-6 max-w-7xl mx-auto space-y-6">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div class="bg-slate-900/80 border border-slate-800 p-5 rounded-xl shadow-lg">
                    <p class="text-sm font-medium text-slate-400">Total Intercepted Threats</p>
                    <h3 id="threatCount" class="text-3xl font-extrabold text-cyan-400 mt-2">0</h3>
                    <span class="text-xs text-emerald-400 mt-1 inline-block"><i class="fa-solid fa-shield"></i> Active Threat Counter</span>
                </div>
                <div class="bg-slate-900/80 border border-slate-800 p-5 rounded-xl shadow-lg">
                    <p class="text-sm font-medium text-slate-400">Protection Engine</p>
                    <h3 class="text-xl font-bold text-slate-200 mt-2">AI Patch Advisor™</h3>
                    <span class="text-xs text-cyan-400 mt-1 inline-block">Active & Providing Fixes</span>
                </div>
                <div class="bg-slate-900/80 border border-slate-800 p-5 rounded-xl shadow-lg">
                    <p class="text-sm font-medium text-slate-400">Storage Mode</p>
                    <h3 class="text-xl font-bold text-emerald-400 mt-2">PostgreSQL / Fallback</h3>
                    <span class="text-xs text-slate-400 mt-1 inline-block">Zero-Gated Core</span>
                </div>
            </div>

            <div class="bg-slate-900/80 border border-slate-800 rounded-xl shadow-lg overflow-hidden">
                <div class="px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                    <h2 class="font-semibold text-slate-200 flex items-center">
                        <i class="fa-solid fa-triangle-exclamation text-amber-400 mr-2"></i> Live Security Forensics & Logs
                    </h2>
                    <button onclick="fetchLogs()" class="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1.5 rounded-lg border border-slate-700 transition">
                        <i class="fa-solid fa-rotate mr-1"></i> Refresh Logs
                    </button>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse">
                        <thead>
                            <tr class="border-b border-slate-800 text-xs font-semibold text-slate-400 uppercase bg-slate-950/50">
                                <th class="px-6 py-3">Timestamp</th>
                                <th class="px-6 py-3">Attacker IP</th>
                                <th class="px-6 py-3">Target Path</th>
                                <th class="px-6 py-3">Threat Detected</th>
                                <th class="px-6 py-3">AI Patch Solution</th>
                            </tr>
                        </thead>
                        <tbody id="logTableBody" class="divide-y divide-slate-800 text-sm">
                            <tr>
                                <td colspan="5" class="px-6 py-8 text-center text-slate-500">
                                    <i class="fa-solid fa-shield text-3xl mb-2 text-slate-600 block"></i>
                                    No attacks recorded yet. System is safe and monitoring traffic.
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </main>
        <script>
            async function fetchLogs() {
                try {
                    const response = await fetch('/api/v1/security/logs');
                    const data = await response.json();
                    document.getElementById('threatCount').innerText = data.total_threats_intercepted;
                    const tbody = document.getElementById('logTableBody');
                    tbody.innerHTML = '';
                    if (data.recent_forensic_logs.length === 0) {
                        tbody.innerHTML = `<tr><td colspan="5" class="px-6 py-8 text-center text-slate-500">No attacks recorded yet.</td></tr>`;
                        return;
                    }
                    data.recent_forensic_logs.forEach(log => {
                        const row = document.createElement('tr');
                        row.className = "hover:bg-slate-800/50 transition";
                        row.innerHTML = `
                            <td class="px-6 py-4 text-xs text-slate-400">${log.timestamp}</td>
                            <td class="px-6 py-4 font-mono text-cyan-400">${log.ip}</td>
                            <td class="px-6 py-4 font-mono text-slate-300">${log.path}</td>
                            <td class="px-6 py-4"><span class="bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded text-xs font-medium">${log.threat}</span></td>
                            <td class="px-6 py-4 text-xs text-amber-300">${log.ai_patch || 'N/A'}</td>
                        `;
                        tbody.appendChild(row);
                    });
                } catch (error) {
                    console.error("Error fetching security logs:", error);
                }
            }
            setInterval(fetchLogs, 5000);
            fetchLogs();
        </script>
    </body>
    </html>
    """
    return render_template_string(html_content)

@app.route('/api/v1/security/logs', methods=['GET'])
def get_security_logs():
    logs = list(FALLBACK_LOGS)
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, ip, path, threat, ai_patch FROM security_logs ORDER BY id DESC LIMIT 15")
            rows = cursor.fetchall()
            for row in rows:
                logs.append({
                    "timestamp": row[0],
                    "ip": row[1],
                    "path": row[2],
                    "threat": row[3],
                    "ai_patch": row[4]
                })
            cursor.close()
            conn.close()
    except Exception as e:
        print("Failed to fetch logs from DB:", e)

    return jsonify({
        "total_threats_intercepted": len(logs),
        "recent_forensic_logs": logs[:15]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
