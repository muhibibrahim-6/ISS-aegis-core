import os
import time
import re
import requests
from collections import defaultdict
from flask import Flask, jsonify, request, render_template_string, Response

app = Flask(__name__)

# --- 1. Configuration & Storage ---
# ডিসকর্ড ওয়েবহুক ইউআরএল (এখানে আপনার ডিসকর্ড চ্যানেলের ওয়েবহুক লিংক বসাবেন)
DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL_HERE"

# রেজিস্টার্ড কাস্টমার বা ক্লায়েন্ট ডাটাবেজ
CUSTOMERS = {
    "aegis_live_key_999": {"client_name": "Acme Corp", "domain": "acme.com", "plan": "Enterprise"},
    "aegis_live_key_123": {"client_name": "CyberShop", "domain": "cybershop.bd", "plan": "Pro"}
}

# কাস্টমারদের রিয়েল সার্ভার ম্যাপিং (রিভার্স প্রক্সির জন্য)
ORIGIN_SERVER_MAP = {
    "acme.com": "http://192.168.1.50:8000",
}

request_history = defaultdict(list)
BLOCKED_IPS = set()
blocked_until = {}
SECURITY_LOGS = []

BLOCK_DURATION = 300

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

# --- 2. Core Security & AI Patch Engine ---
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
        return  # লিংক সেট না থাকলে এড়িয়ে যাবে
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

# --- 3. Firewall Middleware ---
@app.before_request
def aegis_firewall_middleware():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    path = request.path
    
    # ড্যাশবোর্ড, লগ এপিআই এবং স্ট্যাটিক রুটগুলোকে ফায়ারওয়াল চেকিং থেকে মুক্ত রাখা
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
        
        log_entry = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(current_time)),
            "ip": client_ip,
            "path": path,
            "threat": threat_type,
            "ai_patch_advisor": patch_advice
        }
        SECURITY_LOGS.insert(0, log_entry)
        
        # ডিসকর্ডে নোটিফিকেশন পাঠানো
        send_discord_alert(log_entry)
        
        return jsonify({
            "error": "Web Application Firewall Triggered",
            "threat_detected": threat_type,
            "action": "IP Blocked & Forensic Logged",
            "ai_developer_advisor": patch_advice
        }), 403

# --- 4. Reverse Proxy Route for Customers ---
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

# --- 5. Dashboard UI & Logs API ---
@app.route('/')
def dashboard():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Aegis Core - Enterprise WAF & SaaS Dashboard</title>
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
                    <p class="text-xs text-slate-400">International System Security • Enterprise WAF</p>
                </div>
            </div>
            <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <span class="w-2 h-2 mr-2 bg-emerald-400 rounded-full animate-pulse"></span> WAF Active & Protected
            </span>
        </nav>
        <main class="p-6 max-w-7xl mx-auto space-y-6">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div class="bg-slate-900/80 border border-slate-800 p-5 rounded-xl shadow-lg">
                    <p class="text-sm font-medium text-slate-400">Total Intercepted Threats</p>
                    <h3 id="threatCount" class="text-3xl font-extrabold text-cyan-400 mt-2">0</h3>
                    <span class="text-xs text-emerald-400 mt-1 inline-block"><i class="fa-solid fa-arrow-up"></i> Real-time tracking</span>
                </div>
                <div class="bg-slate-900/80 border border-slate-800 p-5 rounded-xl shadow-lg">
                    <p class="text-sm font-medium text-slate-400">Protection Engine</p>
                    <h3 class="text-xl font-bold text-slate-200 mt-2">AI Patch Advisor™</h3>
                    <span class="text-xs text-cyan-400 mt-1 inline-block">Active & Providing Fixes</span>
                </div>
                <div class="bg-slate-900/80 border border-slate-800 p-5 rounded-xl shadow-lg">
                    <p class="text-sm font-medium text-slate-400">System Status</p>
                    <h3 class="text-xl font-bold text-emerald-400 mt-2">100% Operational</h3>
                    <span class="text-xs text-slate-400 mt-1 inline-block">Zero-Gated Core</span>
                </div>
            </div>

            <!-- Pricing & SaaS Section -->
            <div class="bg-slate-900/80 border border-slate-800 p-6 rounded-xl shadow-lg">
                <h2 class="text-lg font-bold text-cyan-400 mb-4"><i class="fa-solid fa-tags mr-2"></i> Enterprise SaaS Plans</h2>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div class="bg-slate-950 p-4 rounded-lg border border-slate-800">
                        <h3 class="font-bold text-slate-200">Starter WAF</h3>
                        <p class="text-2xl font-extrabold text-cyan-400 mt-2">$29<span class="text-xs text-slate-400">/mo</span></p>
                        <p class="text-xs text-slate-400 mt-2">SQLi & XSS Protection + Rate Limiting</p>
                    </div>
                    <div class="bg-slate-950 p-4 rounded-lg border-2 border-cyan-500">
                        <span class="bg-cyan-500 text-slate-950 text-[10px] font-bold px-2 py-0.5 rounded">POPULAR</span>
                        <h3 class="font-bold text-slate-200 mt-1">Business Pro</h3>
                        <p class="text-2xl font-extrabold text-cyan-400 mt-2">$79<span class="text-xs text-slate-400">/mo</span></p>
                        <p class="text-xs text-slate-400 mt-2">AI Patch Advisor + Discord Alerts</p>
                    </div>
                    <div class="bg-slate-950 p-4 rounded-lg border border-slate-800">
                        <h3 class="font-bold text-slate-200">Global Enterprise</h3>
                        <p class="text-2xl font-extrabold text-cyan-400 mt-2">$199<span class="text-xs text-slate-400">/mo</span></p>
                        <p class="text-xs text-slate-400 mt-2">Dedicated Proxy Node + Custom Rules</p>
                    </div>
                </div>
            </div>

            <div class="bg-slate-900/80 border border-slate-800 rounded-xl shadow-lg overflow-hidden">
                <div class="px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                    <h2 class="font-semibold text-slate-200 flex items-center">
                        <i class="fa-solid fa-triangle-exclamation text-amber-400 mr-2"></i> Live Security Forensics & AI Patch Log
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
                        let aiAdviceHtml = `<span class="text-slate-500">N/A</span>`;
                        if (log.ai_patch_advisor) {
                            aiAdviceHtml = `
                                <div class="bg-slate-950 p-2.5 rounded border border-slate-800 space-y-1">
                                    <p class="text-xs text-amber-400 font-medium"><i class="fa-solid fa-wand-magic-sparkles"></i> ${log.ai_patch_advisor.developer_fix}</p>
                                    <code class="text-[11px] bg-slate-900 text-cyan-300 p-1 rounded block overflow-x-auto">${log.ai_patch_advisor.secure_code_example}</code>
                                </div>
                            `;
                        }
                        row.innerHTML = `
                            <td class="px-6 py-4 text-xs text-slate-400">${log.timestamp}</td>
                            <td class="px-6 py-4 font-mono text-cyan-400">${log.ip}</td>
                            <td class="px-6 py-4 font-mono text-slate-300">${log.path}</td>
                            <td class="px-6 py-4"><span class="bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded text-xs font-medium">${log.threat}</span></td>
                            <td class="px-6 py-4">${aiAdviceHtml}</td>
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
    return jsonify({
        "total_threats_intercepted": len(SECURITY_LOGS),
        "recent_forensic_logs": SECURITY_LOGS[:15]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
