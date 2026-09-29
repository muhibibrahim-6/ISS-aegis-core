import os
from flask import Flask, jsonify
import time
from collections import defaultdict
import re

app = Flask(__name__)

# --- Firewall Core Logic ---
request_history = defaultdict(list)
BLOCKED_IPS = set()
blocked_until = {}
SECURITY_LOGS = []

MAX_REQUESTS_PER_MINUTE = 60
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

def generate_ai_patch_advice(threat_type):
    if "SQL Injection" in threat_type:
        return {
            "vulnerability": "SQL Injection",
            "risk_level": "CRITICAL",
            "developer_fix": "Use Parameterized Queries or ORM (like SQLAlchemy) instead of concatenating raw strings.",
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

@app.before_request
def aegis_firewall_middleware():
    from flask import request
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_time = time.time()
    path = request.path
    
    # ড্যাশবোর্ড ও লগ এপিআই রুটগুলোকে ফায়ারওয়াল চেকিং থেকে মুক্ত রাখা
    if path == '/' or path == '/api/v1/security/logs':
        return
        
    if client_ip in BLOCKED_IPS:
        if current_time < blocked_until.get(client_ip, 0):
            return jsonify({
                "error": "Access Denied by Aegis Core",
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
        
        return jsonify({
            "error": "Web Application Firewall Triggered",
            "threat_detected": threat_type,
            "action": "IP Blocked & Forensic Logged",
            "ai_developer_advisor": patch_advice
        }), 403

# --- Dashboard UI Route ---
@app.route('/')
def dashboard():
    return """
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
                <span class="w-2 h-2 mr-2 bg-emerald-400 rounded-full animate-pulse"></span> WAF Active
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

@app.route('/api/v1/security/logs', methods=['GET'])
def get_security_logs():
    return jsonify({
        "total_threats_intercepted": len(SECURITY_LOGS),
        "recent_forensic_logs": SECURITY_LOGS[:15]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
