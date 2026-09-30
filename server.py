@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    
    success_msg = None
    error_msg = None
    
    if request.method == 'POST':
        client_name = request.form.get('client_name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        domain = request.form.get('domain')
        api_key = request.form.get('api_key')
        origin_ip = request.form.get('origin_ip')
        plan = request.form.get('plan')
        
        try:
            conn = get_db_connection()
            if not conn:
                error_msg = "❌ ডেটাবেজ কানেকশন পাওয়া যায়নি! দয়া করে রেন্ডার (Render) ড্যাশবোর্ডে গিয়ে চেক করুন যে 'DATABASE_URL' এনভায়রনমেন্ট ভেরিয়েবল সঠিকভাবে যুক্ত করা আছে কি না।"
            else:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO customers (api_key, username, email, password, client_name, domain, plan, origin_ip) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (api_key, username, email, password, client_name, domain, plan, origin_ip)
                )
                conn.commit()
                cursor.close()
                conn.close()
                success_msg = f"✅ ক্লায়েন্ট '{client_name}' সফলভাবে ক্রিয়েট হয়েছে!"
        except Exception as e:
            error_msg = f"❌ ডেটাবেজ এরর: {e} (সম্ভবত এই API Key বা Domain আগে থেকেই ব্যবহার করা হয়েছে)"

    customers = []
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT api_key, username, email, client_name, domain, plan, origin_ip FROM customers")
            customers = cursor.fetchall()
            cursor.close()
            conn.close()
    except Exception as e:
        print("Admin DB Error:", e)

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Master Admin Dashboard - Aegis Core</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans">
        <nav class="border-b border-slate-800 bg-slate-900 px-6 py-4 flex justify-between items-center">
            <h1 class="font-bold text-cyan-400">AEGIS CORE • MASTER ADMIN (ibr@him)</h1>
            <a href="/admin/logout" class="text-xs text-red-400 hover:underline">Logout</a>
        </nav>
        <main class="p-6 max-w-7xl mx-auto space-y-6">
            {% if success_msg %}
            <div class="bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 p-4 rounded-lg text-sm font-medium">{{ success_msg }}</div>
            {% endif %}
            {% if error_msg %}
            <div class="bg-red-500/15 border border-red-500/30 text-red-400 p-4 rounded-lg text-sm font-medium">{{ error_msg }}</div>
            {% endif %}
            
            <div class="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
                <h2 class="text-lg font-bold text-cyan-400"><i class="fa-solid fa-user-plus mr-2"></i> Onboard New Client</h2>
                <form method="POST" class="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <input type="text" name="client_name" placeholder="Company Name" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="username" placeholder="Client Username" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="email" name="email" placeholder="Client Email" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="password" name="password" placeholder="Client Password" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="domain" placeholder="domain.com" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="api_key" placeholder="API Key (e.g. aegis_key_123)" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <input type="text" name="origin_ip" placeholder="Origin URL (https://site.com)" required class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                    <select name="plan" class="bg-slate-950 border border-slate-800 p-2.5 rounded text-xs">
                        <option>Starter</option>
                        <option>Pro</option>
                        <option>Enterprise</option>
                    </select>
                    <button type="submit" class="md:col-span-4 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold p-2.5 rounded text-xs transition">Create Client Account</button>
                </form>
            </div>

            <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
                <h2 class="text-lg font-bold text-cyan-400"><i class="fa-solid fa-users mr-2"></i> Registered Clients</h2>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs border-collapse">
                        <thead>
                            <tr class="border-b border-slate-800 text-slate-400 uppercase bg-slate-950">
                                <th class="p-3">Company</th>
                                <th class="p-3">Username</th>
                                <th class="p-3">Email</th>
                                <th class="p-3">Domain</th>
                                <th class="p-3">API Key</th>
                                <th class="p-3">Plan</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-800">
                            {% for c in customers %}
                            <tr>
                                <td class="p-3 font-semibold">{{ c[3] }}</td>
                                <td class="p-3 text-cyan-400">{{ c[1] }}</td>
                                <td class="p-3 text-slate-300">{{ c[2] }}</td>
                                <td class="p-3 text-cyan-400">{{ c[4] }}</td>
                                <td class="p-3 font-mono text-slate-400">{{ c[0] }}</td>
                                <td class="p-3">{{ c[5] }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </main>
    </body>
    </html>
    """, success_msg=success_msg, error_msg=error_msg, customers=customers)
