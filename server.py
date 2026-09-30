from flask import Flask, render_template_string, request, Response, session, redirect, url_for
import requests

app = Flask(__name__)
app.secret_key = "muhib_secure_secret_key_change_this"  # সেশনের নিরাপত্তার জন্য সিক্রেট কি

# সিকিউরড হোমপেজ ও মাই প্রোফাইল পেজের টেমপ্লেট
HOME_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ISS Antivirus Cloud & Firewall</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            background-color: #0f172a; 
            color: #fff; 
            margin: 0; 
            padding: 20px; 
            text-align: center; 
        }
        h1 { color: #38bdf8; }
        p { color: #94a3b8; }
        .nav-bar { margin: 20px 0; }
        .nav-bar a { color: #f8fafc; background: #3b82f6; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold; }
        .nav-bar a:hover { background: #2563eb; }
        .gallery { 
            display: flex; 
            flex-wrap: wrap; 
            justify-content: center; 
            gap: 20px; 
            margin: 30px 0; 
        }
        .gallery img { 
            width: 300px; 
            height: 180px; 
            object-fit: cover; 
            border-radius: 8px; 
            border: 2px solid #3b82f6; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .social-links { 
            margin-top: 40px; 
            padding: 25px; 
            background: #1e293b; 
            border-radius: 12px; 
            display: inline-block; 
            box-shadow: 0 4px 10px rgba(0,0,0,0.4);
        }
        .social-links h3 { margin-top: 0; color: #f8fafc; }
        .social-links a { 
            color: #38bdf8; 
            margin: 0 15px; 
            text-decoration: none; 
            font-size: 18px; 
            font-weight: bold; 
        }
        .social-links a:hover { 
            text-decoration: underline; 
            color: #7dd3fc; 
        }
    </style>
</head>
<body>

    <div class="nav-bar">
        <a href="/">Home</a> | 
        <a href="/my-profile">My Profile / Admin Access</a>
    </div>

    <h1>Welcome to ISS Antivirus & Cloud Security</h1>
    <p>Protecting your digital assets with advanced firewall & proxy routing.</p>

    <!-- হোমপেজে সিকিউরিটি ছবিগুলো -->
    <h2>Security Infrastructure & Overview</h2>
    <div class="gallery">
        <img src="/static/images (6).jpeg" alt="Cloud Security Server">
        <img src="/static/images (5).jpeg" alt="Network Firewall Wall">
        <img src="/static/images (4).jpeg" alt="Malware Defense">
        <img src="/static/images (3).jpeg" alt="Traffic Routing Firewall">
    </div>

    <!-- সোশ্যাল মিডিয়া লিংকগুলো -->
    <div class="social-links">
        <h3>Connect With Me</h3>
        <a href="https://www.linkedin.com/in/Muhib%20Ibrahim" target="_blank">LinkedIn</a>
        <a href="https://www.instagram.com/mrshadow6000" target="_blank">Instagram</a>
        <a href="https://www.youtube.com/@Muhib%20Ibrahim" target="_blank">YouTube</a>
        <a href="https://medium.com/@muhibibra" target="_blank">Medium</a>
    </div>

</body>
</html>
"""

# মাই প্রোফাইল এবং লগইন/এডমিন প্যানেল টেমপ্লেট
PROFILE_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>My Profile & Control Panel</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #0f172a; color: #fff; margin: 0; padding: 40px; text-align: center; }
        .box { background: #1e293b; padding: 30px; border-radius: 10px; display: inline-block; width: 350px; box-shadow: 0 4px 10px rgba(0,0,0,0.5); }
        input { width: 90%; padding: 10px; margin: 10px 0; border-radius: 5px; border: 1px solid #475569; background: #0f172a; color: #fff; }
        button { background: #3b82f6; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; width: 100%; }
        button:hover { background: #2563eb; }
        .error { color: #f87171; font-size: 14px; }
        .dashboard { background: #065f46; padding: 20px; border-radius: 8px; margin-top: 20px; }
        a { color: #38bdf8; text-decoration: none; }
    </style>
</head>
<body>
    <p><a href="/">&larr; Back to Home</a></p>
    <div class="box">
        <h2>My Profile</h2>
        {% if not logged_in %}
            <p>Login to Access Admin Panel</p>
            {% if error %}
                <p class="error">{{ error }}</p>
            {% endif %}
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required><br>
                <input type="password" name="password" placeholder="Password" required><br>
                <button type="submit">Login / Verify</button>
            </form>
        {% else %}
            <div class="dashboard">
                <h3>🔒 Admin Panel Unlocked</h3>
                <p>Welcome, Admin Muhib Ibrahim!</p>
                <p>System Status: Protected & Running</p>
                <a href="/my-profile?logout=true" style="color: #fca5a5;">Logout</a>
            </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HOME_PAGE_TEMPLATE)

@app.route('/my-profile', methods=['GET', 'POST'])
def my_profile():
    error = None
    if request.args.get('logout'):
        session.pop('admin_logged_in', None)
        return redirect(url_for('my_profile'))

    if request.method == 'POST':
        # আপনার পছন্দমতো ইউজারনেম ও পাসওয়ার্ড এখানে সেট করে নিতে পারেন
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == "admin" and password == "muhib123":  # এখানে আপনার সিক্রেট ইউজারনেম ও পাসওয়ার্ড দিন
            session['admin_logged_in'] = True
        else:
            error = "Invalid Username or Password!"

    logged_in = session.get('admin_logged_in', False)
    return render_template_string(PROFILE_PAGE_TEMPLATE, logged_in=logged_in, error=error)

# প্রক্সি রাউট
@app.route('/proxy/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(subpath):
    target_url = f"https://iss-antivirus-cloud.onrender.com/{subpath}"
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
        return f"Proxy Error: {str(e)}", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
