from flask import Flask, render_template_string, request, Response
import requests

app = Flask(__name__)

# হোমপেজের জন্য এইচটিএমএল টেমপ্লেট (ছবি এবং সোশ্যাল মিডিয়া লিংকসহ)
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

    <h1>Welcome to ISS Antivirus & Cloud Security</h1>
    <p>Protecting your digital assets with advanced firewall & proxy routing.</p>

    <!-- হোমপেজে সিকিউরিটি ছবিগুলো যোগ করা হলো -->
    <h2>Security Infrastructure & Overview</h2>
    <div class="gallery">
        <!-- আপনার প্রোভাইড করা ছবির ফাইলগুলোর নাম অনুযায়ী পাথ সেট করা হয়েছে -->
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

@app.route('/')
def home():
    return render_template_string(HOME_PAGE_TEMPLATE)

# প্রক্সি রাউট যা আপনার অ্যান্টিভাইরাস ক্লাউড সাইটকে রাউট করবে
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
