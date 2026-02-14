# Paste your COMPLETE final Flask code below this line

from flask import Flask, request, render_template_string
import pickle
import pandas as pd
import smtplib
from email.mime.text import MIMEText
import os

# Load model
model = pickle.load(open("ids_model.pkl", "rb"))
model_columns = pickle.load(open("model_columns.pkl", "rb"))

app = Flask(__name__)

blocked_ips = set()
login_attempts = {}
attack_counter = 0
attack_logs = []

def send_email_alert(message):
    pass  # Optional

login_page = """
<h2>🔐 Secure Login Portal</h2>
<form method="POST">
Username:<br><input type="text" name="username"><br><br>
Password:<br><input type="password" name="password"><br><br>
<input type="submit" value="Login">
</form>
<a href="/dashboard">Dashboard</a>
"""

@app.route("/", methods=["GET", "POST"])
def login():
    global attack_counter

    ip = request.remote_addr

    if ip in blocked_ips:
        return "<h3>🚫 Access Denied - IP Blocked</h3>"

    if request.method == "POST":
        if ip not in login_attempts:
            login_attempts[ip] = 0

        login_attempts[ip] += 1

        if login_attempts[ip] > 5:
            blocked_ips.add(ip)
            attack_counter += 1
            attack_logs.append(f"Brute Force detected from {ip}")
            return "<h3>🚨 Brute Force Detected! IP Blocked.</h3>"

        sample = pd.DataFrame([{col: 0 for col in model_columns}])
        prediction = model.predict(sample)[0]

        if prediction == 1:
            blocked_ips.add(ip)
            attack_counter += 1
            attack_logs.append(f"ML Attack detected from {ip}")
            return "<h3>🚨 ML Attack Detected! IP Blocked.</h3>"

        return "<h3>✅ Login Successful</h3>"

    return render_template_string(login_page)

@app.route("/dashboard")
def dashboard():
    return f"""
    <h2>🛡 Dashboard</h2>
    <p>Total Attacks: {attack_counter}</p>
    <p>Blocked IPs: {list(blocked_ips)}</p>
    <ul>
    {''.join([f"<li>{log}</li>" for log in attack_logs])}
    </ul>
    <a href="/">Back</a>
    """

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
