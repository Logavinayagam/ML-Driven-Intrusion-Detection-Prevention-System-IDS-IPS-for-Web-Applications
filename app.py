from flask import Flask, request, jsonify
import pickle
import pandas as pd
import os

# ============================
# LOAD MODEL
# ============================

model = pickle.load(open("ids_model.pkl", "rb"))
model_columns = pickle.load(open("model_columns.pkl", "rb"))

app = Flask(__name__)

# ============================
# GLOBAL SECURITY STATE
# ============================

blocked_ips = set()
login_attempts = {}
attack_counter = 0
attack_logs = []

# ============================
# IDS + IPS API ENDPOINT
# ============================

@app.route("/api/login", methods=["POST"])
def api_login():
    global attack_counter

    data = request.json
    username = data.get("username")
    password = data.get("password")

    ip = request.remote_addr

    # IPS: Block check
    if ip in blocked_ips:
        return jsonify({
            "status": "blocked",
            "reason": "IP blocked by IPS"
        }), 403

    # Track brute force
    if ip not in login_attempts:
        login_attempts[ip] = 0

    login_attempts[ip] += 1

    if login_attempts[ip] > 5:
        blocked_ips.add(ip)
        attack_counter += 1
        attack_logs.append(f"Brute force detected from {ip}")

        return jsonify({
            "status": "blocked",
            "reason": "Brute force detected"
        }), 403

    # Simulated normal login validation
    if username == "admin" and password == "admin123":
        login_attempts[ip] = 0
        return jsonify({
            "status": "success",
            "message": "Login successful"
        })

    # Wrong credentials → count but don't block immediately
    return jsonify({
        "status": "failed",
        "message": "Invalid credentials"
    }), 401


# ============================
# DASHBOARD API
# ============================

@app.route("/api/dashboard", methods=["GET"])
def api_dashboard():
    return jsonify({
        "total_attacks": attack_counter,
        "blocked_ips": list(blocked_ips),
        "attack_logs": attack_logs
    })


# ============================
# HEALTH CHECK
# ============================

@app.route("/")
def home():
    return jsonify({
        "message": "IDS + IPS Backend Running"
    })


# ============================
# RUN SERVER
# ============================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
