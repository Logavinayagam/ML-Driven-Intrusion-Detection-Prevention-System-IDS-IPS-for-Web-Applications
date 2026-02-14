from flask import Flask, request, jsonify
import os
import time
import re

app = Flask(__name__)

# ============================
# SECURITY CONFIG
# ============================

BLOCK_DURATION = 600  # 10 minutes
MAX_LOGIN_ATTEMPTS = 5
MAX_REQUESTS_PER_10_SEC = 20

blocked_ips = {}        # {ip: block_time}
login_attempts = {}     # {ip: attempts}
request_times = {}      # {ip: [timestamps]}
attack_counter = 0
attack_logs = []

# ============================
# HELPER FUNCTIONS
# ============================

def block_ip(ip, reason):
    global attack_counter
    blocked_ips[ip] = time.time()
    attack_counter += 1
    attack_logs.append(f"{reason} from {ip}")

def is_ip_blocked(ip):
    if ip in blocked_ips:
        if time.time() - blocked_ips[ip] > BLOCK_DURATION:
            del blocked_ips[ip]
            login_attempts[ip] = 0
            return False
        return True
    return False

def detect_sql_injection(text):
    patterns = [
        r"(\bor\b.+\=)",
        r"(\bunion\b)",
        r"(\bdrop\b)",
        r"(--)",
        r"(\bselect\b)"
    ]
    return any(re.search(p, text.lower()) for p in patterns)

def detect_xss(text):
    return "<script>" in text.lower()

def detect_path_traversal(text):
    return "../" in text

def detect_command_injection(text):
    return any(char in text for char in [";", "|", "&", "`"])

def detect_dos(ip):
    now = time.time()
    if ip not in request_times:
        request_times[ip] = []

    request_times[ip].append(now)
    request_times[ip] = [t for t in request_times[ip] if now - t < 10]

    return len(request_times[ip]) > MAX_REQUESTS_PER_10_SEC

# ============================
# LOGIN API
# ============================

@app.route("/api/login", methods=["POST"])
def api_login():
    ip = request.remote_addr
    data = request.json

    username = data.get("username", "")
    password = data.get("password", "")
    role = data.get("role", "user")

    # Block check
    if is_ip_blocked(ip):
        return jsonify({
            "status": "blocked",
            "reason": "IP temporarily blocked"
        }), 403

    # DoS detection
    if detect_dos(ip):
        block_ip(ip, "DoS attack detected")
        return jsonify({
            "status": "blocked",
            "reason": "DoS attack detected"
        }), 403

    # Injection checks
    combined_input = username + password

    if detect_sql_injection(combined_input):
        block_ip(ip, "SQL Injection detected")
        return jsonify({
            "status": "blocked",
            "reason": "SQL Injection detected"
        }), 403

    if detect_xss(combined_input):
        block_ip(ip, "XSS attack detected")
        return jsonify({
            "status": "blocked",
            "reason": "XSS attack detected"
        }), 403

    if detect_path_traversal(combined_input):
        block_ip(ip, "Path Traversal detected")
        return jsonify({
            "status": "blocked",
            "reason": "Path Traversal detected"
        }), 403

    if detect_command_injection(combined_input):
        block_ip(ip, "Command Injection detected")
        return jsonify({
            "status": "blocked",
            "reason": "Command Injection detected"
        }), 403

    # Brute force detection
    if ip not in login_attempts:
        login_attempts[ip] = 0

    login_attempts[ip] += 1

    if login_attempts[ip] > MAX_LOGIN_ATTEMPTS:
        block_ip(ip, "Brute Force detected")
        return jsonify({
            "status": "blocked",
            "reason": "Brute Force detected"
        }), 403

    # Role abuse detection
    if role == "user" and username == "admin":
        block_ip(ip, "Role Abuse detected")
        return jsonify({
            "status": "blocked",
            "reason": "Role Abuse detected"
        }), 403

    # Demo credential validation
    if username == "admin" and password == "admin123":
        login_attempts[ip] = 0
        return jsonify({
            "status": "success",
            "message": "Login successful"
        })

    return jsonify({
        "status": "failed",
        "message": "Invalid credentials"
    }), 401

# ============================
# DASHBOARD API
# ============================

@app.route("/api/dashboard")
def dashboard():
    return jsonify({
        "total_attacks": attack_counter,
        "blocked_ips": list(blocked_ips.keys()),
        "attack_logs": attack_logs
    })

# ============================
# RESET API
# ============================

@app.route("/api/reset", methods=["POST"])
def reset():
    blocked_ips.clear()
    login_attempts.clear()
    request_times.clear()
    attack_logs.clear()
    global attack_counter
    attack_counter = 0

    return jsonify({"status": "reset successful"})

# ============================
# HEALTH CHECK
# ============================

@app.route("/")
def home():
    return jsonify({"message": "Hybrid IDS + IPS Backend Running"})

# ============================
# RUN SERVER
# ============================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
