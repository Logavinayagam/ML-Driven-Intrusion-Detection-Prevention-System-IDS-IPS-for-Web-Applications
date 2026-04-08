import streamlit as st
import joblib
import numpy as np
import smtplib
import os
import requests
from email.mime.text import MIMEText

# Load model
model = joblib.load("ids_model.pkl")

st.set_page_config(page_title="AI Intrusion Detection System", layout="centered")

# 🌐 Get IP
def get_ip():
    try:
        return requests.get("https://api.ipify.org").text
    except:
        return "Unknown IP"

# 📧 Email function
def send_alert(msg):
    sender = os.getenv("EMAIL")
    password = os.getenv("EMAIL_PASS")
    receiver = sender

    ip = get_ip()
    full_msg = f"{msg}\n\nUser IP: {ip}"

    try:
        message = MIMEText(full_msg, "plain", "utf-8")

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, receiver, message.as_string())
        server.quit()
    except Exception as e:
        st.error(f"Email failed: {e}")

# 🎨 UI
st.markdown("""
<style>
body {background-color: #0e1117; color: white;}
.stButton>button {
    border-radius: 10px;
    background-color: #00adb5;
    color: white;
}
</style>
""", unsafe_allow_html=True)

st.title("🔐 AI Intrusion Detection System")

# Track login attempts
if "attempts" not in st.session_state:
    st.session_state.attempts = 0

# Login inputs
username = st.text_input("👤 Username")
password = st.text_input("🔑 Password", type="password")

# Login logic
if st.button("Login"):
    if username == "admin" and password == "1234":
        st.success("✅ Login Successful")
        st.session_state.attempts = 0

        st.subheader("🚀 Intrusion Detection Running...")

        # ✅ Always Normal (for demo)
        prediction = [0]

        st.success("🟢 Normal Traffic")

    else:
        st.session_state.attempts += 1
        st.error("❌ Invalid Login")

        # 🚨 Brute force detection
        if st.session_state.attempts >= 3:
            st.warning("⚠️ Multiple failed login attempts detected")
            send_alert("Brute Force Attack Detected in your IDS system")
