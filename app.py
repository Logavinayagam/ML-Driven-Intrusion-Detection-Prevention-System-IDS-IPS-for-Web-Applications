import streamlit as st
import joblib
import numpy as np
import smtplib
import os
from email.mime.text import MIMEText

# Load trained model
model = joblib.load("ids_model.pkl")

st.set_page_config(page_title="AI Intrusion Detection System", layout="centered")

# 📧 Email Alert Function (UTF-8 safe)
def send_alert(msg):
    sender = os.getenv("EMAIL")
    password = os.getenv("EMAIL_PASS")
    receiver = sender

    try:
        message = MIMEText(msg, "plain", "utf-8")

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, receiver, message.as_string())
        server.quit()
    except Exception as e:
        st.error(f"Email failed: {e}")

# 🎨 UI Styling
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

# Title
st.title("🔐 AI Intrusion Detection System")

# 🔁 Track login attempts
if "attempts" not in st.session_state:
    st.session_state.attempts = 0

# 🔐 Login Inputs
username = st.text_input("👤 Username")
password = st.text_input("🔑 Password", type="password")

# 🔐 Login Logic
if st.button("Login"):
    if username == "admin" and password == "1234":
        st.success("✅ Login Successful")
        st.session_state.attempts = 0

        st.subheader("🚀 Run Intrusion Detection")

        # 🔍 Detection Button
        if st.button("Detect Intrusion"):
            sample = np.zeros(model.n_features_in_).reshape(1, -1)
            prediction = model.predict(sample)

            if prediction[0] == 0:
                st.success("🟢 Normal Traffic")
            else:
                st.error("🔴 Intrusion Detected!")
                send_alert("Intrusion Detected in your IDS system")

    else:
        st.session_state.attempts += 1
        st.error("❌ Invalid Login")

        # 🚨 Brute Force Detection
        if st.session_state.attempts >= 3:
            st.warning("⚠️ Multiple failed login attempts detected")
            send_alert("Brute Force Attack Detected in your IDS system")
