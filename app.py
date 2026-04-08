import streamlit as st
import joblib
import numpy as np

model = joblib.load("ids_model.pkl")

st.set_page_config(page_title="Intrusion Detection", layout="centered")

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

username = st.text_input("👤 Username")
password = st.text_input("🔑 Password", type="password")

if st.button("Login"):
    if username == "admin" and password == "1234":
        st.success("✅ Login Successful")

        st.subheader("📡 Enter Network Features")

        inputs = []
        num_features = model.n_features_in_

        for i in range(num_features):
            val = st.number_input(f"Feature {i+1}", value=0.0)
            inputs.append(val)

        if st.button("🚀 Detect Intrusion"):
            prediction = model.predict([inputs])

            if prediction[0] == 0:
                st.success("🟢 Normal Traffic")
            else:
                st.error("🔴 Intrusion Detected!")

    else:
        st.error("❌ Invalid Login")
