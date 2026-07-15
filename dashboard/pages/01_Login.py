import os
import streamlit as st
import requests
from dashboard.components.ui import inject_custom_css

# Page configuration
st.set_page_config(page_title="SOC Portal Login", page_icon="🔑", layout="wide")
inject_custom_css()

# Resolve backend URL
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000/api/v1")

# Check if already authenticated
if st.session_state.get("authenticated", False):
    st.markdown('<div style="text-align: center; margin-top: 100px;">', unsafe_allow_html=True)
    st.success(f"You are already authenticated as **{st.session_state.username}** ({st.session_state.user_role})")
    if st.button("Go to Overview Dashboard", use_container_width=True):
        st.switch_page("pages/02_SOC_Overview.py")
    st.markdown('</div>', unsafe_allow_html=True)
else:
    st.markdown(
        """
        <div style="text-align: center; margin-top: 50px; margin-bottom: 30px;">
            <h1 style="color:#6366f1; font-size: 2.5rem; font-weight:800; margin-bottom:5px;">AI CYBERSECURITY PLATFORM</h1>
            <p style="color:#94a3b8; font-size:1.1rem;">SOC Automation & Threat Intelligence Center</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    with st.container():
        _, col, _ = st.columns([1, 2, 1])
        with col:
            st.markdown('<div class="glass-card">', unsafe_allow_html=True)
            st.subheader("System Authentication Log In")
            
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            
            if st.button("Log In", use_container_width=True):
                if not username or not password:
                    st.error("Please enter both username and password.")
                else:
                    url = f"{BACKEND_URL}/auth/login"
                    try:
                        response = requests.post(
                            url, 
                            data={"username": username, "password": password},
                            timeout=10
                        )
                        if response.status_code == 200:
                            data = response.json()
                            st.session_state["authenticated"] = True
                            st.session_state["access_token"] = data["access_token"]
                            st.session_state["token"] = data["access_token"]
                            st.session_state["user_role"] = data["role"]
                            st.session_state["role"] = data["role"]
                            st.session_state["username"] = data["username"]
                            st.session_state["org_name"] = data.get("org_name", "Global Registry")
                            st.success("Access Granted! Loading system dashboard...")
                            st.switch_page("pages/02_SOC_Overview.py")
                        else:
                            st.error("Authentication failed: Invalid credentials or inactive account.")
                    except Exception as e:
                        st.error(f"Failed to connect to authentication backend: {str(e)}")
            st.markdown('</div>', unsafe_allow_html=True)
