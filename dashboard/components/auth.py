import os
import streamlit as st
import requests
from typing import Optional, Any

# Resolve backend URL dynamically from environment (supporting docker network or local dev)
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000/api/v1")

def get_auth_headers() -> dict:
    """
    Builds authorization headers if access token exists in session state.
    """
    token = st.session_state.get("access_token")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}

def api_get(endpoint: str, params: Optional[dict] = None) -> Optional[Any]:
    """
    Perform authenticated GET request to backend.
    """
    url = f"{BACKEND_URL}{endpoint}"
    headers = get_auth_headers()
    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        if response.status_code == 401:
            # Token might be expired, log out or refresh
            clear_session()
            st.rerun()
        if response.status_code == 200:
            return response.json()
        logger_warn_response(endpoint, response)
        return None
    except Exception as e:
        st.error(f"API Error (GET {endpoint}): {str(e)}")
        return None

def api_post(endpoint: str, json_data: Optional[dict] = None, files: Optional[dict] = None, stream: bool = False) -> Optional[Any]:
    """
    Perform authenticated POST request to backend.
    """
    url = f"{BACKEND_URL}{endpoint}"
    headers = get_auth_headers()
    try:
        if files:
            # When sending files, requests sets content type boundary automatically, do not pass JSON
            response = requests.post(url, headers=headers, files=files, timeout=30, stream=stream)
        else:
            response = requests.post(url, headers=headers, json=json_data, timeout=30, stream=stream)
            
        if response.status_code == 401:
            clear_session()
            st.rerun()
        if response.status_code in {200, 201}:
            if stream or payload_is_file(response):
                return response.content
            return response.json()
        
        logger_warn_response(endpoint, response)
        return None
    except Exception as e:
        st.error(f"API Error (POST {endpoint}): {str(e)}")
        return None

def payload_is_file(response: requests.Response) -> bool:
    """Check if headers represent binary file download."""
    content_type = response.headers.get("content-type", "")
    return "application/pdf" in content_type or "attachment" in response.headers.get("content-disposition", "")

def logger_warn_response(endpoint: str, response: requests.Response):
    """Utility log error handler."""
    try:
        err_detail = response.json().get("detail", response.text)
    except Exception:
        err_detail = response.text
    st.warning(f"Backend returned code {response.status_code} for {endpoint}: {err_detail}")

def check_authentication() -> bool:
    """
    Verifies if user is logged in. If not, displays login page forms
    and halts other rendering.
    """
    # Initialize session state keys
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if "access_token" not in st.session_state:
        st.session_state["access_token"] = None
    if "user_role" not in st.session_state:
        st.session_state["user_role"] = None
    if "username" not in st.session_state:
        st.session_state["username"] = None

    if not st.session_state["authenticated"]:
        st.switch_page("pages/01_Login.py")
        return False
    return True

def clear_session():
    """Wipes authentication keys from session state."""
    st.session_state["authenticated"] = False
    st.session_state["access_token"] = None
    st.session_state["token"] = None
    st.session_state["user_role"] = None
    st.session_state["role"] = None
    st.session_state["username"] = None
    st.session_state["org_name"] = None

def show_login_interface():
    """
    Renders login template directly inside main view.
    """
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
        # Clean center layout columns
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
                    # Authenticate against FastAPI backend /login
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
                            st.rerun()
                        else:
                            st.error("Authentication failed: Invalid credentials or inactive account.")
                    except Exception as e:
                        st.error(f"Failed to connect to authentication backend: {str(e)}")
            st.markdown('</div>', unsafe_allow_html=True)
    st.stop() # Halt execution so page content is not rendered below
