import os
import streamlit as st
import requests
from typing import Optional, Any

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
            clear_session()
            st.rerun()
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        st.error(f"API Connection Error (GET {endpoint}): {str(e)}")
        return None

def api_post(endpoint: str, json_data: Optional[dict] = None, files: Optional[dict] = None, stream: bool = False) -> Optional[Any]:
    """
    Perform authenticated POST request to backend.
    """
    url = f"{BACKEND_URL}{endpoint}"
    headers = get_auth_headers()
    try:
        if files:
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
        
        try:
            err = response.json().get("detail", response.text)
        except Exception:
            err = response.text
        st.warning(f"Backend Notification ({response.status_code}): {err}")
        return None
    except Exception as e:
        st.error(f"API Error (POST {endpoint}): {str(e)}")
        return None

def payload_is_file(response: requests.Response) -> bool:
    """Check if response headers represent a file download."""
    content_type = response.headers.get("content-type", "")
    return "application/pdf" in content_type or "attachment" in response.headers.get("content-disposition", "")

def clear_session():
    """Wipes authentication keys from session state."""
    st.session_state["authenticated"] = False
    st.session_state["access_token"] = None
    st.session_state["token"] = None
    st.session_state["user_role"] = None
    st.session_state["role"] = None
    st.session_state["username"] = None
    st.session_state["org_name"] = None

def check_authentication() -> bool:
    """
    Verifies if user is logged in. If not, displays the clean ThreatScope login view.
    """
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if "access_token" not in st.session_state:
        st.session_state["access_token"] = None
    if "user_role" not in st.session_state:
        st.session_state["user_role"] = None
    if "username" not in st.session_state:
        st.session_state["username"] = None
    if "org_name" not in st.session_state:
        st.session_state["org_name"] = None

    if not st.session_state["authenticated"]:
        show_login_interface()
        return False
    return True

def show_login_interface():
    """
    Renders ThreatScope Dark SOC authentication panel.
    """
    st.markdown(
        """
        <div style="max-width: 480px; margin: 40px auto 24px auto; text-align: center;">
            <div style="display: inline-flex; align-items: center; justify-content: center; width: 48px; height: 48px; border-radius: 10px; background: linear-gradient(135deg, rgba(45, 212, 191, 0.2) 0%, rgba(56, 189, 248, 0.15) 100%); border: 1px solid #2DD4BF; color: #2DD4BF; margin-bottom: 12px;">
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#2DD4BF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"/>
                    <path d="M9 12l2 2 4-4"/>
                </svg>
            </div>
            <h2 style="font-size: 1.6rem; font-weight: 700; color: #E8EEF7; margin-bottom: 4px; letter-spacing: -0.01em;">
                ThreatScope
            </h2>
            <p style="font-size: 0.85rem; color: #9AAAC0; margin-top: 0;">
                Cybersecurity Intelligence & Risk Operations
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    _, col, _ = st.columns([1, 1.3, 1])
    with col:
        st.markdown(
            """
            <div class="soc-card" style="padding: 1.75rem;">
                <div style="font-size: 0.95rem; font-weight: 600; color: #E8EEF7; margin-bottom: 12px; border-bottom: 1px solid #1E2D47; padding-bottom: 8px;">
                    Analyst Authentication
                </div>
            """,
            unsafe_allow_html=True
        )

        st.caption("Evaluation Mode — Quick Select Role:")
        preset_cols = st.columns(4)
        with preset_cols[0]:
            if st.button("Admin", key="btn_admin", use_container_width=True):
                st.session_state["login_user"] = "admin"
                st.session_state["login_pwd"] = "admin123"
        with preset_cols[1]:
            if st.button("Analyst", key="btn_analyst", use_container_width=True):
                st.session_state["login_user"] = "analyst"
                st.session_state["login_pwd"] = "analyst123"
        with preset_cols[2]:
            if st.button("Manager", key="btn_manager", use_container_width=True):
                st.session_state["login_user"] = "manager"
                st.session_state["login_pwd"] = "manager123"
        with preset_cols[3]:
            if st.button("Auditor", key="btn_auditor", use_container_width=True):
                st.session_state["login_user"] = "viewer"
                st.session_state["login_pwd"] = "viewer123"

        default_user = st.session_state.get("login_user", "admin")
        default_pwd = st.session_state.get("login_pwd", "admin123")

        username = st.text_input("Username", value=default_user, key="input_username")
        password = st.text_input("Password", value=default_pwd, type="password", key="input_password")

        st.write("")
        if st.button("Authenticate to ThreatScope Console", use_container_width=True, type="primary"):
            if not username or not password:
                st.error("Please provide both username and password.")
            else:
                url = f"{BACKEND_URL}/auth/login"
                try:
                    with st.spinner("Verifying credentials against security database..."):
                        response = requests.post(
                            url, 
                            data={"username": username.strip(), "password": password.strip()},
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
                        raw_org = data.get("org_name")
                        st.session_state["org_name"] = raw_org if raw_org else "Local Lab"
                        st.success(f"Access granted. Initializing session for {data['username']} ({data['role']})...")
                        st.rerun()
                    else:
                        st.error("Authentication failed: Invalid credentials or account deactivated.")
                except Exception as e:
                    st.error(f"Failed to connect to authentication API: {str(e)}")

        st.markdown(
            """
            <div style="margin-top: 16px; font-size: 0.72rem; color: #9AAAC0; line-height: 1.4; border-top: 1px solid #1E2D47; padding-top: 10px;">
                🔒 All session telemetry is isolated per tenant organization with row-level security.
            </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.stop()
