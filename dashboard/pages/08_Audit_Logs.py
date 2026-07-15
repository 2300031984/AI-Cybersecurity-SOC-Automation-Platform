import streamlit as st
import pandas as pd
from dashboard.components.ui import inject_custom_css, render_banner
from dashboard.components.auth import check_authentication, clear_session, api_get

# Page configuration
st.set_page_config(page_title="Audit Logs Dashboard", page_icon="⚙️", layout="wide")
inject_custom_css()

# Authentication Guard
if not check_authentication():
    st.stop()

# Sidebar Controls
st.sidebar.markdown("### 🛡️ SOC CONTROL CENTER")
st.sidebar.markdown(f"User: **{st.session_state.username}**")
st.sidebar.markdown(f"Role: `{st.session_state.user_role}`")
st.sidebar.markdown(f"Organization: **{st.session_state.org_name}**")

if st.sidebar.button("Log Out", key="logout_audit_page", use_container_width=True):
    clear_session()
    st.rerun()

render_banner(
    "Enterprise Security Audit Logs",
    "Inspect system modifications, authentication tracking, and administrative sync operations"
)

# Admin role guard
if st.session_state.user_role != "Admin":
    st.markdown('<div style="text-align: center; margin-top: 50px;">', unsafe_allow_html=True)
    st.error("🚫 Access Denied: You do not have sufficient administrative permissions to inspect audit ledger histories.")
    st.markdown('</div>', unsafe_allow_html=True)
    st.stop()

with st.spinner("Fetching security audit logs..."):
    audit_logs = api_get("/logs/audit")

if audit_logs:
    st.write(f"Showing **{len(audit_logs)}** audit events:")
    
    rows = []
    for log in audit_logs:
        rows.append({
            "Timestamp": pd.to_datetime(log.get("created_at")).strftime("%Y-%m-%d %H:%M:%S") if log.get("created_at") else "N/A",
            "Username": log.get("user", {}).get("username") if log.get("user") else "System",
            "Role": log.get("user", {}).get("role") if log.get("user") else "N/A",
            "Action": log.get("action"),
            "Resource Path": log.get("resource"),
            "Event Details": log.get("details"),
            "IP Address": log.get("ip_address") or "N/A"
        })
        
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)
else:
    st.info("No security audit events currently registered in the database.")
