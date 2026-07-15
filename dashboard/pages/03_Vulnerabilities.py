import streamlit as st
import pandas as pd
from dashboard.components.ui import inject_custom_css, render_banner
from dashboard.components.auth import check_authentication, clear_session, api_get

# Page configuration
st.set_page_config(page_title="Vulnerability Management", page_icon="🚨", layout="wide")
inject_custom_css()

# Authentication Guard
if not check_authentication():
    st.stop()

# Sidebar Controls
st.sidebar.markdown("### 🛡️ SOC CONTROL CENTER")
st.sidebar.markdown(f"User: **{st.session_state.username}**")
st.sidebar.markdown(f"Role: `{st.session_state.user_role}`")
st.sidebar.markdown(f"Organization: **{st.session_state.org_name}**")

if st.sidebar.button("Log Out", key="logout_vuln_page", use_container_width=True):
    clear_session()
    st.rerun()

render_banner(
    "Vulnerability Management Center",
    "Inspect, search, and filter organization-specific threat exposures"
)

# Search & Filters layout
st.markdown('<div class="glass-card">', unsafe_allow_html=True)
col_search, col_sev, col_kev = st.columns([2, 1, 1])

with col_search:
    search_query = st.text_input("🔍 Search (CVE ID, Vendor, Product, Title, Description)", value="")

with col_sev:
    severity_filter = st.selectbox(
        "Severity",
        options=["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

with col_kev:
    is_kev_filter = st.checkbox("🔥 CISA KEV (Actively Exploited Only)", value=False)

st.markdown('</div>', unsafe_allow_html=True)

# Fetching Data
params = {"limit": 100}
if search_query:
    params["search"] = search_query
if severity_filter != "All Severities":
    params["severity"] = severity_filter
if is_kev_filter:
    params["is_kev"] = True

with st.spinner("Querying vulnerability registry..."):
    vulnerabilities = api_get("/vulnerabilities", params=params)

if vulnerabilities:
    st.write(f"Showing **{len(vulnerabilities)}** matching vulnerabilities:")
    
    # Render table
    rows = []
    for v in vulnerabilities:
        rows.append({
            "CVE ID": v["cve_id"],
            "Description": v["description"] or "No description provided.",
            "CVSS": v["cvss_score"] if v["cvss_score"] is not None else "N/A",
            "EPSS": f"{v.get('epss_score', 0.0):.4%}",
            "Severity": v["severity"] or "UNKNOWN",
            "Vendor": v["vendor"]["name"] if v["vendor"] else "Unknown",
            "Product": v["product"]["name"] if v["product"] else "Unknown",
            "Exploit Status": "🔥 Active Exploit (KEV)" if v["is_kev"] else "No active exploits"
        })
        
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)
else:
    st.info("No vulnerabilities found matching your search or filters.")
