import streamlit as st
from dashboard.components.ui import inject_custom_css, render_banner
from dashboard.components.auth import check_authentication, clear_session, api_post

# Page configuration
st.set_page_config(page_title="Incident Response playbooks", page_icon="🚨", layout="wide")
inject_custom_css()

# Authentication Guard
if not check_authentication():
    st.stop()

# Sidebar Controls
st.sidebar.markdown("### 🛡️ SOC CONTROL CENTER")
st.sidebar.markdown(f"User: **{st.session_state.username}**")
st.sidebar.markdown(f"Role: `{st.session_state.user_role}`")
st.sidebar.markdown(f"Organization: **{st.session_state.org_name}**")

if st.sidebar.button("Log Out", key="logout_ir_page", use_container_width=True):
    clear_session()
    st.rerun()

render_banner(
    "AI Incident Response & Prioritization",
    "Rank vulnerability patch sequences and instantly generate firewall containment scripts"
)

# Role check: viewer cannot access playbooks/priorities
is_authorized = st.session_state.user_role in ["Admin", "Analyst", "Manager"]

if not is_authorized:
    st.warning("Your role (Viewer) does not have permissions to access scheduling priorities or compile containment playbooks.")
    st.stop()

tab1, tab2 = st.tabs(["🎯 AI Patch Prioritizer", "🚨 Containment Playbooks"])

with tab1:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.subheader("🎯 Compute Priority Matrix")
    st.markdown("Generates a prioritized remediation schedule by scoring active CVEs against exploit probability, KEV status, and organization importance.")
    
    if st.button("Generate Patch Prioritization Schedule", use_container_width=True):
        with st.spinner("Calculating threat priority score parameters..."):
            result = api_post("/prioritize")
            
        if result and "report" in result:
            st.success("Prioritization calculations complete.")
            st.markdown(result["report"])
        else:
            st.error("Failed to run prioritize calculation or no threat records registered.")
    st.markdown('</div>', unsafe_allow_html=True)

with tab2:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.subheader("🚨 Generate Incident Response Containment Playbook")
    st.markdown("Instantly compile localized mitigation guides, Snort rules, and Splunk queries for active threat exposures.")
    
    cve_id = st.text_input("Enter Active CVE ID (e.g. CVE-2023-38606)")
    
    if st.button("Compile Incident Response Playbook", use_container_width=True):
        if not cve_id:
            st.error("Please enter a CVE ID.")
        else:
            with st.spinner(f"Compiling playbook for {cve_id}..."):
                res = api_post(f"/incident-response/{cve_id.strip()}")
                
            if res and "playbook" in res:
                st.success(f"Playbook generated for {cve_id}!")
                st.markdown(res["playbook"])
            else:
                st.error(f"Failed to generate playbook. Verify CVE ID belongs to your tenant registry.")
    st.markdown('</div>', unsafe_allow_html=True)
