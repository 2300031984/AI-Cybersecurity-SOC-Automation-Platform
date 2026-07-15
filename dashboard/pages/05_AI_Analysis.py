import streamlit as st
import pandas as pd
from dashboard.components.ui import inject_custom_css, render_banner
from dashboard.components.auth import check_authentication, clear_session, api_get, api_post

# Page configuration
st.set_page_config(page_title="AI Vulnerability Analysis", page_icon="🤖", layout="wide")
inject_custom_css()

# Authentication Guard
if not check_authentication():
    st.stop()

# Sidebar Controls
st.sidebar.markdown("### 🛡️ SOC CONTROL CENTER")
st.sidebar.markdown(f"User: **{st.session_state.username}**")
st.sidebar.markdown(f"Role: `{st.session_state.user_role}`")
st.sidebar.markdown(f"Organization: **{st.session_state.org_name}**")

if st.sidebar.button("Log Out", key="logout_analysis_page", use_container_width=True):
    clear_session()
    st.rerun()

render_banner(
    "AI Threat Analysis & Briefings",
    "Generate security assessments using localized Gemini RAG and compile multi-CVE PDF briefings"
)

# Role permission check
is_privileged = st.session_state.user_role in ["Admin", "Analyst"]

col_left, col_right = st.columns([1, 1])

with col_left:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.subheader("🤖 Trigger Live Gemini AI Analysis")
    if is_privileged:
        cve_to_analyze = st.text_input("Enter CVE ID (e.g. CVE-2023-38606)", value="")
        if st.button("Trigger Live Report", use_container_width=True):
            if not cve_to_analyze:
                st.error("Please enter a CVE ID.")
            else:
                with st.spinner("Invoking Gemini threat summarization engine..."):
                    res = api_post(f"/analysis/trigger/{cve_to_analyze.strip()}")
                if res:
                    st.success(f"Analysis complete for {cve_to_analyze}!")
                    st.write(f"**Executive Summary**: {res.get('executive_summary')}")
                    st.write(f"**Technical Analysis**: {res.get('technical_analysis')}")
                    st.write(f"**Containment Recommendations**: {res.get('recommendations')}")
                    st.write(f"**Priority Score**: `{res.get('patch_priority')}`")
                    st.rerun()
    else:
        st.warning("Your role (Viewer/Manager) does not have permissions to trigger new AI vulnerability analyses.")
    st.markdown('</div>', unsafe_allow_html=True)

with col_right:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.subheader("📄 Compile Threat Briefing Report")
    if is_privileged:
        cves_input = st.text_area("Enter CVE IDs (one per line or comma-separated)", value="")
        report_format = st.selectbox("Export Format", ["PDF", "HTML", "Markdown"])
        
        if st.button("Compile & Generate Report", use_container_width=True):
            cve_list = [c.strip() for c in cves_input.replace(",", "\n").split("\n") if c.strip()]
            if not cve_list:
                st.error("Please enter at least one CVE ID.")
            else:
                with st.spinner("Compiling database records into report format..."):
                    report_bytes = api_post(
                        "/analysis/report",
                        json_data={"cve_ids": cve_list, "format": report_format.lower()}
                    )
                if report_bytes:
                    st.success("Report compiled successfully!")
                    
                    # Convert to byte data
                    if report_format == "PDF":
                        st.download_button(
                            label="📥 Download PDF Briefing",
                            data=report_bytes,
                            file_name="executive_briefing.pdf",
                            mime="application/pdf",
                            use_container_width=True
                        )
                    elif report_format == "Markdown":
                        st.download_button(
                            label="📥 Download Markdown Briefing",
                            data=report_bytes,
                            file_name="executive_briefing.md",
                            mime="text/markdown",
                            use_container_width=True
                        )
                        st.text_area("Report Preview", value=report_bytes.decode("utf-8") if isinstance(report_bytes, bytes) else report_bytes, height=200)
                    elif report_format == "HTML":
                        st.download_button(
                            label="📥 Download HTML Briefing",
                            data=report_bytes,
                            file_name="executive_briefing.html",
                            mime="text/html",
                            use_container_width=True
                        )
    else:
        st.warning("Your role (Viewer/Manager) does not have permissions to compile multi-CVE briefs.")
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown("### 📋 AI Generated Reports History Ledger")
with st.spinner("Loading report history ledger..."):
    history = api_get("/reports/history")

if history:
    for item in history:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        col_cve, col_date = st.columns([1, 3])
        with col_cve:
            st.markdown(f"**{item.get('cve_id')}**")
        with col_date:
            st.caption(f"Created: {item.get('created_at', 'N/A')[:16]}")
        st.markdown(item.get("summary"))
        st.markdown('</div>', unsafe_allow_html=True)
else:
    st.info("No generated AI reports found in the history ledger.")
