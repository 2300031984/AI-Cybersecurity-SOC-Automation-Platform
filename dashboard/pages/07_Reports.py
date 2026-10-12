import streamlit as st
import pandas as pd
from dashboard.components.ui import (
    inject_custom_css,
    render_top_navbar,
    render_page_header
)
from dashboard.components.auth import check_authentication, api_get, api_post

# Page configuration
st.set_page_config(
    page_title="Reports | ThreatScope",
    page_icon="📄",
    layout="wide",
    initial_sidebar_state="collapsed"
)
inject_custom_css()

# Authentication Guard
if not check_authentication():
    st.stop()

# Top Navigation Bar & Context Bar
render_top_navbar(
    title="Security Intelligence Reports",
    breadcrumb="Reports"
)

# Page Header
render_page_header(
    title="Security Intelligence Reports & Executive Briefings",
    description="Generate executive briefings, technical dossiers, and export multi-CVE threat assessments using grounded intelligence."
)

# Role verification
user_role = st.session_state.get("user_role", "Viewer")
is_privileged = user_role in ["Admin", "Analyst"]

col_left, col_right = st.columns([1.1, 1.3])

with col_left:
    st.markdown('<div class="soc-card">', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="soc-card-header">
            <div>
                <h3 class="soc-card-title">Compile Multi-CVE Threat Briefing</h3>
                <p class="soc-card-subtitle">Synthesize comprehensive executive and technical dossiers across tracked vulnerabilities</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    if is_privileged:
        vulns = api_get("/vulnerabilities", params={"limit": 20})
        default_cves = ", ".join([v["cve_id"] for v in vulns[:3]]) if vulns else "CVE-2021-44228, CVE-2023-38606"

        cves_input = st.text_area(
            "CVE Identification Numbers (comma or newline separated):",
            value=default_cves,
            height=110,
            key="report_cves_input"
        )
        report_format = st.selectbox("Export Document Format", ["PDF Document", "Markdown Report", "HTML Briefing"], key="report_fmt")
        
        compile_btn = st.button("Generate Executive Briefing", type="primary", use_container_width=True)

        if compile_btn:
            cve_list = [c.strip() for c in cves_input.replace(",", "\n").split("\n") if c.strip()]
            if not cve_list:
                st.error("Please supply at least one valid CVE ID.")
            else:
                fmt_map = {"PDF Document": "pdf", "Markdown Report": "markdown", "HTML Briefing": "html"}
                chosen_fmt = fmt_map[report_format]

                with st.spinner(f"Compiling {report_format} executive dossier..."):
                    report_bytes = api_post(
                        "/analysis/report",
                        json_data={"cve_ids": cve_list, "format": chosen_fmt}
                    )

                if report_bytes:
                    st.success("Executive briefing compiled successfully!")
                    
                    if chosen_fmt == "pdf":
                        st.download_button(
                            label="📥 Download Executive Briefing (PDF)",
                            data=report_bytes,
                            file_name="threatscope_soc_briefing.pdf",
                            mime="application/pdf",
                            use_container_width=True
                        )
                    elif chosen_fmt == "markdown":
                        st.download_button(
                            label="📥 Download Markdown Dossier",
                            data=report_bytes,
                            file_name="threatscope_soc_briefing.md",
                            mime="text/markdown",
                            use_container_width=True
                        )
                    elif chosen_fmt == "html":
                        st.download_button(
                            label="📥 Download HTML Briefing",
                            data=report_bytes,
                            file_name="threatscope_soc_briefing.html",
                            mime="text/html",
                            use_container_width=True
                        )
    else:
        st.markdown(
            """
            <div class="soc-callout soc-callout-warning">
                <b>Permission Notice:</b> Report compilation requires the <b>Admin</b> or <b>Analyst</b> role.
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown('</div>', unsafe_allow_html=True)

with col_right:
    st.markdown('<div class="soc-card">', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="soc-card-header">
            <div>
                <h3 class="soc-card-title">Trigger Specific CVE Deep-Dive</h3>
                <p class="soc-card-subtitle">Generate an immediate AI Threat Analysis for a single vulnerability</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    if is_privileged:
        single_cve = st.text_input("Enter Target CVE ID:", placeholder="e.g. CVE-2023-38606", key="single_cve_input")
        if st.button("Trigger Live Threat Intelligence Analysis", use_container_width=True):
            if not single_cve:
                st.error("Please specify a CVE ID.")
            else:
                with st.spinner(f"Running threat intelligence analysis on {single_cve}..."):
                    res = api_post(f"/analysis/trigger/{single_cve.strip()}")
                if res:
                    st.success(f"Analysis saved for {single_cve}!")
                    st.markdown(f"**Patch Priority:** `{res.get('patch_priority')}`")
                    st.markdown(f"**Executive Summary:**\n{res.get('executive_summary')}")
                    st.markdown(f"**Recommendations:**\n{res.get('recommendations')}")
    else:
        st.info("Analysis triggering is restricted to Analysts and Administrators.")

    st.markdown('</div>', unsafe_allow_html=True)

# Historical Reports Ledger
st.markdown("### Published Reports & Historical Analyses Ledger")

with st.spinner("Loading published report history..."):
    history = api_get("/reports/history")

if history:
    for item in history:
        st.markdown(
            f"""
            <div class="soc-card" style="margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1E2D47; padding-bottom: 6px; margin-bottom: 8px;">
                    <span style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #2DD4BF; font-size: 1rem;">
                        {item.get('cve_id')}
                    </span>
                    <span style="font-size: 0.75rem; color: #9AAAC0;">
                        Recorded: {item.get('created_at', '')[:16].replace('T', ' ')}
                    </span>
                </div>
            """,
            unsafe_allow_html=True
        )
        st.markdown(item.get("summary"))
        st.markdown('</div>', unsafe_allow_html=True)
else:
    st.info("No generated AI threat reports found in the history ledger.")
