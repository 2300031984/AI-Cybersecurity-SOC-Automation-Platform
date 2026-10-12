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
    page_title="Risk Prioritization | ThreatScope",
    page_icon="🎯",
    layout="wide",
    initial_sidebar_state="collapsed"
)
inject_custom_css()

# Authentication Guard
if not check_authentication():
    st.stop()

# Top Navigation Bar & Context Bar
render_top_navbar(
    title="Risk Prioritization & Remediation Sequencing",
    breadcrumb="Risk Prioritization"
)

# Page Header
render_page_header(
    title="Risk Prioritization & Remediation Sequencing",
    description="Algorithmic risk evaluation combining CVSS technical impact, EPSS weaponization likelihood, and CISA KEV mandates."
)

# Role Authorization
user_role = st.session_state.get("user_role", "Viewer")
is_authorized = user_role in ["Admin", "Analyst", "Manager"]

if not is_authorized:
    st.markdown(
        """
        <div class="soc-callout soc-callout-warning">
            <b>Access Restricted:</b> Your account role (Auditor/Viewer) does not have authorization to calculate patch sequencing schedules or compile containment playbooks. Contact an administrator to request elevation.
        </div>
        """,
        unsafe_allow_html=True
    )
    st.stop()

# Three Concepts Explanation Banner
st.markdown(
    """
    <div class="soc-card" style="margin-bottom: 1.25rem;">
        <div class="soc-card-header">
            <div>
                <h3 class="soc-card-title">ThreatScope Multi-Vector Decision Framework</h3>
                <p class="soc-card-subtitle">Transparent risk calculation transparently synthesizing severity, weaponization, and exploitation data</p>
            </div>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px;">
            <div style="background-color: #172338; border: 1px solid #29364A; border-radius: 6px; padding: 0.9rem;">
                <div style="color: #38BDF8; font-weight: 600; font-size: 0.85rem; margin-bottom: 4px;">1. CVSS Base Severity</div>
                <div style="color: #9AAAC0; font-size: 0.8rem; line-height: 1.4;">
                    Quantifies the theoretical technical severity and impact of a vulnerability on confidentiality, integrity, and availability.
                </div>
            </div>
            <div style="background-color: #172338; border: 1px solid #29364A; border-radius: 6px; padding: 0.9rem;">
                <div style="color: #2DD4BF; font-weight: 600; font-size: 0.85rem; margin-bottom: 4px;">2. EPSS Weaponization Likelihood</div>
                <div style="color: #9AAAC0; font-size: 0.8rem; line-height: 1.4;">
                    Estimates the empirical probability that a vulnerability will be exploited in the wild over the next 30 days based on global threat activity.
                </div>
            </div>
            <div style="background-color: #172338; border: 1px solid #29364A; border-radius: 6px; padding: 0.9rem;">
                <div style="color: #EF4444; font-weight: 600; font-size: 0.85rem; margin-bottom: 4px;">3. CISA KEV Catalog Status</div>
                <div style="color: #9AAAC0; font-size: 0.8rem; line-height: 1.4;">
                    Identifies vulnerabilities included in CISA's catalog of known exploited vulnerabilities, establishing mandatory federal remediation deadlines.
                </div>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

tab_matrix, tab_workspace, tab_playbooks = st.tabs([
    "🎯 AI Remediation Prioritizer",
    "📊 Risk Assessment Table",
    "🚨 Containment Playbook Generator"
])

# =========================================================================
# TAB 1: AI REMEDIATION PRIORITIZER
# =========================================================================
with tab_matrix:
    st.markdown('<div class="soc-card">', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="soc-card-header">
            <div>
                <h3 class="soc-card-title">Algorithmic Remediation Sequencing</h3>
                <p class="soc-card-subtitle">Computes prioritized remediation sequences combining CVSS severity, EPSS in-the-wild exploit likelihood, and CISA KEV mandates</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <p style="font-size: 0.84rem; color: #9AAAC0;">
            Traditional vulnerability management relies solely on static CVSS base scores, creating alert fatigue. 
            ThreatScope calculates a composite priority ranking utilizing technical severity, real-time exploit prediction, and mandated federal directives.
        </p>
        """,
        unsafe_allow_html=True
    )

    if st.button("Generate Prioritized Remediation Schedule", type="primary", use_container_width=True):
        with st.spinner("Analyzing organization threat catalog and computing priority matrix..."):
            prioritize_res = api_post("/prioritize")

        if prioritize_res and "report" in prioritize_res:
            st.success("Remediation priority calculation complete.")
            st.markdown(
                """
                <div class="soc-card" style="margin-top: 15px; border-top: 3px solid #2DD4BF;">
                """,
                unsafe_allow_html=True
            )
            st.markdown(prioritize_res["report"])
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.error("Failed to generate prioritization schedule. Ensure active vulnerabilities are logged for this environment.")

    st.markdown('</div>', unsafe_allow_html=True)

# =========================================================================
# TAB 2: TRANSPARENT RISK ASSESSMENT TABLE
# =========================================================================
with tab_workspace:
    st.markdown('<div class="soc-card">', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="soc-card-header">
            <div>
                <h3 class="soc-card-title">Transparent Risk Assessment Workspace</h3>
                <p class="soc-card-subtitle">Multi-dimensional sorting and filtering across empirical scoring metrics</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    vulns = api_get("/vulnerabilities", params={"limit": 100})

    if vulns:
        # Sorting controls
        sort_col1, sort_col2 = st.columns(2)
        with sort_col1:
            sort_by = st.selectbox(
                "Sort Vulnerabilities By:",
                options=["EPSS Exploit Likelihood (Highest first)", "CVSS Score (Highest first)", "CISA KEV Status (Active first)", "Published Date (Most recent first)"]
            )
        with sort_col2:
            kev_only = st.checkbox("Show Only CISA KEV (Actively Exploited) Findings", value=False)

        parsed_data = []
        for v in vulns:
            if kev_only and not v.get("is_kev"):
                continue
            
            epss_num = v.get("epss_score") or 0.0
            vendor_name = v.get("vendor", {}).get("name") if v.get("vendor") else "Not specified"

            parsed_data.append({
                "CVE ID": v.get("cve_id"),
                "Title": v.get("title") or "Advisory Record",
                "CVSS Base Score": cvss_num,
                "EPSS Probability (30d)": f"{epss_num * 100:.2f}%",
                "epss_raw": epss_num,
                "CISA KEV Status": "⚠️ Catalog Listed" if is_kev else "Not Listed",
                "kev_raw": is_kev,
                "Impacted Vendor": vendor_name,
                "Published Date": v.get("published_date")[:10] if v.get("published_date") else "Unknown"
            })

        df_risk = pd.DataFrame(parsed_data)

        if not df_risk.empty:
            if "EPSS" in sort_by:
                df_risk = df_risk.sort_values(by="epss_raw", ascending=False)
            elif "CVSS" in sort_by:
                df_risk = df_risk.sort_values(by="CVSS Base Score", ascending=False)
            elif "CISA KEV" in sort_by:
                df_risk = df_risk.sort_values(by="kev_raw", ascending=False)
            else:
                df_risk = df_risk.sort_values(by="Published Date", ascending=False)

            display_df = df_risk.drop(columns=["epss_raw", "kev_raw"])
            st.dataframe(display_df, use_container_width=True, hide_index=True)
            st.caption("ℹ️ Transparent Evidence Model: No synthetic or proprietary risk scores are fabricated. Sort and filter directly across verified CVSS, EPSS, and CISA KEV data points.")
        else:
            st.info("No vulnerabilities match the current filter selection.")
    else:
        st.info("No vulnerabilities recorded in this tenant registry.")

    st.markdown('</div>', unsafe_allow_html=True)

# =========================================================================
# TAB 3: CONTAINMENT PLAYBOOK GENERATOR
# =========================================================================
with tab_playbooks:
    st.markdown('<div class="soc-card">', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="soc-card-header">
            <div>
                <h3 class="soc-card-title">Defensive Incident Containment Playbooks</h3>
                <p class="soc-card-subtitle">Generate containment guidance, Snort detection signatures, and hunting scripts for tracked CVEs</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    vulns_for_pb = api_get("/vulnerabilities", params={"limit": 50})
    cve_list = [v["cve_id"] for v in vulns_for_pb] if vulns_for_pb else []

    c_cve, c_btn = st.columns([2.5, 1], vertical_alignment="bottom")
    with c_cve:
        if cve_list:
            target_cve = st.selectbox("Select Target CVE for Defensive Containment Playbook:", options=cve_list)
        else:
            target_cve = st.text_input("Enter Target CVE ID (e.g. CVE-2021-44228):")

    with c_btn:
        compile_btn = st.button("Compile Playbook", type="primary", use_container_width=True)

    if compile_btn:
        if not target_cve:
            st.error("Please select or specify a valid CVE ID.")
        else:
            with st.spinner(f"Compiling defensive containment playbook for {target_cve}..."):
                pb_res = api_post(f"/incident-response/{target_cve.strip()}")

            if pb_res and "playbook" in pb_res:
                st.success(f"Containment playbook compiled for {target_cve}:")
                st.markdown(
                    """
                    <div class="soc-card" style="margin-top: 12px; border-top: 3px solid #EF4444;">
                    """,
                    unsafe_allow_html=True
                )
                st.markdown(pb_res["playbook"])
                st.markdown('</div>', unsafe_allow_html=True)
            else:
                st.error(f"Failed to generate playbook for {target_cve}. Ensure the CVE exists in the organization registry.")

    st.markdown('</div>', unsafe_allow_html=True)
