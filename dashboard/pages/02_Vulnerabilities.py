import streamlit as st
import pandas as pd
from dashboard.components.ui import (
    inject_custom_css,
    render_top_navbar,
    render_page_header,
    get_severity_badge_html,
    get_kev_badge_html
)
from dashboard.components.auth import check_authentication, api_get, api_post

# Page configuration
st.set_page_config(
    page_title="Vulnerabilities | ThreatScope",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed"
)
inject_custom_css()

# Authentication Guard
if not check_authentication():
    st.stop()

# Top Navigation Bar & Context Bar
render_top_navbar(
    title="Vulnerability Operations",
    breadcrumb="Vulnerabilities"
)

# Page Header
render_page_header(
    title="Vulnerability Operations",
    description="Search, evaluate, and investigate tracked Common Vulnerabilities and Exposures across monitored environments."
)

# =========================================================================
# UNIFIED SEARCH, FILTER & DISCOVERY TOOLBAR
# =========================================================================
st.markdown('<div class="soc-card" style="margin-bottom: 1rem;">', unsafe_allow_html=True)

f_row1_c1, f_row1_c2, f_row1_c3, f_row1_c4 = st.columns([3, 1.5, 1.5, 1])

with f_row1_c1:
    search_query = st.text_input(
        "Search Identifier or Keyword",
        placeholder="e.g. CVE-2021-44228, Apache, Log4j, Kernel...",
        key="vuln_search"
    )

with f_row1_c2:
    severity_filter = st.selectbox(
        "Severity Rating",
        options=["ALL SEVERITIES", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        key="vuln_sev"
    )

with f_row1_c3:
    is_kev_filter = st.checkbox("CISA KEV (Catalog Listed Only)", value=False, key="vuln_kev")

with f_row1_c4:
    st.write("")
    st.write("")
    if st.button("Reset Filters", use_container_width=True):
        st.session_state["vuln_search"] = ""
        st.session_state["vuln_sev"] = "ALL SEVERITIES"
        st.session_state["vuln_kev"] = False
        st.rerun()

# Threshold filters
with st.expander("⚙️ Advanced Scoring Filters (CVSS & EPSS Thresholds)"):
    flt_col1, flt_col2 = st.columns(2)
    with flt_col1:
        min_cvss = st.slider("Minimum CVSS Base Score", min_value=0.0, max_value=10.0, value=0.0, step=0.5)
    with flt_col2:
        min_epss_pct = st.slider("Minimum EPSS Probability (%)", min_value=0, max_value=100, value=0, step=5)

st.markdown('</div>', unsafe_allow_html=True)

# Build Backend Query Parameters
params = {"limit": 100}
if search_query:
    params["search"] = search_query.strip()
if severity_filter != "ALL SEVERITIES":
    params["severity"] = severity_filter
if is_kev_filter:
    params["is_kev"] = True

with st.spinner("Querying vulnerability registry..."):
    vulns_list = api_get("/vulnerabilities", params=params)

# Client-side filtering for CVSS and EPSS sliders if requested
filtered_vulns = []
if vulns_list:
    for v in vulns_list:
        cvss_val = v.get("cvss_score") or 0.0
        epss_val = (v.get("epss_score") or 0.0) * 100.0
        if cvss_val >= min_cvss and epss_val >= min_epss_pct:
            filtered_vulns.append(v)

if not filtered_vulns:
    st.info("No matching vulnerability records found. Adjust your search keywords or clear scoring filters.")
else:
    # =========================================================================
    # VULNERABILITY DATA WORKSPACE
    # =========================================================================
    st.markdown('<div class="soc-card">', unsafe_allow_html=True)
    st.markdown(
        f"""
        <div class="soc-card-header">
            <div>
                <h3 class="soc-card-title">Tracked Vulnerability Catalog ({len(filtered_vulns)} findings)</h3>
                <p class="soc-card-subtitle">Verified Common Vulnerabilities and Exposures synced from official NVD and threat feeds</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    cve_options = [v["cve_id"] for v in filtered_vulns]
    
    if "selected_cve" not in st.session_state or st.session_state["selected_cve"] not in cve_options:
        st.session_state["selected_cve"] = cve_options[0]

    # Build display table
    table_rows = []
    for v in filtered_vulns:
        epss_val = v.get("epss_score")
        table_rows.append({
            "CVE ID": v["cve_id"],
            "Severity": v.get("severity") or "UNKNOWN",
            "CVSS Base": f"{v['cvss_score']:.1f}" if v.get("cvss_score") is not None else "N/A",
            "EPSS Probability": f"{epss_val * 100:.2f}%" if epss_val is not None else "N/A",
            "CISA KEV": "⚠️ Catalog Listed" if v.get("is_kev") else "Not Listed",
            "Vendor": v.get("vendor", {}).get("name") if v.get("vendor") else "Not specified",
            "Product": v.get("product", {}).get("name") if v.get("product") else "Not specified",
            "Published Date": v.get("published_date")[:10] if v.get("published_date") else "N/A"
        })

    df_vulns = pd.DataFrame(table_rows)
    st.dataframe(df_vulns, use_container_width=True, hide_index=True)

    # Interactive Dossier Selector
    st.write("")
    sel_col1, sel_col2 = st.columns([3, 1], vertical_alignment="bottom")
    with sel_col1:
        chosen_cve = st.selectbox(
            "Select Vulnerability for Evidence-First Investigation Dossier:",
            options=cve_options,
            index=cve_options.index(st.session_state["selected_cve"]) if st.session_state["selected_cve"] in cve_options else 0,
            key="cve_selector"
        )
        st.session_state["selected_cve"] = chosen_cve

    st.markdown('</div>', unsafe_allow_html=True)

    # =========================================================================
    # EVIDENCE-FIRST INVESTIGATION WORKSPACE
    # =========================================================================
    selected_cve_id = st.session_state["selected_cve"]

    with st.spinner(f"Loading threat dossier for {selected_cve_id}..."):
        detail = api_get(f"/cve/{selected_cve_id}")

    if detail:
        st.markdown(
            f"""
            <div class="soc-card" style="border-top: 3px solid #2DD4BF;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
                    <div>
                        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px;">
                            <span style="font-family: 'JetBrains Mono', monospace; font-size: 1.35rem; font-weight: 700; color: #E8EEF7;">
                                {detail.get('cve_id')}
                            </span>
                            {get_severity_badge_html(detail.get('severity'))}
                            {get_kev_badge_html(detail.get('is_kev'))}
                        </div>
                        <div style="font-size: 0.95rem; font-weight: 600; color: #9AAAC0;">
                            {detail.get('title') or 'Vulnerability Advisory Record'}
                        </div>
                    </div>
                    <div style="text-align: right; background-color: #172338; border: 1px solid #29364A; border-radius: 6px; padding: 0.4rem 0.8rem;">
                        <span style="font-size: 0.7rem; color: #9AAAC0; text-transform: uppercase;">CVSS Base Score</span>
                        <div style="font-size: 1.45rem; font-weight: 700; color: #E8EEF7; line-height: 1.1;">
                            {f"{detail['cvss_score']:.1f}" if detail.get('cvss_score') is not None else 'N/A'}
                        </div>
                    </div>
                </div>
            """,
            unsafe_allow_html=True
        )

        # Quick Answer Banner
        st.markdown(
            """
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 10px; margin-bottom: 1rem; background-color: #172338; border: 1px solid #29364A; border-radius: 6px; padding: 0.75rem 1rem; font-size: 0.8rem;">
                <div>
                    <span style="color: #2DD4BF; font-weight: 600;">1. WHAT IS THIS?</span>
                    <div style="color: #9AAAC0; margin-top: 2px;">Known vulnerability advisory catalogued in NVD with verified CPE mapping.</div>
                </div>
                <div>
                    <span style="color: #38BDF8; font-weight: 600;">2. WHY IT MATTERS:</span>
                    <div style="color: #9AAAC0; margin-top: 2px;">Evaluated via CVSS severity and EPSS 30-day weaponization probability telemetry.</div>
                </div>
                <div>
                    <span style="color: #F87171; font-weight: 600;">3. NEXT ACTION:</span>
                    <div style="color: #9AAAC0; margin-top: 2px;">Review containment guidance, Snort rules, and mandated CISA remediation dates below.</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 5 Investigation Tabs
        tab_overview, tab_risk, tab_remediation, tab_refs, tab_history = st.tabs([
            "📋 Overview",
            "⚖️ Risk Assessment",
            "🛡️ Remediation & Playbook",
            "🔗 Source References",
            "🕒 Analysis History"
        ])

        # TAB 1: OVERVIEW
        with tab_overview:
            st.markdown("#### Vulnerability Synopsis")
            desc = detail.get("description") or "Not available from current sources."
            st.write(desc)

            st.write("---")
            m_col1, m_col2, m_col3 = st.columns(3)
            with m_col1:
                vendor_name = detail.get('vendor', {}).get('name') if detail.get('vendor') else 'Not available from current sources'
                product_name = detail.get('product', {}).get('name') if detail.get('product') else 'Not available from current sources'
                st.markdown(f"**Impacted Vendor:** `{vendor_name}`")
                st.markdown(f"**Impacted Product:** `{product_name}`")
            with m_col2:
                pub = detail.get('published_date')
                st.markdown(f"**First Published:** `{pub[:10] if pub else 'Not available from current sources'}`")
                mod = detail.get('last_modified_date')
                st.markdown(f"**Last Modified:** `{mod[:10] if mod else 'Not available from current sources'}`")
            with m_col3:
                cvss_vec = detail.get("cvss_vector") or "Not available from current sources"
                st.markdown(f"**CVSS v3 Vector:**")
                st.code(cvss_vec, language="text")

        # TAB 2: RISK ASSESSMENT
        with tab_risk:
            st.markdown("#### Quantitative Threat & Exploit Metrics")
            
            r_col1, r_col2 = st.columns(2)
            with r_col1:
                st.markdown('<div class="soc-card">', unsafe_allow_html=True)
                st.markdown("##### 📈 EPSS (Exploit Prediction Scoring System)")
                epss_obj = detail.get("epss")
                if epss_obj:
                    epss_prob = epss_obj.get("score", 0.0)
                    epss_pct = epss_obj.get("percentile", 0.0)
                    st.metric("Exploitation Probability (30-day window)", f"{epss_prob * 100:.2f}%", f"Percentile: {epss_pct * 100:.1f}%")
                    st.caption("EPSS evaluates empirical in-the-wild exploitation activity across global honeypots and threat telemetry.")
                else:
                    st.info("EPSS metric not available from current sources.")
                st.markdown('</div>', unsafe_allow_html=True)

            with r_col2:
                st.markdown('<div class="soc-card">', unsafe_allow_html=True)
                st.markdown("##### 🚨 CISA KEV (Known Exploited Vulnerabilities)")
                kev_obj = detail.get("cisa_kev")
                if kev_obj:
                    st.markdown(f"**Listed in Official CISA KEV Catalog:** `YES (Known Exploited Vulnerability)`")
                    st.markdown(f"**Date Catalogued:** `{kev_obj.get('date_added') or 'N/A'}`")
                    st.markdown(f"**Mandated Remediation Due Date:** `{kev_obj.get('due_date') or 'N/A'}`")
                    st.markdown(f"**Required Action:** {kev_obj.get('action_required') or 'Apply vendor mitigations.'}")
                else:
                    st.info("This CVE is not currently listed in the CISA KEV catalog.")
                st.markdown('</div>', unsafe_allow_html=True)

        # TAB 3: REMEDIATION & PLAYBOOK
        with tab_remediation:
            st.markdown("#### AI Threat Analysis & Containment Guidance")
            
            ai_data = detail.get("ai_analysis")
            if ai_data:
                st.markdown(
                    """
                    <div class="soc-callout soc-callout-info">
                        <b>🤖 AI-Generated Intelligence Briefing:</b> Synthesized from localized database telemetry via Google Gemini. Clearly distinguish AI analytical deductions from official advisory facts.
                    </div>
                    """,
                    unsafe_allow_html=True
                )
                st.markdown(f"**Executive Summary:**\n{ai_data.get('executive_summary')}")
                st.markdown(f"**Technical Analysis:**\n{ai_data.get('technical_analysis')}")
                st.markdown(f"**Risk Impact Evaluation:**\n{ai_data.get('risk_impact')}")
                st.markdown(f"**Recommended Containment Actions:**\n{ai_data.get('recommendations')}")
                st.markdown(f"**Patch Priority Recommendation:** `{ai_data.get('patch_priority')}`")
            else:
                st.info("No AI threat briefing has been compiled yet for this CVE.")
                is_privileged = st.session_state.get("user_role") in ["Admin", "Analyst"]
                if is_privileged:
                    if st.button(f"Generate Live AI Threat Briefing for {selected_cve_id}", type="primary"):
                        with st.spinner("Invoking Gemini threat analysis engine..."):
                            res = api_post(f"/analysis/trigger/{selected_cve_id}")
                        if res:
                            st.success("AI analysis generated and recorded!")
                            st.rerun()

            st.write("---")
            st.markdown("##### 🚨 Defensive Containment Playbook")
            if st.button(f"Generate Instant Incident Response Playbook for {selected_cve_id}", key="gen_playbook_btn"):
                with st.spinner("Compiling containment rules, Snort signatures, and firewall scripts..."):
                    pb_res = api_post(f"/incident-response/{selected_cve_id}")
                if pb_res and "playbook" in pb_res:
                    st.success("Containment playbook compiled:")
                    st.markdown(pb_res["playbook"])

        # TAB 4: SOURCE REFERENCES
        with tab_refs:
            st.markdown("#### Official Source References & Grounding")
            cve_code = detail.get("cve_id")
            nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_code}"
            mitre_link = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_code}"
            cisa_link = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

            st.markdown(f"- 🌐 **NVD NIST Official Advisory:** [{nvd_link}]({nvd_link})")
            st.markdown(f"- 🛡️ **MITRE CVE Entry:** [{mitre_link}]({mitre_link})")
            st.markdown(f"- 🏛️ **CISA KEV Catalog Reference:** [{cisa_link}]({cisa_link})")
            st.markdown(f"- 📦 **Data Grounding:** Ingested into organization PostgreSQL/SQLite database via authenticated NVD API 2.0")

        # TAB 5: ANALYSIS HISTORY
        with tab_history:
            st.markdown("#### Dossier Audit Ledger")
            created_at = detail.get("published_date") or "Not recorded"
            st.markdown(f"- **Database Ingestion Date:** `{created_at}`")
            st.markdown(f"- **Tenant Organization ID:** `{st.session_state.get('org_name', 'Local Lab')}`")
            st.markdown(f"- **Enrichment Status:** `{'Enriched with AI threat briefing' if detail.get('ai_analysis') else 'Standard Advisory Telemetry'}`")

        st.markdown('</div>', unsafe_allow_html=True)
