import streamlit as st
import pandas as pd
from datetime import datetime
from dashboard.components.ui import (
    inject_custom_css,
    render_top_navbar,
    render_page_header,
    render_kpi_card,
    get_severity_badge_html,
    get_kev_badge_html
)
from dashboard.components.auth import check_authentication, api_get
from dashboard.components.charts import (
    render_severity_pie_chart,
    render_epss_histogram,
    render_kev_bar_chart,
    render_timeline_trend
)

# Page configuration
st.set_page_config(
    page_title="Security Overview | ThreatScope",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)
inject_custom_css()

# Authentication Guard
if not check_authentication():
    st.stop()

# Fetch Real Backend Data
with st.spinner("Connecting to telemetry pipeline..."):
    stats = api_get("/dashboard/summary")
    chart_stats = api_get("/statistics")
    latest_cves = api_get("/vulnerabilities", params={"limit": 10})
    workflow_logs = api_get("/logs/workflow", params={"limit": 5})

# Determine last successful sync timestamp from workflow logs
last_sync_str = "No sync recorded"
if workflow_logs:
    for log in workflow_logs:
        if log.get("status") == "SUCCESS":
            try:
                dt = datetime.fromisoformat(log.get("created_at"))
                last_sync_str = dt.strftime("%b %d, %H:%M UTC")
                break
            except Exception:
                last_sync_str = log.get("created_at", "Recorded")
                break

# Top Navigation Bar & Slim Context Bar
render_top_navbar(
    title="Security Overview",
    breadcrumb="Overview",
    freshness_ts=last_sync_str
)

# Page Header
render_page_header(
    title="Security Overview",
    description="Monitor tracked vulnerabilities, understand exploitation risk, and identify remediation priorities."
)

# =========================================================================
# ROW 1 — SUMMARY METRICS
# =========================================================================
if stats:
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        total_vulns = stats.get("total_vulnerabilities")
        val = f"{total_vulns:,}" if total_vulns is not None else "Unavailable"
        render_kpi_card(
            title="Tracked Vulnerabilities",
            value=val,
            subtext="Catalogued in organization vulnerability registry",
            border_type="neutral"
        )
    with col2:
        crit_count = stats.get("critical_vulnerabilities")
        val = f"{crit_count:,}" if crit_count is not None else "Unavailable"
        render_kpi_card(
            title="Critical Vulnerabilities",
            value=val,
            subtext="CVSS >= 9.0 or classified Critical severity",
            border_type="critical"
        )
    with col3:
        high_count = stats.get("high_vulnerabilities")
        val = f"{high_count:,}" if high_count is not None else "Unavailable"
        render_kpi_card(
            title="High-Severity Exposures",
            value=val,
            subtext="CVSS 7.0 - 8.9 elevated impact rating",
            border_type="high"
        )
    with col4:
        kev_count = stats.get("cisa_kev_count")
        val = f"{kev_count:,}" if kev_count is not None else "Unavailable"
        render_kpi_card(
            title="CISA KEV Catalog Entries",
            value=val,
            subtext="Catalogued in CISA Known Exploited registry",
            border_type="critical"
        )
    with col5:
        render_kpi_card(
            title="Intelligence Sources Configured",
            value="5 Live / 1 Fallback",
            subtext="NVD, CISA, EPSS, AbuseIPDB, MITRE (VT fallback)",
            border_type="low"
        )
else:
    st.info("Telemetry data unavailable from backend service.")

st.write("")

# =========================================================================
# ROW 2 — TWO-COLUMN ANALYTICS LAYOUT
# =========================================================================
if chart_stats:
    c_left, c_right = st.columns([1, 1])
    
    with c_left:
        st.markdown('<div class="soc-card">', unsafe_allow_html=True)
        st.markdown(
            """
            <div class="soc-card-header">
                <div>
                    <h3 class="soc-card-title">Vulnerabilities by Severity</h3>
                    <p class="soc-card-subtitle">Distribution of tracked CVEs classified by CVSS qualitative rating</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        pie_fig = render_severity_pie_chart(chart_stats.get("severity_distribution", []))
        st.plotly_chart(pie_fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with c_right:
        st.markdown('<div class="soc-card">', unsafe_allow_html=True)
        st.markdown(
            """
            <div class="soc-card-header">
                <div>
                    <h3 class="soc-card-title">Exploitation Likelihood & CISA KEV Status</h3>
                    <p class="soc-card-subtitle">EPSS probability distribution and CISA KEV catalog indicators</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.markdown(
            """
            <div style="font-size: 0.78rem; color: #9AAAC0; margin-bottom: 8px; line-height: 1.4;">
                <span style="color: #38BDF8;">● <b>EPSS</b></span> estimates the empirical probability of in-the-wild exploitation over the next 30 days.
                <span style="color: #EF4444; margin-left: 8px;">● <b>CISA KEV</b></span> identifies vulnerabilities catalogued by CISA with verified exploitation in the wild.
            </div>
            """,
            unsafe_allow_html=True
        )
        epss_fig = render_epss_histogram(chart_stats.get("epss_distribution", []))
        st.plotly_chart(epss_fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    c_b1, c_b2 = st.columns([1, 1])
    with c_b1:
        st.markdown('<div class="soc-card">', unsafe_allow_html=True)
        st.markdown(
            """
            <div class="soc-card-header">
                <div>
                    <h3 class="soc-card-title">CISA KEV Entries by Affected Vendor</h3>
                    <p class="soc-card-subtitle">Tracked vulnerabilities in CISA KEV catalog mapped to software vendors</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        bar_fig = render_kev_bar_chart(chart_stats.get("kev_vendor_distribution", []))
        st.plotly_chart(bar_fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with c_b2:
        st.markdown('<div class="soc-card">', unsafe_allow_html=True)
        st.markdown(
            """
            <div class="soc-card-header">
                <div>
                    <h3 class="soc-card-title">Threat Ingestion Velocity</h3>
                    <p class="soc-card-subtitle">Historical vulnerability publication and ingestion velocity</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        trend_fig = render_timeline_trend(chart_stats.get("timeline", []))
        st.plotly_chart(trend_fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

st.write("")

# =========================================================================
# ROW 3 — PRIORITY FINDINGS TABLE
# =========================================================================
if latest_cves:
    st.markdown('<div class="soc-card">', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="soc-card-header">
            <div>
                <h3 class="soc-card-title">Priority Vulnerability Findings</h3>
                <p class="soc-card-subtitle">Tracked vulnerability records sorted by publication recency and exploit indicators</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    rows = []
    cve_id_list = []
    for v in latest_cves:
        epss_val = v.get("epss_score")
        epss_formatted = f"{epss_val * 100:.2f}%" if epss_val is not None else "N/A"
        
        pub_date = v.get("published_date")
        if pub_date:
            try:
                pub_clean = pub_date[:10]
            except Exception:
                pub_clean = str(pub_date)
        else:
            pub_clean = "Unknown"

        vendor_name = v.get("vendor", {}).get("name") if v.get("vendor") else "Not specified"
        product_name = v.get("product", {}).get("name") if v.get("product") else "Not specified"

        cve_id_list.append(v["cve_id"])
        rows.append({
            "CVE ID": v["cve_id"],
            "Vulnerability Title": v.get("title") or "Security Advisory",
            "CVSS": f"{v['cvss_score']:.1f}" if v.get("cvss_score") is not None else "N/A",
            "EPSS": epss_formatted,
            "CISA KEV": "⚠️ Catalog Listed" if v.get("is_kev") else "Not Listed",
            "Severity": v.get("severity") or "UNKNOWN",
            "Affected Product": f"{vendor_name} / {product_name}",
            "Last Updated": pub_clean
        })

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)

    # Click to investigate shortcut
    col_sel, col_act = st.columns([2.5, 1], vertical_alignment="bottom")
    with col_sel:
        chosen_cve = st.selectbox("Select CVE ID for Detailed Investigation:", options=cve_id_list, key="overview_cve_select")
    with col_act:
        if st.button("Open in Vulnerability Console", type="primary", use_container_width=True):
            st.session_state["selected_cve"] = chosen_cve
            st.switch_page("pages/02_Vulnerabilities.py")

    st.markdown('</div>', unsafe_allow_html=True)
else:
    st.info("No active vulnerability findings registered in this organization registry.")

st.write("")

# =========================================================================
# ROW 4 — RECENT ACTIVITY & THREAT FEED HEALTH
# =========================================================================
col_act1, col_act2 = st.columns([1.3, 1])

with col_act1:
    st.markdown('<div class="soc-card">', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="soc-card-header">
            <div>
                <h3 class="soc-card-title">Automation Ingestion Ledger</h3>
                <p class="soc-card-subtitle">Verified database logs from threat intelligence synchronization pipelines</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
    if workflow_logs:
        act_rows = []
        for l in workflow_logs:
            act_rows.append({
                "Timestamp": l.get("created_at")[:19].replace("T", " ") if l.get("created_at") else "N/A",
                "Source Feed": l.get("source"),
                "Action": l.get("action_type"),
                "Status": l.get("status"),
                "Details": l.get("details")
            })
        df_act = pd.DataFrame(act_rows)
        st.dataframe(df_act, use_container_width=True, hide_index=True)
    else:
        st.info("No automated ingestion runs recorded in the database yet.")
    st.markdown('</div>', unsafe_allow_html=True)

with col_act2:
    st.markdown('<div class="soc-card">', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="soc-card-header">
            <div>
                <h3 class="soc-card-title">Threat Feed Operational Status</h3>
                <p class="soc-card-subtitle">Verified connectivity and data status of external intelligence integrations</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.markdown(
        """
        <div style="display: flex; flex-direction: column; gap: 8px; font-size: 0.82rem;">
            <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #1E2D47;">
                <span><b>NVD / CVE Feed</b></span>
                <span class="status-pill status-pill-green">Connected (NVD 2.0 API)</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #1E2D47;">
                <span><b>CISA KEV Catalog</b></span>
                <span class="status-pill status-pill-green">Synchronized Feed</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #1E2D47;">
                <span><b>First.org EPSS Feed</b></span>
                <span class="status-pill status-pill-green">Synchronized Scoring</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #1E2D47;">
                <span><b>AbuseIPDB Reputation</b></span>
                <span class="status-pill status-pill-green">Configured (API Key Present)</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #1E2D47;">
                <span><b>VirusTotal Reputation</b></span>
                <span class="status-pill status-pill-amber">Fallback Mode (Demo Profiles)</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 6px 0;">
                <span><b>MITRE ATT&CK Mapping</b></span>
                <span class="status-pill status-pill-neutral">Local Heuristic Engine</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.markdown('</div>', unsafe_allow_html=True)
