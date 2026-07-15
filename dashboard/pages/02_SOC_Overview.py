import streamlit as st
import pandas as pd
from dashboard.components.ui import inject_custom_css, render_banner, render_metric_card
from dashboard.components.auth import check_authentication, clear_session, api_get
from dashboard.components.charts import (
    render_severity_pie_chart,
    render_risk_score_histogram,
    render_epss_histogram,
    render_kev_bar_chart,
    render_timeline_trend
)

# Page configuration
st.set_page_config(page_title="SOC Overview Console", page_icon="🛡️", layout="wide")
inject_custom_css()

# Authentication Guard
if not check_authentication():
    st.stop()

# Sidebar Controls
st.sidebar.markdown("### 🛡️ SOC CONTROL CENTER")
st.sidebar.markdown(f"User: **{st.session_state.username}**")
st.sidebar.markdown(f"Role: `{st.session_state.user_role}`")
st.sidebar.markdown(f"Organization: **{st.session_state.org_name}**")

if st.sidebar.button("Log Out", key="logout_overview_page", use_container_width=True):
    clear_session()
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("### Navigation Quick Links")
st.sidebar.caption("Use the sidebar links above to browse platform modules.")

# Render Main Dashboard Layout
render_banner(
    f"SOC Overview — {st.session_state.org_name}",
    "Unified threat dashboard presenting real-time CVSS, CISA KEV, and EPSS telemetry"
)

# Fetch KPI summary from FastAPI API
with st.spinner("Fetching threat intelligence stats..."):
    stats = api_get("/dashboard/summary")
    statistics_charts = api_get("/statistics")
    latest_cves = api_get("/vulnerabilities", params={"limit": 5})

if stats:
    # Render Glassmorphic metric cards in columns
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        render_metric_card("Total Vulnerabilities", f"{stats.get('total_vulnerabilities', 0):,}", "Active exposures")
    with col2:
        render_metric_card("Critical Threats", f"{stats.get('critical_vulnerabilities', 0):,}", "CVSS >= 9.0 or CRITICAL")
    with col3:
        render_metric_card("Active Exploits (KEV)", f"{stats.get('cisa_kev_count', 0):,}", "Exploited in wild")
    with col4:
        render_metric_card("Average EPSS Score", f"{stats.get('avg_epss_score', 0.0):.2%}", "Likelihood of exploit")
    with col5:
        # Threat Alerts Today: count of critical items or alerts
        alerts_today = stats.get('critical_vulnerabilities', 0)
        render_metric_card("Threat Alerts Today", f"{alerts_today:,}", "Requires remediation")

st.markdown("### Security Posture & Analytics")

if statistics_charts:
    col_chart1, col_chart2 = st.columns(2)
    with col_chart1:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        pie_fig = render_severity_pie_chart(statistics_charts.get("severity_distribution", []))
        st.plotly_chart(pie_fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
        
    with col_chart2:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        trend_fig = render_timeline_trend(statistics_charts.get("timeline", []))
        st.plotly_chart(trend_fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    col_chart3, col_chart4 = st.columns(2)
    with col_chart3:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        bar_fig = render_kev_bar_chart(statistics_charts.get("kev_vendor_distribution", []))
        st.plotly_chart(bar_fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
        
    with col_chart4:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        epss_fig = render_epss_histogram(statistics_charts.get("epss_distribution", []))
        st.plotly_chart(epss_fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

# Render Latest Critical Vulnerabilities Table
st.markdown("### Recent Threat Feed Sync Queue")

if latest_cves:
    rows = []
    for v in latest_cves:
        rows.append({
            "CVE ID": v["cve_id"],
            "Title": v["title"] or "N/A",
            "CVSS": v["cvss_score"] or "N/A",
            "EPSS Score": f"{v.get('epss_score', 0.0):.4f}",
            "Severity": v["severity"] or "N/A",
            "Vendor": v["vendor"]["name"] if v["vendor"] else "Unknown",
            "Product": v["product"]["name"] if v["product"] else "Unknown",
            "Exploit Active (KEV)": "⚠️ Yes" if v["is_kev"] else "No"
        })
        
    df_vulns = pd.DataFrame(rows)
    st.dataframe(df_vulns, use_container_width=True, hide_index=True)
else:
    st.info("No vulnerabilities logged in the queue.")
