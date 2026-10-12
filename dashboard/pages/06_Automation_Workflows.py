import streamlit as st
import pandas as pd
from dashboard.components.ui import (
    inject_custom_css,
    render_top_navbar,
    render_page_header
)
from dashboard.components.auth import check_authentication, api_get

# Page configuration
st.set_page_config(
    page_title="Automation | ThreatScope",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="collapsed"
)
inject_custom_css()

# Authentication Guard
if not check_authentication():
    st.stop()

# Top Navigation Bar & Context Bar
render_top_navbar(
    title="Automation Workflows",
    breadcrumb="Automation"
)

# Page Header
render_page_header(
    title="Automation Workflows & Orchestration",
    description="Operations console for n8n automated intelligence pipelines, scheduled feed synchronizers, and alert dispatchers."
)

# Fetch real workflow execution logs from backend
with st.spinner("Fetching automation execution records..."):
    logs = api_get("/logs/workflow", params={"limit": 50})

# Workflows Registry Overview
st.markdown('<div class="soc-card">', unsafe_allow_html=True)
st.markdown(
    """
    <div class="soc-card-header">
        <div>
            <h3 class="soc-card-title">Configured n8n Automation Pipelines</h3>
            <p class="soc-card-subtitle">Production security orchestration workflows configured in repository deployment definitions</p>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

last_alert_run = "Never executed"
last_report_run = "Never executed"
alert_status = "Configured"
report_status = "Configured"

if logs:
    for l in logs:
        src = l.get("source", "")
        if "NVD" in src or "CISA" in src or "EPSS" in src:
            if last_alert_run == "Never executed":
                last_alert_run = l.get("created_at")[:19].replace("T", " ")
                alert_status = l.get("status", "SUCCESS")
        if "Report" in src or "Daily" in src:
            if last_report_run == "Never executed":
                last_report_run = l.get("created_at")[:19].replace("T", " ")
                report_status = l.get("status", "SUCCESS")

workflows_registry = [
    {
        "Workflow Name": "ThreatScope Auto Ingest & Alert Pipeline",
        "Orchestration Engine": "n8n (v1.0 Workflow Engine)",
        "Purpose": "Polls CISA KEV & EPSS feeds every 12h, correlates exposures, and alerts security team",
        "Trigger Schedule": "Cron: Every 12 Hours (*/12 * * *)",
        "State": "ENABLED",
        "Latest Execution": last_alert_run,
        "Execution Outcome": f"🟢 {alert_status}" if alert_status == "SUCCESS" else f"🔴 {alert_status}",
        "Next Run": "Scheduled per cron"
    },
    {
        "Workflow Name": "Daily Executive Threat Briefing Workflow",
        "Orchestration Engine": "n8n (v1.0 Workflow Engine)",
        "Purpose": "Aggregates 24h threat statistics, computes patch prioritization matrix, and posts briefing",
        "Trigger Schedule": "Cron: Daily 08:00 UTC (0 8 * * *)",
        "State": "ENABLED",
        "Latest Execution": last_report_run,
        "Execution Outcome": f"🟢 {report_status}" if report_status == "SUCCESS" else f"🟡 {report_status}",
        "Next Run": "Scheduled per cron"
    }
]

df_wf = pd.DataFrame(workflows_registry)
st.dataframe(df_wf, use_container_width=True, hide_index=True)

st.markdown(
    """
    <div class="soc-callout soc-callout-info" style="margin-top: 15px;">
        <b>ℹ️ Production Orchestration Note:</b> The automation workflows above are defined in <code>n8n/workflows/</code>. In production environments where containerized n8n runners are active, executions stream directly to the <code>/api/v1/workflow/log</code> endpoint.
    </div>
    """,
    unsafe_allow_html=True
)
st.markdown('</div>', unsafe_allow_html=True)

# Live Execution History Ledger
st.markdown("### Execution History Ledger")

if logs:
    st.markdown('<div class="soc-card">', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="soc-card-header">
            <div>
                <h3 class="soc-card-title">Verified Ingestion & Pipeline Execution Logs</h3>
                <p class="soc-card-subtitle">Real database records from automated threat intelligence synchronization tasks</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    rows = []
    for l in logs:
        status_label = l.get("status", "UNKNOWN")
        badge = "🟢 Successful" if status_label == "SUCCESS" else ("🔴 Failed" if status_label == "FAILED" else f"⚪ {status_label}")
        
        rows.append({
            "Log ID": l.get("id"),
            "Timestamp": l.get("created_at")[:19].replace("T", " ") if l.get("created_at") else "N/A",
            "Pipeline / Source": l.get("source"),
            "Action Type": l.get("action_type"),
            "Result": badge,
            "Execution Details": l.get("details")
        })

    df_logs = pd.DataFrame(rows)
    st.dataframe(df_logs, use_container_width=True, hide_index=True)
    st.markdown('</div>', unsafe_allow_html=True)
else:
    st.info("No workflow execution logs have been registered in the database.")
