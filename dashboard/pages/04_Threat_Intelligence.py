import streamlit as st
import pandas as pd
import plotly.express as px
from dashboard.components.ui import inject_custom_css, render_banner, render_metric_card
from dashboard.components.auth import check_authentication, clear_session, api_get, api_post
from dashboard.components.charts import render_kev_bar_chart

# Page configuration
st.set_page_config(page_title="Threat Intelligence Center", page_icon="📡", layout="wide")
inject_custom_css()

# Authentication Guard
if not check_authentication():
    st.stop()

# Sidebar Controls
st.sidebar.markdown("### 🛡️ SOC CONTROL CENTER")
st.sidebar.markdown(f"User: **{st.session_state.username}**")
st.sidebar.markdown(f"Role: `{st.session_state.user_role}`")
st.sidebar.markdown(f"Organization: **{st.session_state.org_name}**")

if st.sidebar.button("Log Out", key="logout_threat_intel", use_container_width=True):
    clear_session()
    st.rerun()

render_banner(
    "Threat Intelligence & IOC Enrichment",
    "Monitor active Indicators of Compromise (IOC) and enrich data feeds using external reputation APIs"
)

# Tab layouts: 1. Enrichment lookup, 2. IOC telemetry overview, 3. MITRE ATT&CK Mapping
tab1, tab2, tab3 = st.tabs(["🔍 Interactive IOC Lookup", "📊 Ingested IOC Telemetry", "🛡️ MITRE ATT&CK Explorer"])

with tab1:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.subheader("Query Reputation feeds (AbuseIPDB, VirusTotal, AlienVault)")
    
    col_type, col_val = st.columns([1, 3])
    with col_type:
        ioc_type = st.selectbox("IOC Type", ["IP", "Hash", "Domain", "URL"])
    with col_val:
        ioc_query = st.text_input("Enter indicator value (e.g. 8.8.8.8, a malicious hash, or domain)")
        
    assess_btn = st.button("Run Threat Enrichment Scan", use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    if assess_btn:
        if not ioc_query:
            st.error("Please enter a valid indicator value to search.")
        else:
            with st.spinner(f"Analyzing {ioc_type} indicator reputation..."):
                result = api_post("/enrich", json_data={"type": ioc_type.lower(), "query": ioc_query})
                
            if result:
                st.success("Reputational lookup complete.")
                
                col_res1, col_res2 = st.columns(2)
                with col_res1:
                    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
                    st.subheader("Indicator Identity")
                    st.write(f"**Query**: `{result.get('query')}`")
                    st.write(f"**Type**: `{result.get('type').upper()}`")
                    st.write(f"**Result Status**: {result.get('summary')}")
                    
                    # Custom parsing depending on what returned
                    if result.get("abuseipdb"):
                        abuse = result["abuseipdb"]
                        st.write("---")
                        st.write("### AbuseIPDB Telemetry")
                        st.write(f"**Abuse Confidence Score**: `{abuse.get('abuseConfidenceScore', 0)}%`")
                        st.write(f"**Country**: `{abuse.get('countryCode', 'N/A')}`")
                        st.write(f"**ISP**: `{abuse.get('isp', 'N/A')}`")
                        st.write(f"**Whitelisted**: `{abuse.get('isWhitelisted', 'N/A')}`")
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                with col_res2:
                    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
                    st.subheader("VirusTotal reputation stats")
                    if result.get("virustotal"):
                        vt = result["virustotal"]
                        stats = vt.get("last_analysis_stats", {})
                        if stats:
                            st.write(f"🔴 Malicious: `{stats.get('malicious', 0)}`")
                            st.write(f"🟡 Suspicious: `{stats.get('suspicious', 0)}`")
                            st.write(f"🟢 Harmless: `{stats.get('harmless', 0)}`")
                            st.write(f"⚪ Undetected: `{stats.get('undetected', 0)}`")
                        else:
                            st.info("No explicit analysis stats returned.")
                    else:
                        st.info("No VirusTotal reputation details available.")
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                st.markdown("### Raw API Feed Result Details")
                st.json(result)
            else:
                st.error("Failed to run enrichment scan. Verify your API keys or fallback options.")

with tab2:
    with st.spinner("Fetching historical IOC stats..."):
        ioc_data = api_get("/dashboard/ioc")
        
    if ioc_data:
        malicious_count = sum(1 for x in ioc_data if x.get("status") == "malicious")
        total_count = len(ioc_data)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            render_metric_card("Total Analyzed IOCs", str(total_count), "Queried threat feeds")
        with col2:
            render_metric_card("Malicious Indicators", str(malicious_count), "Abuse / Threat match > 75%")
        with col3:
            clean_count = total_count - malicious_count
            render_metric_card("Suspicious / Clean", str(clean_count), "Below alert thresholds")
            
        st.write("---")
        
        st.subheader("📊 Reputational Assessment Scores (VirusTotal vs AbuseIPDB)")
        df = pd.DataFrame(ioc_data)
        
        fig = px.bar(
            df,
            x="ioc",
            y=["vt_score", "abuse_score"],
            barmode="group",
            title="IOC Risk Scores Overview",
            labels={"value": "Risk Score (0-100)", "ioc": "Indicator (IOC)"},
            color_discrete_sequence=["#ef4444", "#f97316"]
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter, sans-serif", color="#e2e8f0"),
            xaxis=dict(gridcolor="#1e293b", linecolor="#1e293b"),
            yaxis=dict(gridcolor="#1e293b", linecolor="#1e293b")
        )
        st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("📋 Ingested Indicators Register")
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No Indicators of Compromise currently registered.")

with tab3:
    st.subheader("🛡️ MITRE ATT&CK Technique Frequency Mapping")
    st.markdown("Frequencies of tactics & techniques detected across organizational vulnerabilities.")
    
    with st.spinner("Fetching MITRE mappings..."):
        mitre_data = api_get("/dashboard/mitre")
        
    if mitre_data:
        df_mitre = pd.DataFrame(mitre_data)
        df_mitre = df_mitre.sort_values(by="count", ascending=True)
        
        fig_mitre = px.bar(
            df_mitre,
            x="count",
            y="technique",
            orientation="h",
            title="MITRE ATT&CK Frequencies on Organization Assets",
            labels={"count": "Exposures", "technique": "ATT&CK Technique"},
            color_discrete_sequence=["#6366f1"]
        )
        fig_mitre.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter, sans-serif", color="#e2e8f0"),
            xaxis=dict(gridcolor="#1e293b", linecolor="#1e293b"),
            yaxis=dict(gridcolor="#1e293b", linecolor="#1e293b")
        )
        st.plotly_chart(fig_mitre, use_container_width=True)
        
        st.dataframe(df_mitre.sort_values(by="count", ascending=False), use_container_width=True, hide_index=True)
    else:
        st.info("No MITRE ATT&CK technique mappings detected in vulnerabilities.")
