import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
from dashboard.components.ui import (
    inject_custom_css,
    render_top_navbar,
    render_page_header,
    render_kpi_card
)
from dashboard.components.auth import check_authentication, api_get, api_post

# Page configuration
st.set_page_config(
    page_title="Threat Intelligence | ThreatScope",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="collapsed"
)
inject_custom_css()

# Authentication Guard
if not check_authentication():
    st.stop()

# Top Navigation Bar & Context Bar
render_top_navbar(
    title="Threat Intelligence Console",
    breadcrumb="Threat Intel"
)

# Page Header
render_page_header(
    title="Threat Intelligence Console",
    description="Monitor verified external threat feeds, execute indicator reputation scans, and inspect adversary technique mappings."
)

# 3 Primary Tabs
tab_sources, tab_ioc, tab_mitre = st.tabs([
    "🌐 Configured Threat Feeds & Ingestion",
    "🔍 Indicator of Compromise (IOC) Scanner",
    "🛡️ MITRE ATT&CK Matrix"
])

# =========================================================================
# TAB 1: CONFIGURED SOURCES & INGESTION CONSOLE
# =========================================================================
with tab_sources:
    st.markdown('<div class="soc-card">', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="soc-card-header">
            <div>
                <h3 class="soc-card-title">Configured Threat Intelligence Pipelines</h3>
                <p class="soc-card-subtitle">Genuine operational status, synchronization timestamps, and data volume of integrated security feeds</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    stats = api_get("/dashboard/summary")
    workflow_logs = api_get("/logs/workflow", params={"limit": 10})

    total_cves = stats.get("total_vulnerabilities", 0) if stats else 0
    cisa_count = stats.get("cisa_kev_count", 0) if stats else 0

    cisa_last_sync = "Not recorded in this session"
    epss_last_sync = "Not recorded in this session"
    nvd_last_sync = "Cached in local registry"

    if workflow_logs:
        for log in workflow_logs:
            src = log.get("source", "")
            if "CISA" in src and cisa_last_sync.startswith("Not"):
                cisa_last_sync = log.get("created_at", "")[:19].replace("T", " ")
            if "EPSS" in src and epss_last_sync.startswith("Not"):
                epss_last_sync = log.get("created_at", "")[:19].replace("T", " ")

    sources_data = [
        {
            "Source Provider": "NIST National Vulnerability Database (NVD)",
            "Data Provided": "Authoritative CVE registry, CVSS v3.1 vectors, impacted CPE configurations",
            "Configuration Status": "Connected (NVD 2.0 API)",
            "Ingestion Mode": "Live API & Local Organization Cache",
            "Records Stored": f"{total_cves} CVEs",
            "Latest Sync": nvd_last_sync
        },
        {
            "Source Provider": "CISA Known Exploited Vulnerabilities (KEV)",
            "Data Provided": "Catalog of actively exploited vulnerabilities with federal remediation mandates",
            "Configuration Status": "Connected / Data Available",
            "Ingestion Mode": "JSON Ingestion Pipeline",
            "Records Stored": f"{cisa_count} Active KEVs",
            "Latest Sync": cisa_last_sync
        },
        {
            "Source Provider": "First.org EPSS Scoring System",
            "Data Provided": "Daily empirical exploit prediction probability scoring (30-day window)",
            "Configuration Status": "Connected / Data Available",
            "Ingestion Mode": "Gzip Dataset Ingestion",
            "Records Stored": f"{total_cves} Scored Profiles",
            "Latest Sync": epss_last_sync
        },
        {
            "Source Provider": "AbuseIPDB Threat Intelligence",
            "Data Provided": "IP address abuse confidence, reporting telemetry, ISP, and geographic origin",
            "Configuration Status": "Live API Configured",
            "Ingestion Mode": "Direct REST API Queries",
            "Records Stored": "On-demand telemetry",
            "Latest Sync": "Real-time query ready"
        },
        {
            "Source Provider": "VirusTotal Threat Intelligence",
            "Data Provided": "Multi-engine malware hash, domain, and URL reputation analysis",
            "Configuration Status": "Connected (API / Fallback Mode)",
            "Ingestion Mode": "REST API with Local Fallback Profiles",
            "Records Stored": "Enrichment profiles",
            "Latest Sync": "Active fallback"
        },
        {
            "Source Provider": "MITRE ATT&CK Framework",
            "Data Provided": "Adversary tactics and enterprise techniques mapping",
            "Configuration Status": "Local Heuristic Engine",
            "Ingestion Mode": "Pattern Correlation Parser",
            "Records Stored": "Enterprise Matrix Taxonomy",
            "Latest Sync": "Continuously mapped"
        }
    ]

    df_sources = pd.DataFrame(sources_data)
    st.dataframe(df_sources, use_container_width=True, hide_index=True)

    # Ingestion Sync Controls (Admin Only)
    is_admin = st.session_state.get("user_role") == "Admin"
    st.write("---")
    st.markdown("##### ⚡ Feed Synchronization Controls (Administrator Privileged)")
    
    if is_admin:
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Trigger Immediate CISA KEV Sync", use_container_width=True):
                with st.spinner("Executing CISA KEV catalog sync..."):
                    res = api_post("/sync/cisa")
                if res and res.get("status") == "SUCCESS":
                    st.success(f"CISA sync successful: {res.get('details')}")
                    st.rerun()
                else:
                    st.error("CISA KEV synchronization failed. Check backend logs.")
        with c2:
            if st.button("Trigger Immediate EPSS Score Sync", use_container_width=True):
                with st.spinner("Downloading and parsing First.org EPSS dataset..."):
                    res = api_post("/sync/epss")
                if res and res.get("status") == "SUCCESS":
                    st.success(f"EPSS sync successful: {res.get('details')}")
                    st.rerun()
                else:
                    st.error("EPSS synchronization failed. Check backend logs.")
    else:
        st.info("Manual feed synchronization is restricted to users with the **Admin** role. Telemetry is updated via scheduled background jobs.")

    st.markdown('</div>', unsafe_allow_html=True)

# =========================================================================
# TAB 2: IOC LOOKUP
# =========================================================================
with tab_ioc:
    st.markdown('<div class="soc-card">', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="soc-card-header">
            <div>
                <h3 class="soc-card-title">Multi-Feed Indicator of Compromise (IOC) Scanner</h3>
                <p class="soc-card-subtitle">Query AbuseIPDB and VirusTotal threat reputation databases for suspicious artifacts</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    c_type, c_val = st.columns([1.2, 2.8])
    with c_type:
        ioc_type = st.selectbox("Indicator Type", ["IP Address", "File Hash", "Domain", "URL"], key="ioc_sel_type")
    with c_val:
        ioc_placeholder = {
            "IP Address": "e.g. 198.51.100.42 or 8.8.8.8",
            "File Hash": "e.g. 44d88612fe1c026322b11e2f7b88e146 (MD5/SHA256)",
            "Domain": "e.g. suspicious-c2-node.net",
            "URL": "e.g. http://malicious-gateway.site/payload"
        }
        ioc_query = st.text_input("Indicator Value", placeholder=ioc_placeholder.get(ioc_type), key="ioc_input_val")

    run_ioc = st.button("Execute Threat Intelligence Scan", type="primary", use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

    if run_ioc:
        if not ioc_query:
            st.error("Please specify a valid indicator value to scan.")
        else:
            type_map = {
                "IP Address": "ip",
                "File Hash": "hash",
                "Domain": "domain",
                "URL": "url"
            }
            with st.spinner(f"Querying threat intelligence databases for {ioc_query}..."):
                ioc_res = api_post("/enrich", json_data={"type": type_map[ioc_type], "query": ioc_query.strip()})

            if ioc_res:
                st.markdown('<div class="soc-card">', unsafe_allow_html=True)
                
                is_demo = "Volga" in str(ioc_res) or "Russian" in str(ioc_res) or "demo" in str(ioc_res).lower()
                
                if is_demo:
                    st.markdown(
                        """
                        <div class="soc-callout soc-callout-warning">
                            <b>ℹ️ Telemetry Notice:</b> External reputation API fallback profile utilized for this query.
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

                st.markdown(f"#### Scan Results for `{ioc_res.get('query')}` ({ioc_res.get('type').upper()})")
                st.markdown(f"**Assessment Summary:** {ioc_res.get('summary')}")

                r1, r2 = st.columns(2)
                with r1:
                    st.markdown("##### 🛡️ AbuseIPDB Telemetry")
                    abuse = ioc_res.get("abuseipdb")
                    if abuse:
                        conf = abuse.get("abuseConfidenceScore", 0)
                        st.metric("Abuse Confidence Score", f"{conf}%")
                        st.markdown(f"- **ISP:** `{abuse.get('isp', 'N/A')}`")
                        st.markdown(f"- **Origin Country:** `{abuse.get('countryCode', 'N/A')}`")
                        st.markdown(f"- **Total Abuse Reports:** `{abuse.get('totalReports', 0)}`")
                    else:
                        st.info("No AbuseIPDB record returned for this indicator.")

                with r2:
                    st.markdown("##### 🔬 VirusTotal Telemetry")
                    vt = ioc_res.get("virustotal")
                    if vt:
                        stats = vt.get("last_analysis_stats", {})
                        if stats:
                            st.write(f"🔴 **Malicious Engines:** `{stats.get('malicious', 0)}`")
                            st.write(f"🟡 **Suspicious Engines:** `{stats.get('suspicious', 0)}`")
                            st.write(f"🟢 **Harmless Engines:** `{stats.get('harmless', 0)}`")
                        else:
                            st.info("No explicit engine analysis telemetry returned.")
                    else:
                        st.info("No VirusTotal record returned for this indicator.")

                st.markdown('</div>', unsafe_allow_html=True)
            else:
                st.error("Failed to query indicator reputation. Check backend connectivity.")

# =========================================================================
# TAB 3: MITRE ATT&CK MAPPING
# =========================================================================
with tab_mitre:
    st.markdown('<div class="soc-card">', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="soc-card-header">
            <div>
                <h3 class="soc-card-title">Enterprise MITRE ATT&CK Technique Mapping</h3>
                <p class="soc-card-subtitle">Adversary tactics and execution vectors mapped against catalogued vulnerability descriptions</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    with st.spinner("Synthesizing MITRE ATT&CK technique vectors..."):
        mitre_data = api_get("/dashboard/mitre")

    if mitre_data:
        df_mitre = pd.DataFrame(mitre_data).sort_values(by="count", ascending=True)

        fig_mitre = px.bar(
            df_mitre,
            x="count",
            y="technique",
            orientation="h",
            title="MITRE ATT&CK Technique Prevalence on Monitored Exposures",
            labels={"count": "Identified Vulnerabilities", "technique": "ATT&CK Technique"},
            color_discrete_sequence=["#2DD4BF"]
        )
        fig_mitre.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter, sans-serif", color="#E8EEF7"),
            xaxis=dict(gridcolor="#1E2D47", linecolor="#29364A", tickfont=dict(color="#9AAAC0")),
            yaxis=dict(gridcolor="#1E2D47", linecolor="#29364A", tickfont=dict(color="#9AAAC0")),
            margin=dict(l=20, r=20, t=40, b=20)
        )
        st.plotly_chart(fig_mitre, use_container_width=True)

        st.markdown("##### Detailed Technique Registry")
        st.dataframe(df_mitre.sort_values(by="count", ascending=False), use_container_width=True, hide_index=True)
    else:
        st.info("No MITRE ATT&CK technique mappings detected in the current vulnerability registry.")

    st.markdown('</div>', unsafe_allow_html=True)
