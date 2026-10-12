import streamlit as st
import requests
import os
from typing import Optional

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000/api/v1")

def inject_custom_css():
    """
    Injects ThreatScope Dark SOC & Threat Intelligence Console design system.
    Palette:
      - App background: #0B1220
      - Topbar/Navbar background: #080E19
      - Primary panel / card: #111C2E
      - Elevated panel: #172338
      - Borders: #29364A
      - Primary text: #E8EEF7
      - Secondary text: #9AAAC0
      - Primary accent (Teal): #2DD4BF
      - Info accent (Cyan): #38BDF8
      - Critical: #EF4444
      - High: #F97316
      - Medium: #EAB308
      - Low: #22C55E
      - Unknown / Info: #64748B
    """
    st.markdown(
        """
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
        <style>
            /* 1. Global Reset & Dark SOC Typography */
            html, body, [class*="css"] {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
                background-color: #0B1220 !important;
                color: #E8EEF7 !important;
            }

            .stApp {
                background-color: #0B1220 !important;
            }

            /* Main Content Container - Full Width Workspace */
            .main .block-container {
                max-width: 100% !important;
                padding-top: 0.5rem !important;
                padding-bottom: 3rem !important;
                padding-left: 1.75rem !important;
                padding-right: 1.75rem !important;
                background-color: #0B1220 !important;
            }

            /* Hide Streamlit Default Chrome & Sidebar completely */
            #MainMenu { visibility: hidden !important; }
            footer { visibility: hidden !important; }
            header { display: none !important; }
            [data-testid="stSidebar"] { display: none !important; }
            [data-testid="collapsedControl"] { display: none !important; }
            section[data-testid="stSidebar"] { display: none !important; }

            /* 2. Top Navigation Bar Styles */
            .threatscope-nav-container {
                position: sticky;
                top: 0;
                z-index: 999;
                background-color: #080E19;
                border: 1px solid #29364A;
                border-radius: 10px;
                padding: 0.65rem 1.25rem;
                margin-bottom: 0.75rem;
                box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35);
            }

            .threatscope-brand {
                display: flex;
                align-items: center;
                gap: 10px;
            }

            .threatscope-brand-icon {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 32px;
                height: 32px;
                border-radius: 6px;
                background: linear-gradient(135deg, rgba(45, 212, 191, 0.2) 0%, rgba(56, 189, 248, 0.15) 100%);
                border: 1px solid #2DD4BF;
                color: #2DD4BF;
                font-size: 1.1rem;
            }

            .threatscope-brand-title {
                font-size: 1.05rem;
                font-weight: 700;
                color: #E8EEF7 !important;
                letter-spacing: -0.01em;
                line-height: 1.1;
            }

            .threatscope-brand-sub {
                font-size: 0.65rem;
                font-weight: 600;
                color: #2DD4BF !important;
                text-transform: uppercase;
                letter-spacing: 0.08em;
            }

            /* Style Streamlit page_link items in Topnav */
            div[data-testid="stPageLink-NavLink"] {
                background: transparent !important;
                border-radius: 6px !important;
                transition: all 0.15s ease !important;
                padding: 0.3rem 0.5rem !important;
            }

            a[data-testid="stPageLink-NavLink"] {
                color: #9AAAC0 !important;
                text-decoration: none !important;
                font-size: 0.82rem !important;
                font-weight: 500 !important;
                border-bottom: 2px solid transparent !important;
                border-radius: 4px !important;
                display: flex !important;
                align-items: center !important;
                gap: 6px !important;
            }

            a[data-testid="stPageLink-NavLink"]:hover {
                color: #E8EEF7 !important;
                background-color: rgba(45, 212, 191, 0.08) !important;
            }

            a[data-testid="stPageLink-NavLink"][aria-current="page"] {
                color: #2DD4BF !important;
                font-weight: 600 !important;
                background-color: rgba(45, 212, 191, 0.12) !important;
                border-bottom: 2px solid #2DD4BF !important;
            }

            /* 3. Second Row Slim Context Bar */
            .threatscope-context-bar {
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
                gap: 10px;
                background-color: #111C2E;
                border: 1px solid #29364A;
                border-radius: 8px;
                padding: 0.55rem 1rem;
                margin-bottom: 1.25rem;
            }

            .threatscope-context-left {
                display: flex;
                align-items: center;
                gap: 8px;
                font-size: 0.78rem;
            }

            .threatscope-breadcrumb {
                font-size: 0.7rem;
                font-weight: 600;
                color: #9AAAC0;
                letter-spacing: 0.05em;
                text-transform: uppercase;
            }

            .threatscope-context-divider {
                color: #29364A;
            }

            .threatscope-context-title {
                font-size: 0.95rem;
                font-weight: 700;
                color: #E8EEF7;
            }

            .threatscope-context-right {
                display: flex;
                align-items: center;
                gap: 8px;
                flex-wrap: wrap;
            }

            /* Page Header Block */
            .threatscope-page-header {
                margin-bottom: 1.25rem;
                border-bottom: 1px solid #1E2D47;
                padding-bottom: 0.85rem;
            }
            .threatscope-page-title {
                font-size: 1.35rem;
                font-weight: 700;
                color: #E8EEF7;
                margin: 0 0 0.2rem 0;
                letter-spacing: -0.01em;
            }
            .threatscope-page-desc {
                font-size: 0.84rem;
                color: #9AAAC0;
                margin: 0;
            }

            /* 4. ThreatScope Cards & Surfaces */
            .soc-card {
                background-color: #111C2E;
                border: 1px solid #29364A;
                border-radius: 8px;
                padding: 1.25rem;
                margin-bottom: 1.25rem;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
            }

            .soc-card-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding-bottom: 0.75rem;
                margin-bottom: 0.85rem;
                border-bottom: 1px solid #1E2D47;
            }

            .soc-card-title {
                font-size: 0.92rem;
                font-weight: 600;
                color: #E8EEF7;
                margin: 0;
                letter-spacing: 0.01em;
            }

            .soc-card-subtitle {
                font-size: 0.75rem;
                color: #9AAAC0;
                margin: 0.15rem 0 0 0;
            }

            /* KPI Metric Cards */
            .kpi-card {
                background-color: #111C2E;
                border: 1px solid #29364A;
                border-radius: 8px;
                padding: 1.1rem 1.25rem;
                position: relative;
                overflow: hidden;
                box-shadow: 0 2px 6px rgba(0, 0, 0, 0.2);
            }
            .kpi-card-border-critical { border-top: 3px solid #EF4444; }
            .kpi-card-border-high { border-top: 3px solid #F97316; }
            .kpi-card-border-medium { border-top: 3px solid #EAB308; }
            .kpi-card-border-low { border-top: 3px solid #22C55E; }
            .kpi-card-border-neutral { border-top: 3px solid #2DD4BF; }
            
            .kpi-label {
                font-size: 0.72rem;
                font-weight: 600;
                color: #9AAAC0;
                text-transform: uppercase;
                letter-spacing: 0.06em;
                margin-bottom: 0.35rem;
            }
            .kpi-value {
                font-size: 1.85rem;
                font-weight: 700;
                color: #E8EEF7;
                line-height: 1.1;
                margin-bottom: 0.35rem;
                font-family: 'Inter', sans-serif;
            }
            .kpi-subtext {
                font-size: 0.72rem;
                color: #9AAAC0;
                display: flex;
                align-items: center;
                gap: 4px;
                line-height: 1.3;
            }

            /* System Telemetry Status Pills */
            .status-pill {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                padding: 0.2rem 0.55rem;
                border-radius: 9999px;
                font-size: 0.68rem;
                font-weight: 500;
                letter-spacing: 0.02em;
            }
            .status-pill-green {
                background-color: rgba(34, 197, 94, 0.12);
                color: #4ADE80;
                border: 1px solid rgba(34, 197, 94, 0.3);
            }
            .status-pill-green::before {
                content: "";
                display: inline-block;
                width: 6px;
                height: 6px;
                border-radius: 50%;
                background-color: #22C55E;
            }
            .status-pill-amber {
                background-color: rgba(234, 179, 8, 0.12);
                color: #FACC15;
                border: 1px solid rgba(234, 179, 8, 0.3);
            }
            .status-pill-amber::before {
                content: "";
                display: inline-block;
                width: 6px;
                height: 6px;
                border-radius: 50%;
                background-color: #EAB308;
            }
            .status-pill-red {
                background-color: rgba(239, 68, 68, 0.12);
                color: #F87171;
                border: 1px solid rgba(239, 68, 68, 0.3);
            }
            .status-pill-red::before {
                content: "";
                display: inline-block;
                width: 6px;
                height: 6px;
                border-radius: 50%;
                background-color: #EF4444;
            }
            .status-pill-neutral {
                background-color: #172338;
                color: #9AAAC0;
                border: 1px solid #29364A;
            }

            /* 5. Severity Status Badges */
            .badge {
                display: inline-block;
                padding: 0.2rem 0.55rem;
                font-size: 0.68rem;
                font-weight: 600;
                border-radius: 4px;
                text-transform: uppercase;
                letter-spacing: 0.04em;
                line-height: 1.2;
            }
            .badge-critical {
                background-color: rgba(239, 68, 68, 0.15);
                color: #F87171;
                border: 1px solid rgba(239, 68, 68, 0.4);
            }
            .badge-high {
                background-color: rgba(249, 115, 22, 0.15);
                color: #FB923C;
                border: 1px solid rgba(249, 115, 22, 0.4);
            }
            .badge-medium {
                background-color: rgba(234, 179, 8, 0.15);
                color: #FACC15;
                border: 1px solid rgba(234, 179, 8, 0.4);
            }
            .badge-low {
                background-color: rgba(34, 197, 94, 0.15);
                color: #4ADE80;
                border: 1px solid rgba(34, 197, 94, 0.4);
            }
            .badge-info {
                background-color: #172338;
                color: #9AAAC0;
                border: 1px solid #29364A;
            }
            .badge-kev {
                background-color: rgba(244, 63, 94, 0.18);
                color: #FB7185;
                border: 1px solid rgba(244, 63, 94, 0.5);
                font-weight: 700;
            }

            /* Code & Monospace styling */
            .mono-text {
                font-family: 'JetBrains Mono', monospace !important;
                font-size: 0.82rem;
                color: #38BDF8;
            }
            code {
                font-family: 'JetBrains Mono', monospace !important;
                background-color: #172338 !important;
                color: #38BDF8 !important;
                padding: 0.15rem 0.4rem !important;
                border-radius: 4px !important;
                border: 1px solid #29364A !important;
                font-size: 0.8rem !important;
            }

            /* 6. Form Controls, Inputs & Dark Interactive Elements */
            div[data-baseweb="input"], div[data-baseweb="base-input"] {
                background-color: #111C2E !important;
                border-color: #29364A !important;
                border-radius: 6px !important;
                color: #E8EEF7 !important;
            }
            div[data-baseweb="input"]:focus-within {
                border-color: #2DD4BF !important;
                box-shadow: 0 0 0 1px #2DD4BF !important;
            }
            div[data-baseweb="input"] input {
                color: #E8EEF7 !important;
                background-color: transparent !important;
            }
            div[data-baseweb="input"] input::placeholder {
                color: #64748B !important;
            }

            div[data-baseweb="select"] > div {
                background-color: #111C2E !important;
                border-color: #29364A !important;
                color: #E8EEF7 !important;
                border-radius: 6px !important;
            }
            div[data-baseweb="select"] * {
                color: #E8EEF7 !important;
            }

            div[data-baseweb="textarea"] {
                background-color: #111C2E !important;
                border-color: #29364A !important;
                border-radius: 6px !important;
            }
            div[data-baseweb="textarea"] textarea {
                color: #E8EEF7 !important;
                background-color: transparent !important;
            }

            /* Buttons */
            .stButton > button {
                border-radius: 6px !important;
                font-weight: 500 !important;
                font-size: 0.84rem !important;
                padding: 0.42rem 0.95rem !important;
                transition: all 0.15s ease !important;
            }
            .stButton > button[kind="primary"] {
                background-color: #2DD4BF !important;
                color: #080E19 !important;
                border: 1px solid #2DD4BF !important;
                font-weight: 600 !important;
            }
            .stButton > button[kind="primary"]:hover {
                background-color: #14B8A6 !important;
                border-color: #14B8A6 !important;
            }
            .stButton > button[kind="secondary"] {
                background-color: #172338 !important;
                color: #E8EEF7 !important;
                border: 1px solid #29364A !important;
            }
            .stButton > button[kind="secondary"]:hover {
                background-color: #1E2D47 !important;
                border-color: #38BDF8 !important;
            }

            /* Streamlit Tabs Styling */
            div[data-baseweb="tab-list"] {
                background-color: transparent !important;
                border-bottom: 1px solid #29364A !important;
                gap: 8px !important;
            }
            div[data-baseweb="tab"] {
                font-size: 0.84rem !important;
                font-weight: 500 !important;
                color: #9AAAC0 !important;
                padding: 0.5rem 1rem !important;
                border-radius: 6px 6px 0 0 !important;
                background-color: transparent !important;
            }
            div[data-baseweb="tab"]:hover {
                color: #E8EEF7 !important;
                background-color: rgba(255, 255, 255, 0.03) !important;
            }
            div[data-baseweb="tab"][aria-selected="true"] {
                color: #2DD4BF !important;
                font-weight: 600 !important;
                border-bottom: 2px solid #2DD4BF !important;
                background-color: rgba(45, 212, 191, 0.05) !important;
            }

            /* Dataframe Dark Styling */
            div[data-testid="stDataFrame"] {
                border: 1px solid #29364A !important;
                border-radius: 8px !important;
                background-color: #111C2E !important;
            }

            /* Expander Styling */
            div[data-testid="stExpander"] {
                border: 1px solid #29364A !important;
                border-radius: 8px !important;
                background-color: #111C2E !important;
                margin-bottom: 0.75rem !important;
            }
            div[data-testid="stExpander"] summary {
                color: #E8EEF7 !important;
                font-size: 0.86rem !important;
            }

            /* Callout styles */
            .soc-callout {
                padding: 0.85rem 1rem;
                border-radius: 6px;
                font-size: 0.82rem;
                line-height: 1.5;
                margin-bottom: 1rem;
                background-color: #172338;
                border: 1px solid #29364A;
            }
            .soc-callout-info {
                border-left: 4px solid #38BDF8;
                color: #E8EEF7;
            }
            .soc-callout-warning {
                border-left: 4px solid #EAB308;
                color: #FDE047;
            }
            .soc-callout-critical {
                border-left: 4px solid #EF4444;
                color: #FCA5A5;
            }
        </style>
        """,
        unsafe_allow_html=True
    )

def get_live_backend_health() -> dict:
    """
    Queries backend health check endpoint to verify genuine database and service connection.
    Never hardcodes 'operational' unless verified.
    """
    try:
        root_url = BACKEND_URL.replace("/api/v1", "")
        resp = requests.get(f"{root_url}/", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "online": True,
                "database": data.get("database", "connected"),
                "service": data.get("service", "FastAPI"),
                "gemini": data.get("gemini_api", "mock_mode")
            }
    except Exception:
        pass
    return {"online": False, "database": "unavailable", "service": "offline", "gemini": "unavailable"}

def render_top_navigation(active_page: str):
    """
    Renders ThreatScope sticky horizontal top navigation bar.
    Row 1: Left: Shield mark and 'ThreatScope' product name.
           Center: Main navigation menu (Overview, Vulnerabilities, Risk Prioritization, Threat Intel, AI Assistant, Automation, Reports).
           Right: User profile & Settings.
    """
    # Top Bar Container
    st.markdown('<div class="threatscope-nav-container">', unsafe_allow_html=True)
    
    col_brand, col_nav, col_user = st.columns([2.4, 7.8, 1.8], vertical_alignment="center")

    with col_brand:
        st.markdown(
            """
            <div class="threatscope-brand">
                <div class="threatscope-brand-icon">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2DD4BF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"/>
                        <path d="M9 12l2 2 4-4"/>
                    </svg>
                </div>
                <div>
                    <div class="threatscope-brand-title">ThreatScope</div>
                    <div class="threatscope-brand-sub">Risk Operations</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col_nav:
        n_cols = st.columns(7)
        nav_items = [
            ("Overview", "pages/01_Overview.py", "📊"),
            ("Vulnerabilities", "pages/02_Vulnerabilities.py", "🔍"),
            ("Risk Prioritization", "pages/04_Risk_Prioritization.py", "🎯"),
            ("Threat Intel", "pages/03_Threat_Intelligence.py", "📡"),
            ("AI Assistant", "pages/05_AI_Security_Assistant.py", "🤖"),
            ("Automation", "pages/06_Automation_Workflows.py", "⚡"),
            ("Reports", "pages/07_Reports.py", "📄")
        ]
        
        for idx, (label, target_path, icon) in enumerate(nav_items):
            with n_cols[idx]:
                st.page_link(
                    target_path,
                    label=label,
                    icon=icon,
                    disabled=False
                )

    with col_user:
        u_c1, u_c2 = st.columns([1.1, 0.9])
        with u_c1:
            st.page_link("pages/08_Settings.py", label="Settings", icon="⚙️")
        with u_c2:
            if st.button("Exit", key="topnav_logout_btn", help="Sign out of current tenant session"):
                from dashboard.components.auth import clear_session
                clear_session()
                st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)

def render_context_bar(title: str, breadcrumb: str, freshness_ts: Optional[str] = None):
    """
    Renders the slim secondary row context bar with breadcrumb,
    genuine backend health telemetry, tenant identity, and data freshness.
    """
    health = get_live_backend_health()
    raw_org = st.session_state.get("org_name")
    
    # If no configured organization, generic default, or sample seed org, display "Local Lab" or "Demo Environment"
    if not raw_org or raw_org in ["Global Registry", "Enterprise Tenant", "None", "Microsoft", "Amazon", "Infosys", "TCS", "Deloitte"]:
        org_display = "Local Lab"
    else:
        org_display = str(raw_org)

    username = st.session_state.get("username", "Analyst")
    role = st.session_state.get("user_role", "Viewer")
    
    if health["online"]:
        api_pill = '<span class="status-pill status-pill-green">API: Connected</span>'
    else:
        api_pill = '<span class="status-pill status-pill-red">API: Disconnected</span>'

    freshness_display = freshness_ts or "Live Synced"

    st.markdown(
        f"""
        <div class="threatscope-context-bar">
            <div class="threatscope-context-left">
                <span class="threatscope-breadcrumb">THREATSCOPE / {breadcrumb.upper()}</span>
                <span class="threatscope-context-divider">|</span>
                <span class="threatscope-context-title">{title}</span>
            </div>
            <div class="threatscope-context-right">
                {api_pill}
                <span class="status-pill status-pill-neutral">🏢 {org_display}</span>
                <span class="status-pill status-pill-neutral">🕒 {freshness_display}</span>
                <span class="status-pill status-pill-neutral">👤 {username} ({role})</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

def render_page_header(title: str, description: str):
    """
    Renders compact page header with title and one-line description.
    """
    st.markdown(
        f"""
        <div class="threatscope-page-header">
            <h1 class="threatscope-page-title">{title}</h1>
            <p class="threatscope-page-desc">{description}</p>
        </div>
        """,
        unsafe_allow_html=True
    )

def render_top_navbar(title: str, breadcrumb: str, freshness_ts: Optional[str] = None):
    """
    Renders the unified top navigation and context bar.
    Maintains compatibility with legacy page calls.
    """
    render_top_navigation(active_page=breadcrumb)
    render_context_bar(title=title, breadcrumb=breadcrumb, freshness_ts=freshness_ts)

def render_kpi_card(title: str, value: str, subtext: str = "", border_type: str = "neutral"):
    """
    Renders a restrained Dark SOC KPI card.
    border_type: 'critical', 'high', 'medium', 'low', 'neutral'
    """
    border_class = f"kpi-card-border-{border_type}"
    st.markdown(
        f"""
        <div class="kpi-card {border_class}">
            <div class="kpi-label">{title}</div>
            <div class="kpi-value">{value}</div>
            <div class="kpi-subtext">{subtext}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

def render_sidebar(active_page: str):
    """
    Legacy sidebar function preserved for backward compatibility.
    Sidebar is hidden by default in CSS in favor of top navigation.
    """
    pass

def get_severity_badge_html(severity: str) -> str:
    """
    Returns HTML snippet for standardized severity badge in Dark SOC styling.
    """
    sev = str(severity).upper() if severity else "UNKNOWN"
    if sev == "CRITICAL":
        return f'<span class="badge badge-critical">{sev}</span>'
    elif sev == "HIGH":
        return f'<span class="badge badge-high">{sev}</span>'
    elif sev == "MEDIUM":
        return f'<span class="badge badge-medium">{sev}</span>'
    elif sev == "LOW":
        return f'<span class="badge badge-low">{sev}</span>'
    else:
        return f'<span class="badge badge-info">{sev}</span>'

def get_kev_badge_html(is_kev: bool) -> str:
    """
    Returns HTML snippet for CISA KEV status badge in Dark SOC styling.
    """
    if is_kev:
        return '<span class="badge badge-kev">⚠️ CISA KEV (ACTIVE)</span>'
    return '<span class="badge badge-info">No Active Exploit</span>'
