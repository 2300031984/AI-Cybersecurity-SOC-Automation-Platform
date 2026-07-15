import streamlit as st

def inject_custom_css():
    """
    Injects custom CSS stylesheets into Streamlit to create a premium dark mode,
    glassmorphism effects, clean typography (Inter font), and customized buttons/widgets.
    """
    st.markdown(
        """
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            /* 1. Global Reset & Typography */
            html, body, [class*="css"] {
                font-family: 'Inter', sans-serif;
                background-color: #0b0f19 !important;
                color: #e2e8f0 !important;
            }
            
            /* Sidebar Styling */
            [data-testid="stSidebar"] {
                background-color: #0f172a !important;
                border-right: 1px solid #1e293b !important;
            }
            [data-testid="stSidebar"] * {
                color: #94a3b8 !important;
            }
            
            /* Main Content Margins */
            .main .block-container {
                max-width: 1200px;
                padding-top: 2rem;
                padding-bottom: 2rem;
            }
            
            /* Hide Streamlit Default Watermarks */
            #MainMenu { visibility: hidden; }
            footer { visibility: hidden; }
            header { background: rgba(11, 15, 25, 0.8) !important; backdrop-filter: blur(10px); }
            
            /* 2. Glassmorphism Card System */
            .glass-card {
                background: rgba(30, 41, 59, 0.4);
                border: 1px solid rgba(255, 255, 255, 0.05);
                border-radius: 12px;
                padding: 1.5rem;
                box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.2);
                backdrop-filter: blur(12px);
                -webkit-backdrop-filter: blur(12px);
                margin-bottom: 1rem;
                transition: transform 0.2s ease, border-color 0.2s ease;
            }
            .glass-card:hover {
                transform: translateY(-2px);
                border-color: rgba(99, 102, 241, 0.3); /* Accent Border on hover */
            }
            
            /* Card Gradients */
            .card-title {
                font-size: 0.85rem;
                font-weight: 500;
                color: #94a3b8;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                margin-bottom: 0.5rem;
            }
            .card-value {
                font-size: 2.2rem;
                font-weight: 700;
                color: #ffffff;
                margin-bottom: 0.2rem;
                line-height: 1;
            }
            .card-subtext {
                font-size: 0.75rem;
                color: #64748b;
            }
            
            /* 3. Status Badges */
            .badge {
                display: inline-block;
                padding: 0.25rem 0.6rem;
                font-size: 0.7rem;
                font-weight: 600;
                border-radius: 9999px;
                text-transform: uppercase;
                letter-spacing: 0.025em;
            }
            .badge-critical { background-color: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
            .badge-high { background-color: rgba(249, 115, 22, 0.15); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.3); }
            .badge-medium { background-color: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.3); }
            .badge-low { background-color: rgba(59, 130, 246, 0.15); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.3); }
            .badge-info { background-color: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.3); }
            
            /* 4. Beautiful Custom Banner headers */
            .banner {
                background: linear-gradient(135deg, #1e1b4b 0%, #311042 100%);
                border: 1px solid rgba(139, 92, 246, 0.2);
                border-radius: 12px;
                padding: 2rem;
                margin-bottom: 2rem;
                box-shadow: 0 4px 20px 0 rgba(139, 92, 246, 0.1);
            }
            .banner h1 {
                font-size: 2.2rem;
                font-weight: 800;
                color: #ffffff;
                margin: 0 0 0.5rem 0;
            }
            .banner p {
                font-size: 1rem;
                color: #c084fc;
                margin: 0;
            }
            
            /* Custom Table/DataFrame container */
            div[data-testid="stDataFrame"] {
                background-color: #0f172a !important;
                border: 1px solid #1e293b !important;
                border-radius: 8px;
                padding: 5px;
            }
        </style>
        """,
        unsafe_allow_html=True
    )

def render_banner(title: str, subtitle: str):
    """
    Renders a stunning customized header banner.
    """
    st.markdown(
        f"""
        <div class="banner">
            <h1>{title}</h1>
            <p>{subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True
    )

def render_metric_card(title: str, value: str, subtext: str = ""):
    """
    Renders a custom glassmorphism KPI card.
    """
    st.markdown(
        f"""
        <div class="glass-card">
            <div class="card-title">{title}</div>
            <div class="card-value">{value}</div>
            <div class="card-subtext">{subtext}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

def get_severity_badge_html(severity: str) -> str:
    """
    Returns the HTML snippet for a stylized severity status badge.
    """
    sev = str(severity).lower()
    if sev == "critical":
        return f'<span class="badge badge-critical">{severity}</span>'
    elif sev == "high":
        return f'<span class="badge badge-high">{severity}</span>'
    elif sev == "medium":
        return f'<span class="badge badge-medium">{severity}</span>'
    elif sev == "low":
        return f'<span class="badge badge-low">{severity}</span>'
    else:
        return f'<span class="badge badge-info">{severity}</span>'
