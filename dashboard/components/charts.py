import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from typing import List, Dict, Any

# ThreatScope Dark SOC Severity Color Tokens
SEVERITY_COLORS = {
    "CRITICAL": "#EF4444", # Accessible Red
    "HIGH": "#F97316",     # Amber-Orange
    "MEDIUM": "#EAB308",   # Yellow
    "LOW": "#22C55E",      # Green
    "INFO": "#64748B",     # Slate Gray
    "UNKNOWN": "#64748B"
}

ENTERPRISE_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter, -apple-system, sans-serif", color="#E8EEF7", size=12),
    margin=dict(l=20, r=20, t=40, b=20),
    xaxis=dict(
        gridcolor="#1E2D47",
        linecolor="#29364A",
        tickfont=dict(color="#9AAAC0", size=11),
        title_font=dict(size=12, color="#9AAAC0")
    ),
    yaxis=dict(
        gridcolor="#1E2D47",
        linecolor="#29364A",
        tickfont=dict(color="#9AAAC0", size=11),
        title_font=dict(size=12, color="#9AAAC0")
    ),
    legend=dict(
        font=dict(color="#E8EEF7", size=11),
        orientation="h",
        yanchor="bottom",
        y=1.02,
        xanchor="right",
        x=1
    )
)

def render_severity_pie_chart(severity_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders an analyst-grade doughnut chart displaying vulnerability breakdown by severity.
    """
    if not severity_data:
        fig = go.Figure()
        fig.add_annotation(text="No severity telemetry recorded", showarrow=False, font=dict(size=13, color="#9AAAC0"))
        fig.update_layout(**ENTERPRISE_LAYOUT)
        return fig
        
    df = pd.DataFrame(severity_data)
    df["severity"] = df["severity"].astype(str).str.upper()
    
    fig = px.pie(
        df, 
        values="count", 
        names="severity", 
        hole=0.55,
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
        title="Vulnerabilities by Severity"
    )
    
    fig.update_layout(**ENTERPRISE_LAYOUT)
    fig.update_traces(
        textposition="inside",
        textinfo="percent+value",
        hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Proportion: %{percent}<extra></extra>",
        marker=dict(line=dict(color="#111C2E", width=2))
    )
    return fig

def render_risk_score_histogram(cvss_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders a bar chart representing CVSS v3 score distribution across tracked assets.
    """
    if not cvss_data:
        fig = go.Figure()
        fig.add_annotation(text="No CVSS score records", showarrow=False, font=dict(size=13, color="#9AAAC0"))
        fig.update_layout(**ENTERPRISE_LAYOUT)
        return fig
        
    df = pd.DataFrame(cvss_data)
    
    fig = px.bar(
        df,
        x="bucket",
        y="count",
        title="CVSS Score Range Distribution",
        labels={"bucket": "CVSS Base Score Range", "count": "Vulnerability Count"},
        color_discrete_sequence=["#2DD4BF"] # ThreatScope Teal Accent
    )
    
    fig.update_layout(**ENTERPRISE_LAYOUT)
    fig.update_traces(
        hovertemplate="<b>CVSS Range %{x}</b><br>Vulnerabilities: %{y}<extra></extra>",
        marker=dict(line=dict(color="#111C2E", width=1))
    )
    return fig

def render_epss_histogram(epss_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders a histogram of EPSS probabilities (likelihood of in-the-wild exploitation).
    """
    if not epss_data:
        fig = go.Figure()
        fig.add_annotation(text="No EPSS telemetry recorded", showarrow=False, font=dict(size=13, color="#9AAAC0"))
        fig.update_layout(**ENTERPRISE_LAYOUT)
        return fig
        
    df = pd.DataFrame(epss_data)
    
    fig = px.bar(
        df,
        x="bucket",
        y="count",
        title="EPSS Exploit Likelihood Distribution",
        labels={"bucket": "EPSS Probability Range (0.0 - 1.0)", "count": "CVE Count"},
        color_discrete_sequence=["#38BDF8"] # Information Cyan Accent
    )
    
    fig.update_layout(**ENTERPRISE_LAYOUT)
    fig.update_traces(
        hovertemplate="<b>EPSS %{x}</b><br>Vulnerabilities: %{y}<extra></extra>",
        marker=dict(line=dict(color="#111C2E", width=1))
    )
    return fig

def render_kev_bar_chart(kev_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders a horizontal bar chart displaying CISA KEV (actively exploited) counts per vendor.
    """
    if not kev_data:
        fig = go.Figure()
        fig.add_annotation(text="No CISA KEV catalog records", showarrow=False, font=dict(size=13, color="#9AAAC0"))
        fig.update_layout(**ENTERPRISE_LAYOUT)
        return fig
        
    df = pd.DataFrame(kev_data).sort_values(by="count", ascending=True)
    
    fig = px.bar(
        df,
        x="count",
        y="vendor_name",
        orientation="h",
        title="CISA KEV Catalog Entries by Impacted Vendor",
        labels={"count": "Catalogued KEV Entries", "vendor_name": "Vendor"},
        color_discrete_sequence=["#EF4444"] # ThreatScope Red Alert
    )
    
    fig.update_layout(**ENTERPRISE_LAYOUT)
    fig.update_traces(
        hovertemplate="<b>%{y}</b><br>CISA KEV Entries: %{x}<extra></extra>",
        marker=dict(line=dict(color="#111C2E", width=1))
    )
    return fig

def render_timeline_trend(timeline_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders a timeline trend chart of vulnerability publications.
    """
    if not timeline_data:
        fig = go.Figure()
        fig.add_annotation(text="No historical timeline data", showarrow=False, font=dict(size=13, color="#9AAAC0"))
        fig.update_layout(**ENTERPRISE_LAYOUT)
        return fig
        
    df = pd.DataFrame(timeline_data)
    
    fig = px.line(
        df,
        x="date",
        y="count",
        title="Ingested Threat Timeline Velocity",
        labels={"date": "Timeline Date", "count": "CVEs Ingested"},
        markers=True
    )
    
    fig.update_layout(**ENTERPRISE_LAYOUT)
    fig.update_traces(
        line=dict(width=2.5, color="#2DD4BF"),
        marker=dict(size=6, color="#38BDF8"),
        hovertemplate="<b>%{x}</b><br>Ingested CVEs: %{y}<extra></extra>"
    )
    return fig
