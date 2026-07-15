import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from typing import List, Dict, Any

# Define sleek, modern color palette
SEVERITY_COLORS = {
    "CRITICAL": "#ef4444", # Red
    "HIGH": "#f97316",     # Orange
    "MEDIUM": "#eab308",   # Yellow
    "LOW": "#3b82f6",      # Blue
    "INFO": "#94a3b8"      # Slate Gray
}

DARK_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter, sans-serif", color="#e2e8f0"),
    margin=dict(l=20, r=20, t=40, b=20),
    xaxis=dict(gridcolor="#1e293b", linecolor="#1e293b", tickfont=dict(color="#94a3b8")),
    yaxis=dict(gridcolor="#1e293b", linecolor="#1e293b", tickfont=dict(color="#94a3b8")),
    legend=dict(font=dict(color="#e2e8f0"))
)

def render_severity_pie_chart(severity_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders a stunning doughnut severity pie chart.
    """
    if not severity_data:
        # Placeholder figure
        fig = go.Figure()
        fig.add_annotation(text="No severity data available", showarrow=False, font=dict(size=14))
        fig.update_layout(**DARK_LAYOUT)
        return fig
        
    df = pd.DataFrame(severity_data)
    # Ensure uppercase columns for severity colors matching
    df["severity"] = df["severity"].str.upper()
    
    fig = px.pie(
        df, 
        values="count", 
        names="severity", 
        hole=0.4,
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
        title="Vulnerabilities by Severity"
    )
    
    fig.update_layout(**DARK_LAYOUT)
    fig.update_traces(textposition="inside", textinfo="percent+label", hovertemplate="%{label}: %{value} CVEs<extra></extra>")
    return fig

def render_risk_score_histogram(cvss_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders a bar chart representing CVSS score distributions.
    """
    if not cvss_data:
        fig = go.Figure()
        fig.add_annotation(text="No CVSS data available", showarrow=False, font=dict(size=14))
        fig.update_layout(**DARK_LAYOUT)
        return fig
        
    df = pd.DataFrame(cvss_data)
    
    fig = px.bar(
        df,
        x="bucket",
        y="count",
        title="CVSS Risk Score Distribution",
        labels={"bucket": "CVSS Range", "count": "CVE Count"},
        color_discrete_sequence=["#6366f1"] # Indigo accent
    )
    
    fig.update_layout(**DARK_LAYOUT)
    fig.update_traces(hovertemplate="CVSS %{x}: %{y} CVEs<extra></extra>")
    return fig

def render_epss_histogram(epss_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders a bar chart representing EPSS score distributions.
    """
    if not epss_data:
        fig = go.Figure()
        fig.add_annotation(text="No EPSS data available", showarrow=False, font=dict(size=14))
        fig.update_layout(**DARK_LAYOUT)
        return fig
        
    df = pd.DataFrame(epss_data)
    
    fig = px.bar(
        df,
        x="bucket",
        y="count",
        title="EPSS Distribution (Exploit Probability)",
        labels={"bucket": "EPSS Range", "count": "CVE Count"},
        color_discrete_sequence=["#10b981"] # Emerald green accent
    )
    
    fig.update_layout(**DARK_LAYOUT)
    fig.update_traces(hovertemplate="EPSS %{x}: %{y} CVEs<extra></extra>")
    return fig

def render_kev_bar_chart(kev_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders a horizontal bar chart displaying KEV count per vendor.
    """
    if not kev_data:
        fig = go.Figure()
        fig.add_annotation(text="No KEV statistics available", showarrow=False, font=dict(size=14))
        fig.update_layout(**DARK_LAYOUT)
        return fig
        
    df = pd.DataFrame(kev_data)
    # Sort descending
    df = df.sort_values(by="count", ascending=True)
    
    fig = px.bar(
        df,
        x="count",
        y="vendor_name",
        orientation="h",
        title="CISA KEV (Known Exploits) by Vendor",
        labels={"count": "Active KEV Count", "vendor_name": "Vendor"},
        color_discrete_sequence=["#f43f5e"] # Rose accent for high alert
    )
    
    fig.update_layout(**DARK_LAYOUT)
    fig.update_traces(hovertemplate="%{y}: %{x} Active KEVs<extra></extra>")
    return fig

def render_timeline_trend(timeline_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders a smooth timeline trend line chart of vulnerability publications.
    """
    if not timeline_data:
        fig = go.Figure()
        fig.add_annotation(text="No historical timeline data available", showarrow=False, font=dict(size=14))
        fig.update_layout(**DARK_LAYOUT)
        return fig
        
    df = pd.DataFrame(timeline_data)
    
    fig = px.line(
        df,
        x="date",
        y="count",
        title="Threat Velocity (Monthly Publication Trend)",
        labels={"date": "Month", "count": "Vulnerabilities Published"},
        markers=True
    )
    
    fig.update_layout(**DARK_LAYOUT)
    fig.update_traces(
        line=dict(width=3, color="#8b5cf6", shape="spline"), # Purple line with smooth curve
        marker=dict(size=8, color="#a78bfa"),
        hovertemplate="%{x}: %{y} CVEs<extra></extra>"
    )
    return fig
