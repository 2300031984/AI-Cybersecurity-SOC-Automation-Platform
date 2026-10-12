import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from typing import List, Dict, Any

# ThreatScope Dark SOC Color Tokens
SEVERITY_COLORS = {
    "Critical": "#EF4444", # Red
    "High": "#F97316",     # Orange
    "Medium": "#EAB308",   # Yellow
    "Low": "#22C55E",      # Green
    "Info": "#64748B"      # Slate Gray
}

DARK_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter, -apple-system, sans-serif", color="#E8EEF7"),
    margin=dict(l=20, r=20, t=40, b=20),
    xaxis=dict(gridcolor="#1E2D47", linecolor="#29364A", tickfont=dict(color="#9AAAC0")),
    yaxis=dict(gridcolor="#1E2D47", linecolor="#29364A", tickfont=dict(color="#9AAAC0")),
    legend=dict(font=dict(color="#E8EEF7"))
)

def render_risk_pie_chart(risk_data: Dict[str, int]) -> go.Figure:
    """
    Renders a doughnut risk distribution pie chart.
    """
    if not risk_data:
        fig = go.Figure()
        fig.add_annotation(text="No risk data recorded", showarrow=False, font=dict(size=14, color="#9AAAC0"))
        fig.update_layout(**DARK_LAYOUT)
        return fig

    formatted_data = {}
    for k, v in risk_data.items():
        title_key = k.strip().capitalize()
        formatted_data[title_key] = v

    fig = px.pie(
        values=list(formatted_data.values()),
        names=list(formatted_data.keys()),
        hole=0.55,
        color=list(formatted_data.keys()),
        color_discrete_map=SEVERITY_COLORS,
        title="Vulnerability Risk Distribution"
    )
    
    fig.update_layout(**DARK_LAYOUT)
    fig.update_traces(
        textposition="inside",
        textinfo="percent+label",
        hovertemplate="%{label}: %{value} CVEs<extra></extra>",
        marker=dict(line=dict(color="#111C2E", width=2))
    )
    return fig

def render_timeline_trend_daily(timeline_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders a daily threat velocity area/line chart.
    """
    if not timeline_data:
        fig = go.Figure()
        fig.add_annotation(text="No timeline trend telemetry recorded", showarrow=False, font=dict(size=14, color="#9AAAC0"))
        fig.update_layout(**DARK_LAYOUT)
        return fig
        
    df = pd.DataFrame(timeline_data)
    
    fig = px.area(
        df,
        x="date",
        y="count",
        title="Vulnerability Ingestion Trend",
        labels={"date": "Date", "count": "CVE Count"},
        color_discrete_sequence=["rgba(45, 212, 191, 0.3)"] # Semi-transparent Teal
    )
    
    fig.update_layout(**DARK_LAYOUT)
    fig.update_traces(
        line=dict(width=2.5, color="#2DD4BF"),
        hovertemplate="Date: %{x}<br>Count: %{y} CVEs<extra></extra>"
    )
    return fig

def render_mitre_bar_chart(mitre_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders a horizontal bar chart for MITRE ATT&CK technique frequencies.
    """
    if not mitre_data:
        fig = go.Figure()
        fig.add_annotation(text="No MITRE statistics available", showarrow=False, font=dict(size=14, color="#9AAAC0"))
        fig.update_layout(**DARK_LAYOUT)
        return fig
        
    df = pd.DataFrame(mitre_data)
    df = df.sort_values(by="count", ascending=True)
    
    fig = px.bar(
        df,
        x="count",
        y="technique",
        orientation="h",
        title="MITRE ATT&CK Technique Frequency",
        labels={"count": "Occurrences", "technique": "Adversary Technique"},
        color_discrete_sequence=["#38BDF8"] # Cyan Accent
    )
    
    fig.update_layout(**DARK_LAYOUT)
    fig.update_traces(
        hovertemplate="%{y}: %{x} occurrences<extra></extra>",
        marker=dict(line=dict(color="#111C2E", width=1))
    )
    return fig

def epss_chart(data):
    """
    Renders an EPSS Exploit Probability histogram.
    """
    fig = px.histogram(
        data,
        x="epss",
        title="EPSS Exploit Probability Distribution",
        labels={"epss": "EPSS Probability Score"},
        color_discrete_sequence=["#2DD4BF"] # ThreatScope Teal
    )
    fig.update_layout(**DARK_LAYOUT)
    return fig
