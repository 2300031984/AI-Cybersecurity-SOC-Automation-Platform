import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from typing import List, Dict, Any

# Define sleek, modern color palette
SEVERITY_COLORS = {
    "Critical": "#ef4444", # Red
    "High": "#f97316",     # Orange
    "Medium": "#eab308",   # Yellow
    "Low": "#3b82f6",      # Blue
    "Info": "#94a3b8"      # Slate Gray
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

def render_risk_pie_chart(risk_data: Dict[str, int]) -> go.Figure:
    """
    Renders a stunning doughnut risk distribution pie chart.
    """
    if not risk_data:
        fig = go.Figure()
        fig.add_annotation(text="No risk data available", showarrow=False, font=dict(size=14))
        fig.update_layout(**DARK_LAYOUT)
        return fig

    # Map keys to match SEVERITY_COLORS case
    formatted_data = {}
    for k, v in risk_data.items():
        title_key = k.strip().capitalize()
        formatted_data[title_key] = v

    fig = px.pie(
        values=list(formatted_data.values()),
        names=list(formatted_data.keys()),
        hole=0.4,
        color=list(formatted_data.keys()),
        color_discrete_map=SEVERITY_COLORS,
        title="Vulnerability Risk Distribution"
    )
    
    fig.update_layout(**DARK_LAYOUT)
    fig.update_traces(textposition="inside", textinfo="percent+label", hovertemplate="%{label}: %{value} CVEs<extra></extra>")
    return fig

def render_timeline_trend_daily(timeline_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders a daily threat velocity area/line chart.
    """
    if not timeline_data:
        fig = go.Figure()
        fig.add_annotation(text="No timeline trend data available", showarrow=False, font=dict(size=14))
        fig.update_layout(**DARK_LAYOUT)
        return fig
        
    df = pd.DataFrame(timeline_data)
    
    fig = px.area(
        df,
        x="date",
        y="count",
        title="Vulnerability Discovery Trend (Daily velocity)",
        labels={"date": "Date", "count": "CVE Count"},
        color_discrete_sequence=["rgba(139, 92, 246, 0.4)"] # Semi-transparent Purple
    )
    
    fig.update_layout(**DARK_LAYOUT)
    fig.update_traces(
        line=dict(width=3, color="#8b5cf6", shape="spline"),
        hovertemplate="Date: %{x}<br>Count: %{y} CVEs<extra></extra>"
    )
    return fig

def render_mitre_bar_chart(mitre_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders a bar chart for MITRE ATT&CK technique frequencies.
    """
    if not mitre_data:
        fig = go.Figure()
        fig.add_annotation(text="No MITRE statistics available", showarrow=False, font=dict(size=14))
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
        labels={"count": "Trigger Count", "technique": "Technique"},
        color_discrete_sequence=["#22c55e"] # Green accent
    )
    
    fig.update_layout(**DARK_LAYOUT)
    fig.update_traces(hovertemplate="%{y}: %{x} occurrences<extra></extra>")
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
        color_discrete_sequence=["#10b981"] # Emerald Green
    )
    fig.update_layout(**DARK_LAYOUT)
    return fig
