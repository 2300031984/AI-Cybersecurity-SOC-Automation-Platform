import pytest
from dashboard.components.ui import (
    get_severity_badge_html,
    get_kev_badge_html,
    get_live_backend_health
)
from dashboard.components.charts import (
    render_severity_pie_chart,
    render_risk_score_histogram,
    render_epss_histogram,
    render_kev_bar_chart,
    render_timeline_trend
)

def test_severity_badges():
    critical_badge = get_severity_badge_html("CRITICAL")
    assert "badge-critical" in critical_badge
    assert "CRITICAL" in critical_badge

    high_badge = get_severity_badge_html("high")
    assert "badge-high" in high_badge
    assert "HIGH" in high_badge

    medium_badge = get_severity_badge_html("MEDIUM")
    assert "badge-medium" in medium_badge

    low_badge = get_severity_badge_html("low")
    assert "badge-low" in low_badge

    unknown_badge = get_severity_badge_html(None)
    assert "badge-info" in unknown_badge

def test_kev_badge():
    active_kev = get_kev_badge_html(True)
    assert "CISA KEV" in active_kev
    assert "badge-kev" in active_kev

    inactive_kev = get_kev_badge_html(False)
    assert "No Active Exploit" in inactive_kev

def test_charts_empty_handling():
    pie_fig = render_severity_pie_chart([])
    assert pie_fig is not None

    cvss_fig = render_risk_score_histogram([])
    assert cvss_fig is not None

    epss_fig = render_epss_histogram([])
    assert epss_fig is not None

    kev_fig = render_kev_bar_chart([])
    assert kev_fig is not None

    trend_fig = render_timeline_trend([])
    assert trend_fig is not None

def test_charts_with_sample_data():
    pie_fig = render_severity_pie_chart([
        {"severity": "CRITICAL", "count": 5},
        {"severity": "HIGH", "count": 12}
    ])
    assert pie_fig is not None
    assert len(pie_fig.data) > 0

    cvss_fig = render_risk_score_histogram([
        {"bucket": "9-10", "count": 4},
        {"bucket": "7-8", "count": 9}
    ])
    assert cvss_fig is not None

    epss_fig = render_epss_histogram([
        {"bucket": "0.9-1.0", "count": 3}
    ])
    assert epss_fig is not None

    kev_fig = render_kev_bar_chart([
        {"vendor_name": "Microsoft", "count": 4}
    ])
    assert kev_fig is not None

    trend_fig = render_timeline_trend([
        {"date": "2026-01", "count": 10}
    ])
    assert trend_fig is not None
