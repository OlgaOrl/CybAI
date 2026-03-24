# Story #6: Infrastructure scanner


def test_dashboard_has_scan_button(client):
    """Dashboard must have a 'Skanni kohe' button."""
    response = client.get("/")
    html = response.data.decode()
    assert "Skanni" in html


def test_scan_endpoint_returns_200(client):
    """POST /scan must return 200."""
    response = client.post("/scan")
    assert response.status_code == 200


def test_scan_endpoint_returns_risks(client):
    """POST /scan must return a list of risks."""
    response = client.post("/scan")
    data = response.get_json()
    assert isinstance(data, list)
    for risk in data:
        assert "id" in risk
        assert "severity" in risk
        assert "title" in risk


def test_scan_demo_mode_returns_6_risks(client, monkeypatch):
    """In demo mode, scan returns exactly 6 risks."""
    monkeypatch.setenv("DEMO_MODE", "true")
    response = client.post("/scan")
    data = response.get_json()
    assert len(data) == 6


def test_scan_results_have_severity_badges(client, monkeypatch):
    """Scan results must include severity field for badge display."""
    monkeypatch.setenv("DEMO_MODE", "true")
    response = client.post("/scan")
    data = response.get_json()
    valid_severities = {"critical", "high", "medium", "low"}
    for risk in data:
        assert risk["severity"] in valid_severities


def test_dashboard_has_stats_cards(client):
    """Dashboard must show statistics cards."""
    response = client.get("/")
    html = response.data.decode()
    assert "Kriitilised riskid" in html
    assert "Viimane skaneerimine" in html


def test_dashboard_has_severity_filters(client):
    """Dashboard must have filter buttons for severity levels."""
    response = client.get("/")
    html = response.data.decode()
    for label in ("Kriitilised", "Keskmised", "Madalad"):
        assert label in html


def test_dashboard_has_risk_distribution(client):
    """Dashboard must have a risk distribution section."""
    response = client.get("/")
    html = response.data.decode()
    assert "Riskide jaotus" in html


def test_dashboard_has_loading_indicator(client):
    """Dashboard must have a loading indicator element."""
    response = client.get("/")
    html = response.data.decode()
    assert "spinner" in html.lower() or "laadimine" in html.lower()
