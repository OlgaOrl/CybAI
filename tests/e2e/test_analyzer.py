# Story #15: AI analysis architecture


def test_analyze_endpoint_returns_200(client, monkeypatch):
    """POST /api/analyze must return 200."""
    monkeypatch.setenv("DEMO_MODE", "true")
    # First scan to populate risks
    client.get("/api/scan")
    response = client.post("/api/analyze")
    assert response.status_code == 200


def test_analyze_endpoint_returns_list(client, monkeypatch):
    """POST /api/analyze must return a list of analyses."""
    monkeypatch.setenv("DEMO_MODE", "true")
    client.get("/api/scan")
    response = client.post("/api/analyze")
    data = response.get_json()
    assert isinstance(data, list)
    assert len(data) > 0


def test_analyze_results_have_required_fields(client, monkeypatch):
    """Each analysis must have all required fields."""
    monkeypatch.setenv("DEMO_MODE", "true")
    client.get("/api/scan")
    response = client.post("/api/analyze")
    data = response.get_json()

    required = {
        "risk_id",
        "cvss_score",
        "severity",
        "why_dangerous_et",
        "recommendation_et",
        "estimated_fix_time",
        "confidence",
        "analysis_mode",
    }
    for item in data:
        assert required.issubset(set(item.keys()))


def test_analyze_demo_mode_returns_demo_analyses(client, monkeypatch):
    """In demo mode, all analyses must have analysis_mode=demo."""
    monkeypatch.setenv("DEMO_MODE", "true")
    client.get("/api/scan")
    response = client.post("/api/analyze")
    data = response.get_json()
    for item in data:
        assert item["analysis_mode"] == "demo"


def test_analyze_without_scan_returns_empty(client, monkeypatch):
    """POST /api/analyze without prior scan returns empty list."""
    monkeypatch.setenv("DEMO_MODE", "true")
    response = client.post("/api/analyze")
    data = response.get_json()
    assert data == []


def test_analyze_results_have_estonian_text(client, monkeypatch):
    """Analysis text must be non-empty Estonian content."""
    monkeypatch.setenv("DEMO_MODE", "true")
    client.get("/api/scan")
    response = client.post("/api/analyze")
    data = response.get_json()
    for item in data:
        assert len(item["why_dangerous_et"]) > 0
        assert len(item["recommendation_et"]) > 0
