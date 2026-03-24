# Story #4: As a developer I want REST endpoints
# so that the dashboard can interact with the backend

import pytest


@pytest.fixture(autouse=True)
def demo_mode(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")


# ---------------------------------------------------------------------------
# Full API flow: scan → threats → resolve → status
# ---------------------------------------------------------------------------


def test_full_flow_scan_resolve_status(client):
    """Scan, resolve a risk, verify it disappears from threats and status updates."""
    # Step 1: scan returns risks
    scan_resp = client.get("/api/scan")
    assert scan_resp.status_code == 200
    risks = scan_resp.get_json()
    assert len(risks) > 0

    # Step 2: threats initially matches scan
    threats_resp = client.get("/api/threats")
    assert threats_resp.status_code == 200
    threats = threats_resp.get_json()
    assert len(threats) == len(risks)

    # Step 3: resolve one risk
    first_id = risks[0]["id"]
    resolve_resp = client.post(f"/api/resolve/{first_id}")
    assert resolve_resp.status_code == 200

    # Step 4: resolved risk no longer in threats
    threats_after = client.get("/api/threats").get_json()
    ids_after = [r["id"] for r in threats_after]
    assert first_id not in ids_after

    # Step 5: status reflects the resolution
    status = client.get("/api/status").get_json()
    assert status["total"] == len(risks)
    assert status["resolved"] == 1


def test_notify_flow(client):
    """Scan and then request notification for a specific risk."""
    client.get("/api/scan")
    response = client.post("/api/notify/demo-002")
    assert response.status_code == 200
    data = response.get_json()
    assert "teade" in data


def test_dashboard_page_loads(client):
    """Dashboard must render successfully (no page reload needed for data)."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    # Dashboard must contain the scan trigger
    assert "Skanni" in html or "skanni" in html


def test_dashboard_has_statistics_bar(client):
    """Statistics bar elements must be present in dashboard HTML."""
    response = client.get("/")
    html = response.get_data(as_text=True)
    assert "stat-critical" in html
    assert "stat-resolved" in html


def test_dashboard_has_resolve_button_in_js(client):
    """Dashboard JS must include resolve action."""
    response = client.get("/")
    html = response.get_data(as_text=True)
    assert "/api/resolve/" in html


def test_dashboard_uses_api_scan_endpoint(client):
    """Dashboard must fetch from /api/scan, not the old /scan endpoint."""
    response = client.get("/")
    html = response.get_data(as_text=True)
    assert "/api/scan" in html


def test_all_endpoints_return_json_errors(client):
    """All API error responses must be JSON (OWASP A05)."""
    endpoints = [
        ("GET", "/api/nonexistent"),
        ("POST", "/api/resolve/bad<>id"),
        ("POST", "/api/notify/bad<>id"),
    ]
    for method, path in endpoints:
        if method == "GET":
            response = client.get(path)
        else:
            response = client.post(path)
        assert (
            response.content_type == "application/json"
        ), f"{method} {path} returned non-JSON error: {response.content_type}"
        data = response.get_json()
        assert data is not None
        assert "teade" in data
