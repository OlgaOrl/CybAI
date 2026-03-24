# Story #4: As a developer I want REST endpoints
# so that the dashboard can interact with the backend

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def demo_mode(monkeypatch):
    """Use demo data in all route tests so scanner never hits the real system."""
    monkeypatch.setenv("DEMO_MODE", "true")


# ---------------------------------------------------------------------------
# GET /api/scan
# ---------------------------------------------------------------------------


def test_get_scan_returns_200(client):
    response = client.get("/api/scan")
    assert response.status_code == 200


def test_get_scan_returns_json_list(client):
    response = client.get("/api/scan")
    data = response.get_json()
    assert isinstance(data, list)
    assert len(data) == 6  # demo data has 6 risks


def test_get_scan_risks_have_required_fields(client):
    response = client.get("/api/scan")
    data = response.get_json()
    required = {
        "id",
        "type",
        "title",
        "description",
        "severity",
        "location",
        "found_at",
    }
    for risk in data:
        assert required.issubset(risk.keys())


def test_get_scan_content_type_is_json(client):
    response = client.get("/api/scan")
    assert "application/json" in response.content_type


# ---------------------------------------------------------------------------
# GET /api/threats
# ---------------------------------------------------------------------------


def test_get_threats_returns_200(client):
    response = client.get("/api/threats")
    assert response.status_code == 200


def test_get_threats_returns_json_list(client):
    response = client.get("/api/threats")
    data = response.get_json()
    assert isinstance(data, list)


def test_get_threats_excludes_resolved_risks(client):
    client.get("/api/scan")  # populate store
    client.post("/api/resolve/demo-001")
    response = client.get("/api/threats")
    ids = [r["id"] for r in response.get_json()]
    assert "demo-001" not in ids


def test_get_threats_includes_unresolved_risks(client):
    client.get("/api/scan")
    response = client.get("/api/threats")
    ids = [r["id"] for r in response.get_json()]
    assert "demo-001" in ids


# ---------------------------------------------------------------------------
# POST /api/resolve/<risk_id>
# ---------------------------------------------------------------------------


def test_resolve_returns_200(client):
    client.get("/api/scan")
    response = client.post("/api/resolve/demo-001")
    assert response.status_code == 200


def test_resolve_returns_json_with_message(client):
    client.get("/api/scan")
    response = client.post("/api/resolve/demo-001")
    data = response.get_json()
    assert data is not None
    assert "teade" in data


def test_resolve_unknown_risk_returns_404(client):
    client.get("/api/scan")
    response = client.post("/api/resolve/nonexistent-999")
    assert response.status_code == 404


def test_resolve_invalid_risk_id_returns_400(client):
    # use URL-safe but regex-invalid ID (< > rejected by Werkzeug before routing)
    response = client.post("/api/resolve/invalid!id")
    assert response.status_code == 400


def test_resolve_same_risk_twice_returns_200(client):
    client.get("/api/scan")
    client.post("/api/resolve/demo-001")
    response = client.post("/api/resolve/demo-001")
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# POST /api/notify/<risk_id>
# ---------------------------------------------------------------------------


def test_notify_returns_200(client):
    client.get("/api/scan")
    response = client.post("/api/notify/demo-001")
    assert response.status_code == 200


def test_notify_returns_json_with_message(client):
    client.get("/api/scan")
    response = client.post("/api/notify/demo-001")
    data = response.get_json()
    assert data is not None
    assert "teade" in data


def test_notify_unknown_risk_returns_404(client):
    client.get("/api/scan")
    response = client.post("/api/notify/nonexistent-999")
    assert response.status_code == 404


def test_notify_invalid_risk_id_returns_400(client):
    # use URL-safe but regex-invalid ID (< > rejected by Werkzeug before routing)
    response = client.post("/api/notify/invalid!id")
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# GET /api/status
# ---------------------------------------------------------------------------


def test_get_status_returns_200(client):
    response = client.get("/api/status")
    assert response.status_code == 200


def test_get_status_has_required_fields(client):
    response = client.get("/api/status")
    data = response.get_json()
    assert "total" in data
    assert "critical" in data
    assert "resolved" in data


def test_get_status_counts_after_scan(client):
    client.get("/api/scan")
    response = client.get("/api/status")
    data = response.get_json()
    assert data["total"] == 6
    assert data["resolved"] == 0
    assert data["critical"] == 2  # demo-002 and demo-005


def test_get_status_counts_after_resolve(client):
    client.get("/api/scan")
    client.post("/api/resolve/demo-001")
    response = client.get("/api/status")
    data = response.get_json()
    assert data["resolved"] == 1


# ---------------------------------------------------------------------------
# Error handling (OWASP A05)
# ---------------------------------------------------------------------------


def test_404_returns_json_not_html(client):
    response = client.get("/api/nonexistent")
    assert response.status_code == 404
    data = response.get_json()
    assert data is not None
    assert "teade" in data


def test_404_contains_no_stack_trace(client):
    response = client.get("/api/nonexistent")
    text = response.get_data(as_text=True)
    assert "Traceback" not in text
    assert "File " not in text


# ---------------------------------------------------------------------------
# CORS (OWASP A05)
# ---------------------------------------------------------------------------


def test_cors_header_present_for_known_origin(client):
    response = client.get(
        "/api/status",
        headers={"Origin": "http://localhost:5000"},
    )
    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" in response.headers


# ---------------------------------------------------------------------------
# Input validation — no shell injection (OWASP A03)
# ---------------------------------------------------------------------------


def test_no_shell_true_in_routes():
    import inspect
    import cybai.routes as routes_module

    source = inspect.getsource(routes_module)
    assert "shell=True" not in source, "shell=True is prohibited (OWASP A03)"
