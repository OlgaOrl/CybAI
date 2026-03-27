# Story #5: Email security checks


def test_dashboard_has_email_security_section(client):
    """Dashboard must have 'E-posti turvalisus' section."""
    response = client.get("/")
    html = response.data.decode()
    assert "E-posti turvalisus" in html


def test_email_scan_endpoint_returns_200(client, monkeypatch):
    """POST /api/email-scan must return 200."""
    monkeypatch.setenv("DEMO_MODE", "true")
    response = client.post(
        "/api/email-scan",
        json={"domain": "example.com"},
    )
    assert response.status_code == 200


def test_email_scan_returns_checklist(client, monkeypatch):
    """Email scan must return SPF, DKIM, DMARC statuses."""
    monkeypatch.setenv("DEMO_MODE", "true")
    response = client.post(
        "/api/email-scan",
        json={"domain": "example.com"},
    )
    data = response.get_json()
    assert "checks" in data
    protocols = {c["protocol"] for c in data["checks"]}
    assert {"SPF", "DKIM", "DMARC"}.issubset(protocols)


def test_email_scan_returns_risks(client, monkeypatch):
    """Failed checks must return risks."""
    monkeypatch.setenv("DEMO_MODE", "true")
    response = client.post(
        "/api/email-scan",
        json={"domain": "example.com"},
    )
    data = response.get_json()
    assert "risks" in data
    assert isinstance(data["risks"], list)


def test_email_scan_invalid_domain_returns_400(client):
    """Invalid domain must return 400."""
    response = client.post(
        "/api/email-scan",
        json={"domain": "not valid!@#"},
    )
    assert response.status_code == 400


def test_email_scan_missing_domain_returns_400(client):
    """Missing domain must return 400."""
    response = client.post(
        "/api/email-scan",
        json={},
    )
    assert response.status_code == 400
