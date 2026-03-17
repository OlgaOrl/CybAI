# Story #1: Project setup — base dashboard layout


def test_dashboard_returns_200(client):
    response = client.get("/")
    assert response.status_code == 200


def test_dashboard_contains_title(client):
    response = client.get("/")
    html = response.data.decode()
    assert "CybAI" in html


def test_dashboard_has_base_layout(client):
    response = client.get("/")
    html = response.data.decode()
    assert "<header" in html
    assert "<main" in html
    assert "<footer" in html


def test_dashboard_uses_bootstrap(client):
    response = client.get("/")
    html = response.data.decode()
    assert "bootstrap" in html.lower()
