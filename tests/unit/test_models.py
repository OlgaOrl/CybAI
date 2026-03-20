# Story #8: As a developer I want shared conventions defined
# so that all modules use consistent formats

import pytest


def test_risk_is_importable():
    from cybai.models import Risk  # noqa: F401


def test_risk_has_required_fields():
    from cybai.models import Risk

    risk = Risk(
        id="1",
        type="network",
        title="Avatud port",
        description="Port 22 on avalikult ligipääsetav",
        severity="high",
        location="192.168.1.1",
        found_at="2026-03-19T10:00:00Z",
    )
    assert risk.id == "1"
    assert risk.type == "network"
    assert risk.title == "Avatud port"
    assert risk.description == "Port 22 on avalikult ligipääsetav"
    assert risk.severity == "high"
    assert risk.location == "192.168.1.1"
    assert risk.found_at == "2026-03-19T10:00:00Z"


def test_severity_levels_are_defined():
    from cybai.models import SEVERITY_LEVELS

    assert set(SEVERITY_LEVELS) == {"critical", "high", "medium", "low"}


def test_valid_severity_values():
    from cybai.models import Risk

    for severity in ("critical", "high", "medium", "low"):
        risk = Risk(
            id="1",
            type="test",
            title="Test",
            description="Kirjeldus",
            severity=severity,
            location="localhost",
            found_at="2026-03-19T10:00:00Z",
        )
        assert risk.severity == severity


def test_invalid_severity_raises_error():
    from cybai.models import Risk

    with pytest.raises((ValueError, Exception)):
        Risk(
            id="1",
            type="test",
            title="Test",
            description="Kirjeldus",
            severity="kriitilise",
            location="localhost",
            found_at="2026-03-19T10:00:00Z",
        )


def test_risk_can_be_serialized_to_dict():
    from cybai.models import Risk

    risk = Risk(
        id="42",
        type="web",
        title="SQL süstimine",
        description="Sisend ei ole valideeritud",
        severity="critical",
        location="https://example.com/login",
        found_at="2026-03-19T10:00:00Z",
    )
    data = risk.to_dict()
    assert data["id"] == "42"
    assert data["severity"] == "critical"
    assert "found_at" in data
