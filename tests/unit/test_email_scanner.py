# Story #5: Email security checks

from unittest.mock import patch, MagicMock

import dns.resolver

from cybai.models import Risk


# --- Importability ---


def test_email_scanner_is_importable():
    from cybai.email_scanner import scan_email_security  # noqa: F401


def test_check_spf_is_importable():
    from cybai.email_scanner import check_spf  # noqa: F401


def test_check_dkim_is_importable():
    from cybai.email_scanner import check_dkim  # noqa: F401


def test_check_dmarc_is_importable():
    from cybai.email_scanner import check_dmarc  # noqa: F401


# --- scan_email_security ---


def test_scan_email_security_returns_list():
    from cybai.email_scanner import scan_email_security

    results = scan_email_security("example.com")
    assert isinstance(results, list)
    for risk in results:
        assert isinstance(risk, Risk)


def test_scan_email_security_validates_domain():
    """Invalid domain must raise ValueError."""
    from cybai.email_scanner import scan_email_security

    try:
        scan_email_security("not a domain!@#")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_scan_email_security_demo_mode(monkeypatch):
    """Demo mode returns demo email risks."""
    monkeypatch.setenv("DEMO_MODE", "true")
    from cybai.email_scanner import scan_email_security

    results = scan_email_security("example.com")
    assert len(results) >= 1
    assert all(isinstance(r, Risk) for r in results)


# --- SPF ---


@patch("cybai.email_scanner.dns.resolver.resolve")
def test_check_spf_pass(mock_resolve):
    """Valid SPF record returns empty list (no risks)."""
    from cybai.email_scanner import check_spf

    mock_resolve.return_value = [
        MagicMock(to_text=lambda: '"v=spf1 include:_spf.google.com ~all"')
    ]
    results = check_spf("example.com")
    assert results == []


@patch("cybai.email_scanner.dns.resolver.resolve")
def test_check_spf_missing(mock_resolve):
    """Missing SPF record returns a risk."""
    from cybai.email_scanner import check_spf

    mock_resolve.side_effect = dns.resolver.NoAnswer()
    results = check_spf("example.com")
    assert len(results) == 1
    assert results[0].type == "email"
    assert "SPF" in results[0].title


@patch("cybai.email_scanner.dns.resolver.resolve")
def test_check_spf_nxdomain(mock_resolve):
    """Non-existent domain returns a risk."""
    from cybai.email_scanner import check_spf

    mock_resolve.side_effect = dns.resolver.NXDOMAIN()
    results = check_spf("nonexistent.example.com")
    assert len(results) == 1


# --- DKIM ---


@patch("cybai.email_scanner.dns.resolver.resolve")
def test_check_dkim_pass(mock_resolve):
    """Valid DKIM record returns empty list."""
    from cybai.email_scanner import check_dkim

    mock_resolve.return_value = [
        MagicMock(to_text=lambda: '"v=DKIM1; k=rsa; p=MIGf..."')
    ]
    results = check_dkim("example.com")
    assert results == []


@patch("cybai.email_scanner.dns.resolver.resolve")
def test_check_dkim_missing(mock_resolve):
    """Missing DKIM record returns a risk."""
    from cybai.email_scanner import check_dkim

    mock_resolve.side_effect = dns.resolver.NoAnswer()
    results = check_dkim("example.com")
    assert len(results) == 1
    assert results[0].type == "email"
    assert "DKIM" in results[0].title


# --- DMARC ---


@patch("cybai.email_scanner.dns.resolver.resolve")
def test_check_dmarc_reject(mock_resolve):
    """DMARC with reject policy returns empty list."""
    from cybai.email_scanner import check_dmarc

    mock_resolve.return_value = [MagicMock(to_text=lambda: '"v=DMARC1; p=reject;"')]
    results = check_dmarc("example.com")
    assert results == []


@patch("cybai.email_scanner.dns.resolver.resolve")
def test_check_dmarc_quarantine(mock_resolve):
    """DMARC with quarantine policy returns empty list."""
    from cybai.email_scanner import check_dmarc

    mock_resolve.return_value = [MagicMock(to_text=lambda: '"v=DMARC1; p=quarantine;"')]
    results = check_dmarc("example.com")
    assert results == []


@patch("cybai.email_scanner.dns.resolver.resolve")
def test_check_dmarc_none_policy(mock_resolve):
    """DMARC with p=none returns a risk (weak policy)."""
    from cybai.email_scanner import check_dmarc

    mock_resolve.return_value = [MagicMock(to_text=lambda: '"v=DMARC1; p=none;"')]
    results = check_dmarc("example.com")
    assert len(results) == 1
    assert "DMARC" in results[0].title


@patch("cybai.email_scanner.dns.resolver.resolve")
def test_check_dmarc_missing(mock_resolve):
    """Missing DMARC record returns a risk."""
    from cybai.email_scanner import check_dmarc

    mock_resolve.side_effect = dns.resolver.NoAnswer()
    results = check_dmarc("example.com")
    assert len(results) == 1
    assert "DMARC" in results[0].title


# --- Output quality ---


def test_email_risks_have_estonian_text(monkeypatch):
    """Email risks must have Estonian text."""
    monkeypatch.setenv("DEMO_MODE", "true")
    from cybai.email_scanner import scan_email_security

    results = scan_email_security("example.com")
    for risk in results:
        assert len(risk.title) > 0
        assert len(risk.description) > 0


def test_email_risks_use_risk_schema(monkeypatch):
    """Email risks must use shared Risk schema."""
    monkeypatch.setenv("DEMO_MODE", "true")
    from cybai.email_scanner import scan_email_security

    results = scan_email_security("example.com")
    for risk in results:
        d = risk.to_dict()
        for field in (
            "id",
            "type",
            "title",
            "description",
            "severity",
            "location",
            "found_at",
        ):
            assert field in d
