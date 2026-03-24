# Story #6: Infrastructure scanner

from unittest.mock import patch, MagicMock

from cybai.models import Risk, SEVERITY_LEVELS


def test_scanner_is_importable():
    from cybai.scanner import scan_infrastructure  # noqa: F401


def test_scan_returns_list_of_risks():
    from cybai.scanner import scan_infrastructure

    results = scan_infrastructure()
    assert isinstance(results, list)
    for risk in results:
        assert isinstance(risk, Risk)


def test_scan_risks_have_valid_severity():
    from cybai.scanner import scan_infrastructure

    results = scan_infrastructure()
    for risk in results:
        assert risk.severity in SEVERITY_LEVELS


def test_scan_risks_have_estonian_text():
    from cybai.scanner import scan_infrastructure

    results = scan_infrastructure()
    for risk in results:
        assert len(risk.title) > 0
        assert len(risk.description) > 0


def test_scan_risks_use_risk_schema():
    from cybai.scanner import scan_infrastructure

    results = scan_infrastructure()
    for risk in results:
        d = risk.to_dict()
        assert "id" in d
        assert "type" in d
        assert "title" in d
        assert "description" in d
        assert "severity" in d
        assert "location" in d
        assert "found_at" in d


# --- Port scanning ---


def test_check_open_ports_is_importable():
    from cybai.scanner import check_open_ports  # noqa: F401


def test_check_open_ports_returns_risks():
    from cybai.scanner import check_open_ports

    results = check_open_ports()
    assert isinstance(results, list)
    for risk in results:
        assert isinstance(risk, Risk)
        assert risk.type == "network"


@patch("cybai.scanner.socket.socket")
def test_check_open_ports_detects_open_port(mock_socket_cls):
    from cybai.scanner import check_open_ports

    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 0
    mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
    mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)

    results = check_open_ports()
    assert len(results) > 0
    assert any(
        "port" in r.title.lower() or "port" in r.description.lower() for r in results
    )


@patch("cybai.scanner.socket.socket")
def test_check_open_ports_no_results_when_closed(mock_socket_cls):
    from cybai.scanner import check_open_ports

    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 1
    mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
    mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)

    results = check_open_ports()
    assert len(results) == 0


def test_dangerous_ports_are_checked():
    from cybai.scanner import DANGEROUS_PORTS

    expected = {21, 23, 3306, 5432, 6379, 8080, 445}
    assert expected.issubset(set(DANGEROUS_PORTS.keys()))


# --- Firewall ---


def test_check_firewall_returns_risks():
    from cybai.scanner import check_firewall

    results = check_firewall()
    assert isinstance(results, list)
    for risk in results:
        assert isinstance(risk, Risk)


# --- SSL ---


def test_check_ssl_returns_risks():
    from cybai.scanner import check_ssl

    results = check_ssl()
    assert isinstance(results, list)
    for risk in results:
        assert isinstance(risk, Risk)


# --- Failed logins ---


def test_check_failed_logins_returns_risks():
    from cybai.scanner import check_failed_logins

    results = check_failed_logins()
    assert isinstance(results, list)
    for risk in results:
        assert isinstance(risk, Risk)


# --- Admin users ---


def test_check_admin_users_returns_risks():
    from cybai.scanner import check_admin_users

    results = check_admin_users()
    assert isinstance(results, list)
    for risk in results:
        assert isinstance(risk, Risk)


# --- Demo mode ---


def test_scan_returns_demo_data_in_demo_mode(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    from cybai.scanner import scan_infrastructure

    results = scan_infrastructure()
    assert len(results) == 6


def test_scan_returns_real_data_when_not_demo(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")
    from cybai.scanner import scan_infrastructure

    results = scan_infrastructure()
    assert isinstance(results, list)


# --- Security: no shell=True ---


def test_no_shell_true_in_scanner():
    import inspect
    import cybai.scanner as scanner_module

    source = inspect.getsource(scanner_module)
    assert "shell=True" not in source, "shell=True is prohibited (OWASP A03)"
