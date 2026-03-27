# Story #15: AI analysis architecture

from unittest.mock import patch, MagicMock

from cybai.models import Risk, RiskAnalysis


SAMPLE_RISK = Risk(
    id="test-001",
    type="network",
    title="Avatud SSH port",
    description="Port 22 on avatud.",
    severity="high",
    location="192.168.1.10:22",
    found_at="2026-03-19T08:00:00Z",
)


# --- estimated_fix_time field ---


def test_risk_analysis_has_estimated_fix_time():
    """RiskAnalysis must include estimated_fix_time field."""
    analysis = RiskAnalysis(
        risk_id="test-001",
        cvss_score=7.5,
        severity="high",
        why_dangerous_et="SSH port on avatud.",
        recommendation_et="Sulge port 22.",
        estimated_fix_time="30 minutit",
        confidence="high",
    )
    assert analysis.estimated_fix_time == "30 minutit"


def test_risk_analysis_estimated_fix_time_in_dict():
    """estimated_fix_time must appear in to_dict() output."""
    analysis = RiskAnalysis(
        risk_id="test-001",
        cvss_score=7.5,
        severity="high",
        why_dangerous_et="SSH port on avatud.",
        recommendation_et="Sulge port 22.",
        estimated_fix_time="30 minutit",
        confidence="high",
    )
    d = analysis.to_dict()
    assert "estimated_fix_time" in d
    assert d["estimated_fix_time"] == "30 minutit"


# --- Analyzer ---


def test_analyzer_is_importable():
    from cybai.analyzer import analyze_risk  # noqa: F401


def test_analyze_risk_returns_risk_analysis():
    """analyze_risk must return a RiskAnalysis object."""
    from cybai.analyzer import analyze_risk

    result = analyze_risk(SAMPLE_RISK)
    assert isinstance(result, RiskAnalysis)


def test_analyze_risk_risk_id_matches():
    """Returned analysis must reference the input risk."""
    from cybai.analyzer import analyze_risk

    result = analyze_risk(SAMPLE_RISK)
    assert result.risk_id == SAMPLE_RISK.id


def test_analyze_risk_has_estonian_text():
    """Analysis text fields must be non-empty."""
    from cybai.analyzer import analyze_risk

    result = analyze_risk(SAMPLE_RISK)
    assert len(result.why_dangerous_et) > 0
    assert len(result.recommendation_et) > 0


def test_analyze_risk_has_estimated_fix_time():
    """Analysis must include estimated fix time."""
    from cybai.analyzer import analyze_risk

    result = analyze_risk(SAMPLE_RISK)
    assert len(result.estimated_fix_time) > 0


def test_analyze_risk_demo_mode(monkeypatch):
    """In demo mode, analyzer returns demo analysis."""
    monkeypatch.setenv("DEMO_MODE", "true")
    from cybai.analyzer import analyze_risk

    result = analyze_risk(SAMPLE_RISK)
    assert result.analysis_mode == "demo"


def test_analyze_risk_fallback_without_api_key(monkeypatch):
    """Without API key, analyzer uses fallback mode."""
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from cybai.analyzer import analyze_risk

    result = analyze_risk(SAMPLE_RISK)
    assert result.analysis_mode == "fallback"


def test_analyze_risk_valid_cvss():
    """CVSS score must be between 0.0 and 10.0."""
    from cybai.analyzer import analyze_risk

    result = analyze_risk(SAMPLE_RISK)
    assert 0.0 <= result.cvss_score <= 10.0


def test_analyze_risk_valid_severity():
    """Severity must be valid."""
    from cybai.analyzer import analyze_risk

    result = analyze_risk(SAMPLE_RISK)
    assert result.severity in {"critical", "high", "medium", "low"}


def test_analyze_risk_valid_confidence():
    """Confidence must be valid."""
    from cybai.analyzer import analyze_risk

    result = analyze_risk(SAMPLE_RISK)
    assert result.confidence in {"high", "medium", "low"}


# --- AI client ---


def test_ai_client_is_importable():
    from cybai.ai_client import call_claude  # noqa: F401


@patch("cybai.ai_client.anthropic")
def test_ai_client_returns_dict_on_success(mock_anthropic):
    """call_claude must return a parsed dict on success."""
    from cybai.ai_client import call_claude

    mock_client = MagicMock()
    mock_anthropic.Anthropic.return_value = mock_client
    mock_client.messages.create.return_value = MagicMock(
        content=[
            MagicMock(
                text='{"cvss_score": 7.5, "severity": "high", '
                '"why_dangerous_et": "Ohtlik", "recommendation_et": "Sulge", '
                '"estimated_fix_time": "30 min", "confidence": "high", '
                '"eits_mapping": [], "sources": []}'
            )
        ]
    )

    result = call_claude(SAMPLE_RISK, "test-api-key")
    assert isinstance(result, dict)
    assert result["cvss_score"] == 7.5


@patch("cybai.ai_client.anthropic")
def test_ai_client_returns_none_on_error(mock_anthropic):
    """call_claude must return None on API error."""
    from cybai.ai_client import call_claude

    mock_anthropic.Anthropic.side_effect = Exception("API down")

    result = call_claude(SAMPLE_RISK, "test-api-key")
    assert result is None


# --- Prompts ---


def test_prompts_is_importable():
    from cybai.prompts import get_prompt  # noqa: F401


def test_prompts_returns_string():
    """get_prompt must return a non-empty string."""
    from cybai.prompts import get_prompt

    prompt = get_prompt(SAMPLE_RISK)
    assert isinstance(prompt, str)
    assert len(prompt) > 0


def test_prompts_differ_by_risk_type():
    """Different risk types should produce different prompts."""
    from cybai.prompts import get_prompt

    network_risk = Risk(
        id="t1",
        type="network",
        title="T",
        description="D",
        severity="high",
        location="L",
        found_at="2026-01-01T00:00:00Z",
    )
    web_risk = Risk(
        id="t2",
        type="web",
        title="T",
        description="D",
        severity="high",
        location="L",
        found_at="2026-01-01T00:00:00Z",
    )

    p1 = get_prompt(network_risk)
    p2 = get_prompt(web_risk)
    assert p1 != p2


def test_prompts_require_json_output():
    """Prompt must instruct the model to return JSON."""
    from cybai.prompts import get_prompt

    prompt = get_prompt(SAMPLE_RISK)
    assert "JSON" in prompt


def test_prompts_require_estonian():
    """Prompt must instruct the model to respond in Estonian."""
    from cybai.prompts import get_prompt

    prompt = get_prompt(SAMPLE_RISK)
    assert "eesti" in prompt.lower()
