import os

from cybai.ai_client import call_claude
from cybai.demo_data import DEMO_ANALYSES, is_demo_mode
from cybai.logging_utils import get_logger
from cybai.models import Risk, RiskAnalysis

logger = get_logger("analyzer")

_FALLBACK_DATA = {
    "network": {
        "cvss_score": 7.5,
        "severity": "high",
        "why_dangerous_et": (
            "Avatud võrguport võimaldab volitamata ligipääsu. "
            "Ründajad saavad kasutada avatud porte süsteemi kompromiteerimiseks."
        ),
        "recommendation_et": (
            "Sulge mittevajalikud pordid tulemüüriga. "
            "Piira ligipääsu ainult usaldusväärsetele IP-aadressidele."
        ),
        "estimated_fix_time": "30 minutit",
        "confidence": "medium",
        "eits_mapping": ["E-ITS 6.1", "E-ITS 6.2"],
    },
    "web": {
        "cvss_score": 8.0,
        "severity": "high",
        "why_dangerous_et": (
            "Veebiturbe probleem võib võimaldada andmeleket "
            "või sessiooni kaaperdamist. Aegunud protokollid "
            "ja puuduvad päised suurendavad rünnakupinda."
        ),
        "recommendation_et": (
            "Uuenda TLS versioon vähemalt 1.2-le. "
            "Lisa puuduvad turvapäised (CSP, HSTS, X-Frame-Options)."
        ),
        "estimated_fix_time": "1 tund",
        "confidence": "medium",
        "eits_mapping": ["E-ITS 7.1", "E-ITS 7.3"],
    },
    "access": {
        "cvss_score": 6.5,
        "severity": "medium",
        "why_dangerous_et": (
            "Nõrk ligipääsukontroll võimaldab volitamata juurdepääsu. "
            "Lühikesed paroolid ja liiga palju administraatoreid suurendavad riski."
        ),
        "recommendation_et": (
            "Kehtesta minimaalselt 12 tähemärgi pikkused paroolid. "
            "Piira administraatorikontode arvu ja luba MFA."
        ),
        "estimated_fix_time": "2 tundi",
        "confidence": "medium",
        "eits_mapping": ["E-ITS 5.1", "E-ITS 5.3"],
    },
    "system": {
        "cvss_score": 5.5,
        "severity": "medium",
        "why_dangerous_et": (
            "Süsteemi haavatavused tekivad uuendamata tarkvarast ja "
            "ebaturvalistest konfiguratsioonidest."
        ),
        "recommendation_et": (
            "Paigalda kõik turvapaigad. "
            "Kontrolli süsteemi konfiguratsioonid turvastandardite vastu."
        ),
        "estimated_fix_time": "1 tund",
        "confidence": "medium",
        "eits_mapping": ["E-ITS 4.1", "E-ITS 4.2"],
    },
}

_DEFAULT_FALLBACK = {
    "cvss_score": 5.0,
    "severity": "medium",
    "why_dangerous_et": "Tuvastatud turvariski tuleb lähemalt uurida.",
    "recommendation_et": "Konsulteeri turvaspetsialistiga riski hindamiseks.",
    "estimated_fix_time": "1 tund",
    "confidence": "low",
    "eits_mapping": [],
}


def _build_analysis(risk: Risk, data: dict, mode: str) -> RiskAnalysis:
    """Build a RiskAnalysis from a dict, with validation fallback."""
    return RiskAnalysis(
        risk_id=risk.id,
        cvss_score=max(0.0, min(10.0, float(data.get("cvss_score", 5.0)))),
        severity=data.get("severity", "medium"),
        why_dangerous_et=data.get("why_dangerous_et", "")[:800],
        recommendation_et=data.get("recommendation_et", "")[:1200],
        estimated_fix_time=data.get("estimated_fix_time", ""),
        confidence=data.get("confidence", "low"),
        eits_mapping=data.get("eits_mapping", []),
        sources=data.get("sources", []),
        analysis_mode=mode,
    )


def _get_fallback(risk: Risk) -> dict:
    """Return fallback analysis data for a risk type."""
    return _FALLBACK_DATA.get(risk.type, _DEFAULT_FALLBACK)


def analyze_risk(risk: Risk) -> RiskAnalysis:
    """Analyze a single risk: demo → ai → fallback."""
    if is_demo_mode():
        logger.info("Demo analüüs riskile: %s", risk.id)
        demo_map = {a.risk_id: a for a in DEMO_ANALYSES}
        if risk.id in demo_map:
            return demo_map[risk.id]
        return _build_analysis(risk, _get_fallback(risk), "demo")

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if api_key:
        logger.info("AI analüüs riskile: %s", risk.id)
        result = call_claude(risk, api_key)
        if result is not None:
            try:
                return _build_analysis(risk, result, "ai")
            except (ValueError, TypeError):
                logger.warning("AI vastus ei vasta skeemile, kasutan fallbacki")

    logger.info("Fallback analüüs riskile: %s", risk.id)
    return _build_analysis(risk, _get_fallback(risk), "fallback")
