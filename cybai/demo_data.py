import os

from cybai.models import Risk, RiskAnalysis


def is_demo_mode() -> bool:
    return os.environ.get("DEMO_MODE", "false").lower() == "true"


DEMO_RISKS = [
    Risk(
        id="demo-001",
        type="network",
        title="Avatud SSH port",
        description=(
            "Port 22 on avalikult internetist ligipääsetav. "
            "Soovitatav piirata ligipääsu IP-aadresside järgi."
        ),
        severity="high",
        location="192.168.1.10:22",
        found_at="2026-03-19T08:00:00Z",
    ),
    Risk(
        id="demo-002",
        type="web",
        title="Aegunud TLS versioon",
        description=(
            "Veebiserver toetab TLS 1.0 krüpteeringut, "
            "mis on turvalisuse seisukohalt aegunud ja ohtlik."
        ),
        severity="critical",
        location="https://example.ee",
        found_at="2026-03-19T08:05:00Z",
    ),
    Risk(
        id="demo-003",
        type="system",
        title="Tarkvarauuendused puuduvad",
        description=(
            "Operatsioonisüsteemil on 14 rakendamata turvapaika. "
            "Uuenduste paigaldamine on vajalik."
        ),
        severity="medium",
        location="server-01.example.ee",
        found_at="2026-03-19T08:10:00Z",
    ),
    Risk(
        id="demo-004",
        type="access",
        title="Nõrk paroolipoliitika",
        description=(
            "Kasutajakontod võimaldavad lühikesi paroole. "
            "Minimaalne paroolipikkus peaks olema 12 tähemärki."
        ),
        severity="medium",
        location="Active Directory",
        found_at="2026-03-19T08:15:00Z",
    ),
    Risk(
        id="demo-005",
        type="network",
        title="Avatud andmebaasi port",
        description=(
            "PostgreSQL andmebaasi port 5432 on ligipääsetav välisvõrgust. "
            "Andmete lekkimise risk on kõrge."
        ),
        severity="critical",
        location="192.168.1.20:5432",
        found_at="2026-03-19T08:20:00Z",
    ),
    Risk(
        id="demo-006",
        type="web",
        title="Puuduv turvaline päis",
        description=(
            "Veebirakendus ei saada HTTP turvaline päis Content-Security-Policy, "
            "mis suurendab XSS-rünnakute riski."
        ),
        severity="low",
        location="https://example.ee/app",
        found_at="2026-03-19T08:25:00Z",
    ),
]

DEMO_ANALYSES = [
    RiskAnalysis(
        risk_id="demo-001",
        cvss_score=7.5,
        severity="high",
        why_dangerous_et=(
            "Avatud SSH port võimaldab ründajatel teostada "
            "jõuründeid ja saada volitamata ligipääsu serverile."
        ),
        recommendation_et=(
            "Piira SSH ligipääsu tulemüüriga ainult "
            "usaldusväärsetele IP-aadressidele. Keela parooliga "
            "autentimine ja kasuta SSH võtmeid."
        ),
        estimated_fix_time="30 minutit",
        confidence="high",
        eits_mapping=["E-ITS 6.1", "E-ITS 6.2"],
        sources=["NIST SP 800-123", "CIS Benchmark"],
        analysis_mode="demo",
    ),
    RiskAnalysis(
        risk_id="demo-002",
        cvss_score=9.1,
        severity="critical",
        why_dangerous_et=(
            "TLS 1.0 sisaldab teadaolevaid haavatavusi "
            "(BEAST, POODLE). Krüpteeritud liiklust on "
            "võimalik dekrüpteerida."
        ),
        recommendation_et=(
            "Keela TLS 1.0 ja 1.1. Luba ainult TLS 1.2+ "
            "tugevate šifritega. Uuenda serveri konfiguratsioon."
        ),
        estimated_fix_time="1 tund",
        confidence="high",
        eits_mapping=["E-ITS 7.1", "E-ITS 7.3"],
        sources=["OWASP TLS Guide", "Mozilla SSL Config"],
        analysis_mode="demo",
    ),
    RiskAnalysis(
        risk_id="demo-003",
        cvss_score=6.5,
        severity="medium",
        why_dangerous_et=(
            "Rakendamata turvapaigad jätavad süsteemi "
            "haavatavaks teadaolevatele rünnakutele."
        ),
        recommendation_et=(
            "Paigalda kõik turvapaigad viivitamatult. "
            "Seadista automaatne uuenduste kontroll."
        ),
        estimated_fix_time="2 tundi",
        confidence="high",
        eits_mapping=["E-ITS 4.1", "E-ITS 4.2"],
        sources=["CVE Database"],
        analysis_mode="demo",
    ),
    RiskAnalysis(
        risk_id="demo-004",
        cvss_score=5.5,
        severity="medium",
        why_dangerous_et=(
            "Lühikesed paroolid on haavatavad jõuründetele. "
            "Ründaja saab nõrga parooli murda minutitega."
        ),
        recommendation_et=(
            "Kehtesta minimaalselt 12 tähemärgi pikkused "
            "paroolid. Luba mitmefaktoriline autentimine (MFA)."
        ),
        estimated_fix_time="1 tund",
        confidence="medium",
        eits_mapping=["E-ITS 5.1", "E-ITS 5.3"],
        sources=["NIST SP 800-63B"],
        analysis_mode="demo",
    ),
    RiskAnalysis(
        risk_id="demo-005",
        cvss_score=9.5,
        severity="critical",
        why_dangerous_et=(
            "Avalikult ligipääsetav andmebaasiport võimaldab "
            "volitamata juurdepääsu tundlikele andmetele."
        ),
        recommendation_et=(
            "Sulge port 5432 välisvõrgule tulemüüriga. "
            "Luba ühendused ainult rakendusserverist."
        ),
        estimated_fix_time="30 minutit",
        confidence="high",
        eits_mapping=["E-ITS 6.1", "E-ITS 8.1"],
        sources=["CIS PostgreSQL Benchmark"],
        analysis_mode="demo",
    ),
    RiskAnalysis(
        risk_id="demo-006",
        cvss_score=4.0,
        severity="low",
        why_dangerous_et=(
            "Puuduv CSP päis suurendab XSS-rünnakute riski. "
            "Ründaja saab süstida pahatahtlikku koodi."
        ),
        recommendation_et=(
            "Lisa Content-Security-Policy päis veebiserveri "
            "konfiguratsiooni. Keela inline skriptid."
        ),
        estimated_fix_time="45 minutit",
        confidence="medium",
        eits_mapping=["E-ITS 7.1"],
        sources=["OWASP Secure Headers"],
        analysis_mode="demo",
    ),
]
