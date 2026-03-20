import os

from cybai.models import Risk


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
