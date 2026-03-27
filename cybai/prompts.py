from cybai.models import Risk

_SYSTEM_PROMPT = (
    "Sa oled küberturvalisuse ekspert. Analüüsi riski ja vasta ainult JSON formaadis. "
    "Tekst peab olema eesti keeles, praktiline ja lühike."
)

_TYPE_PROMPTS = {
    "network": (
        "Analüüsi võrguriskiga seotud leidu. "
        "Hinda avatud portide, võrguteenuste ja tulemüüri seadistuste mõju."
    ),
    "web": (
        "Analüüsi veebiturbe leidu. "
        "Hinda TLS/SSL, HTTP päiste ja veebirakenduse haavatavuste mõju."
    ),
    "access": (
        "Analüüsi ligipääsuga seotud leidu. "
        "Hinda autentimise, paroolipoliitika ja kasutajaõiguste mõju."
    ),
    "system": (
        "Analüüsi süsteemiga seotud leidu. "
        "Hinda tarkvarauuenduste, konfiguratsioonide ja süsteemiteenuste mõju."
    ),
}

_DEFAULT_TYPE_PROMPT = "Analüüsi turvariski leidu. Hinda selle mõju ja paku lahendus."

_JSON_SCHEMA = """
Vasta ainult JSON objektiga järgmiste väljadega:
{
  "cvss_score": number (0.0-10.0, CVSS v3.1),
  "severity": "critical" | "high" | "medium" | "low",
  "why_dangerous_et": string (max 800 tähemärki, eesti keeles),
  "recommendation_et": string (max 1200 tähemärki, eesti keeles),
  "estimated_fix_time": string (nt "30 minutit", "2 tundi", eesti keeles),
  "confidence": "high" | "medium" | "low",
  "eits_mapping": [string] (E-ITS viited),
  "sources": [string] (allikad)
}
"""


def get_system_prompt() -> str:
    """Return the system prompt for Claude API."""
    return _SYSTEM_PROMPT


def get_prompt(risk: Risk) -> str:
    """Return a risk-type-specific prompt for the given risk."""
    type_context = _TYPE_PROMPTS.get(risk.type, _DEFAULT_TYPE_PROMPT)

    return (
        f"{type_context}\n\n"
        f"Risk:\n"
        f"- Tüüp: {risk.type}\n"
        f"- Pealkiri: {risk.title}\n"
        f"- Kirjeldus: {risk.description}\n"
        f"- Tõsidus: {risk.severity}\n"
        f"- Asukoht: {risk.location}\n\n"
        f"{_JSON_SCHEMA}\n"
        f"Vasta ainult JSON-iga, ilma lisatekstita. Tekst peab olema eesti keeles."
    )
