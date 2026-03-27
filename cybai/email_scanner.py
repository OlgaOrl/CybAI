import re
import uuid
from datetime import datetime, timezone

import dns.resolver

from cybai.demo_data import is_demo_mode
from cybai.logging_utils import get_logger
from cybai.models import Risk

logger = get_logger("email_scanner")

_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)

DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "firebase1",
    "firebase2",
    "mail",
    "s1",
    "s2",
]

DEMO_EMAIL_RISKS = [
    Risk(
        id="email-demo-001",
        type="email",
        title="SPF kirje puudub",
        description=(
            "Domeeni DNS-is puudub SPF kirje. "
            "See võimaldab ründajatel saata võltsitud e-kirju "
            "teie domeeni nimel."
        ),
        severity="high",
        location="example.com",
        found_at="2026-03-19T09:00:00Z",
    ),
    Risk(
        id="email-demo-002",
        type="email",
        title="DKIM kirje puudub",
        description=(
            "DKIM allkirjastamine ei ole seadistatud. "
            "E-kirjade autentsust ei ole võimalik kontrollida."
        ),
        severity="medium",
        location="example.com",
        found_at="2026-03-19T09:05:00Z",
    ),
    Risk(
        id="email-demo-003",
        type="email",
        title="DMARC poliitika on nõrk (p=none)",
        description=(
            "DMARC kirje on olemas, kuid poliitika on p=none. "
            "See ei blokeeri võltsitud e-kirju, "
            "ainult jälgib neid."
        ),
        severity="medium",
        location="example.com",
        found_at="2026-03-19T09:10:00Z",
    ),
]

DEMO_CHECKS = [
    {"protocol": "SPF", "status": "fail", "detail": "Kirje puudub"},
    {"protocol": "DKIM", "status": "fail", "detail": "Kirje puudub"},
    {
        "protocol": "DMARC",
        "status": "fail",
        "detail": "Poliitika p=none",
    },
]


def _risk_id():
    return f"email-{uuid.uuid4().hex[:8]}"


def _now():
    return datetime.now(timezone.utc).isoformat()


def _validate_domain(domain: str) -> None:
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid domain: {domain}")


def scan_email_security(domain: str):
    """Scan email security for a domain. Returns list of Risk objects."""
    _validate_domain(domain)

    if is_demo_mode():
        logger.info("Demo: e-posti turvalisuse kontroll")
        return list(DEMO_EMAIL_RISKS)

    logger.info("E-posti turvalisuse kontroll: %s", domain)
    risks = []
    risks.extend(check_spf(domain))
    risks.extend(check_dkim(domain))
    risks.extend(check_dmarc(domain))
    logger.info("E-posti kontroll lõpetatud, leitud %d riski", len(risks))
    return risks


def get_email_checks(domain: str):
    """Return checklist with SPF/DKIM/DMARC statuses and risks."""
    _validate_domain(domain)

    if is_demo_mode():
        return {
            "checks": list(DEMO_CHECKS),
            "risks": [r.to_dict() for r in DEMO_EMAIL_RISKS],
        }

    checks = []
    risks = []

    spf_risks = check_spf(domain)
    checks.append(
        {
            "protocol": "SPF",
            "status": "fail" if spf_risks else "pass",
            "detail": spf_risks[0].description if spf_risks else "OK",
        }
    )
    risks.extend(spf_risks)

    dkim_risks = check_dkim(domain)
    checks.append(
        {
            "protocol": "DKIM",
            "status": "fail" if dkim_risks else "pass",
            "detail": dkim_risks[0].description if dkim_risks else "OK",
        }
    )
    risks.extend(dkim_risks)

    dmarc_risks = check_dmarc(domain)
    checks.append(
        {
            "protocol": "DMARC",
            "status": "fail" if dmarc_risks else "pass",
            "detail": (dmarc_risks[0].description if dmarc_risks else "OK"),
        }
    )
    risks.extend(dmarc_risks)

    return {
        "checks": checks,
        "risks": [r.to_dict() for r in risks],
    }


def check_spf(domain: str):
    """Check SPF record for a domain."""
    risks = []
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        spf_found = False
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                spf_found = True
                break
        if not spf_found:
            risks.append(
                Risk(
                    id=_risk_id(),
                    type="email",
                    title="SPF kirje puudub",
                    description=(
                        f"Domeeni {domain} DNS-is puudub SPF kirje. "
                        f"See võimaldab e-kirjade võltsimist."
                    ),
                    severity="high",
                    location=domain,
                    found_at=_now(),
                )
            )
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        risks.append(
            Risk(
                id=_risk_id(),
                type="email",
                title="SPF kirje puudub",
                description=(
                    f"Domeeni {domain} SPF kirjet ei leitud. "
                    f"DNS päring ebaõnnestus."
                ),
                severity="high",
                location=domain,
                found_at=_now(),
            )
        )
    except Exception:
        logger.warning("SPF kontrolli viga domeenile %s", domain)

    return risks


def check_dkim(domain: str):
    """Check DKIM record for a domain using common selectors."""
    risks = []
    dkim_found = False

    for selector in DKIM_SELECTORS:
        try:
            qname = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(qname, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if "DKIM1" in txt or "k=rsa" in txt:
                    dkim_found = True
                    break
            if dkim_found:
                break
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
        ):
            continue
        except Exception:
            continue

    if not dkim_found:
        risks.append(
            Risk(
                id=_risk_id(),
                type="email",
                title="DKIM kirje puudub",
                description=(
                    f"Domeeni {domain} DKIM kirjet ei leitud "
                    f"levinud selektorite seas. "
                    f"E-kirjade autentsust ei saa kontrollida."
                ),
                severity="medium",
                location=domain,
                found_at=_now(),
            )
        )

    return risks


def check_dmarc(domain: str):
    """Check DMARC record and policy for a domain."""
    risks = []
    try:
        qname = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(qname, "TXT")
        dmarc_found = False
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                dmarc_found = True
                if "p=none" in txt:
                    risks.append(
                        Risk(
                            id=_risk_id(),
                            type="email",
                            title="DMARC poliitika on nõrk",
                            description=(
                                f"Domeeni {domain} DMARC poliitika "
                                f"on p=none. See ei blokeeri "
                                f"võltsitud e-kirju."
                            ),
                            severity="medium",
                            location=domain,
                            found_at=_now(),
                        )
                    )
                break
        if not dmarc_found:
            risks.append(
                Risk(
                    id=_risk_id(),
                    type="email",
                    title="DMARC kirje puudub",
                    description=(f"Domeeni {domain} DNS-is puudub " f"DMARC kirje."),
                    severity="high",
                    location=domain,
                    found_at=_now(),
                )
            )
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        risks.append(
            Risk(
                id=_risk_id(),
                type="email",
                title="DMARC kirje puudub",
                description=(f"Domeeni {domain} DMARC kirjet ei leitud."),
                severity="high",
                location=domain,
                found_at=_now(),
            )
        )
    except Exception:
        logger.warning("DMARC kontrolli viga domeenile %s", domain)

    return risks
