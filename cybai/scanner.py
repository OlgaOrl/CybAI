import platform
import socket
import subprocess
import uuid
from datetime import datetime, timezone

from cybai.demo_data import DEMO_RISKS, is_demo_mode
from cybai.logging_utils import get_logger
from cybai.models import Risk

logger = get_logger("scanner")

DANGEROUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Proxy",
}

SCAN_TARGET = "127.0.0.1"


def _risk_id():
    return f"scan-{uuid.uuid4().hex[:8]}"


def _now():
    return datetime.now(timezone.utc).isoformat()


def scan_infrastructure():
    """Run all scanner checks and return a list of Risk objects."""
    if is_demo_mode():
        logger.info("Demo režiim aktiivne, tagastan näidisandmed")
        return DEMO_RISKS

    logger.info("Skaneerimine algas")
    risks = []
    risks.extend(check_open_ports())
    risks.extend(check_firewall())
    risks.extend(check_ssl())
    risks.extend(check_failed_logins())
    risks.extend(check_admin_users())
    logger.info("Skaneerimine lõpetatud, leitud %d riski", len(risks))
    return risks


def check_open_ports():
    """Check for open dangerous ports on localhost."""
    risks = []
    for port, service in DANGEROUS_PORTS.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((SCAN_TARGET, port))
            if result == 0:
                severity = "critical" if port in (23, 445, 6379) else "high"
                risks.append(
                    Risk(
                        id=_risk_id(),
                        type="network",
                        title=f"Avatud {service} port {port}",
                        description=(
                            f"Port {port} ({service}) on avatud. "
                            f"See võib võimaldada volitamata ligipääsu."
                        ),
                        severity=severity,
                        location=f"{SCAN_TARGET}:{port}",
                        found_at=_now(),
                    )
                )
                logger.info("Avatud port leitud: %d (%s)", port, service)
    return risks


def check_firewall():
    """Check if the system firewall is enabled."""
    risks = []
    system = platform.system()

    try:
        if system == "Darwin":
            result = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "disabled" in result.stdout.lower():
                risks.append(
                    Risk(
                        id=_risk_id(),
                        type="system",
                        title="Tulemüür on välja lülitatud",
                        description=(
                            "macOS tulemüür on välja lülitatud. "
                            "Soovitatav on tulemüür sisse lülitada."
                        ),
                        severity="high",
                        location="localhost",
                        found_at=_now(),
                    )
                )
        elif system == "Linux":
            result = subprocess.run(
                ["ufw", "status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "inactive" in result.stdout.lower():
                risks.append(
                    Risk(
                        id=_risk_id(),
                        type="system",
                        title="Tulemüür on välja lülitatud",
                        description=(
                            "UFW tulemüür on mitteaktiivne. "
                            "Soovitatav on tulemüür sisse lülitada."
                        ),
                        severity="high",
                        location="localhost",
                        found_at=_now(),
                    )
                )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.warning("Tulemüüri kontrolli ei õnnestunud läbi viia")

    return risks


def check_ssl():
    """Check SSL certificate expiry on localhost:443."""
    risks = []
    try:
        import ssl

        context = ssl.create_default_context()
        with socket.create_connection(("localhost", 443), timeout=3) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname="localhost") as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                if not_after < datetime.now():
                    risks.append(
                        Risk(
                            id=_risk_id(),
                            type="web",
                            title="SSL-sertifikaat on aegunud",
                            description=(
                                f"SSL-sertifikaat aegus {not_after.isoformat()}. "
                                f"Uuendage sertifikaati viivitamatult."
                            ),
                            severity="critical",
                            location="localhost:443",
                            found_at=_now(),
                        )
                    )
                elif (not_after - datetime.now()).days < 30:
                    risks.append(
                        Risk(
                            id=_risk_id(),
                            type="web",
                            title="SSL-sertifikaat aegub varsti",
                            description=(
                                f"SSL-sertifikaat aegub {not_after.isoformat()}. "
                                f"Uuendage sertifikaati esimesel võimalusel."
                            ),
                            severity="medium",
                            location="localhost:443",
                            found_at=_now(),
                        )
                    )
    except (ConnectionRefusedError, OSError, socket.timeout):
        pass

    return risks


def check_failed_logins():
    """Check for failed login attempts in system logs."""
    risks = []
    system = platform.system()

    try:
        if system == "Darwin":
            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--predicate",
                    'eventMessage contains "failed"',
                    "--style",
                    "compact",
                    "--last",
                    "1h",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            failed_count = result.stdout.lower().count("failed")
        elif system == "Linux":
            result = subprocess.run(
                ["journalctl", "--since", "1 hour ago", "--no-pager", "-q"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            failed_count = result.stdout.lower().count("failed password")
        else:
            failed_count = 0

        if failed_count > 10:
            risks.append(
                Risk(
                    id=_risk_id(),
                    type="access",
                    title="Palju ebaõnnestunud sisselogimisi",
                    description=(
                        f"Viimase tunni jooksul tuvastati {failed_count} "
                        f"ebaõnnestunud sisselogimiskatset. "
                        f"Võimalik jõuründe katse."
                    ),
                    severity="high",
                    location="localhost",
                    found_at=_now(),
                )
            )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.warning("Sisselogimiste kontrolli ei õnnestunud läbi viia")

    return risks


def check_admin_users():
    """Check for users with admin/root privileges."""
    risks = []
    system = platform.system()

    try:
        if system in ("Darwin", "Linux"):
            result = subprocess.run(
                (
                    ["dscl", ".", "-read", "/Groups/admin", "GroupMembership"]
                    if system == "Darwin"
                    else ["getent", "group", "sudo"]
                ),
                capture_output=True,
                text=True,
                timeout=5,
            )
            if system == "Darwin":
                members = result.stdout.split(":")[-1].strip().split()
            else:
                members = result.stdout.strip().split(":")[-1].split(",")

            members = [m for m in members if m]

            if len(members) > 2:
                risks.append(
                    Risk(
                        id=_risk_id(),
                        type="access",
                        title="Liiga palju administraatoreid",
                        description=(
                            f"Süsteemis on {len(members)} administraatorikontot: "
                            f"{', '.join(members)}. "
                            f"Soovitatav on piirata administraatorite arvu."
                        ),
                        severity="medium",
                        location="localhost",
                        found_at=_now(),
                    )
                )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.warning("Administraatorite kontrolli ei õnnestunud läbi viia")

    return risks
