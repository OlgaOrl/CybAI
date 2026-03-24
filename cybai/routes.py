import re

from flask import Blueprint, current_app, jsonify, render_template

from cybai.logging_utils import get_logger
from cybai.scanner import scan_infrastructure

logger = get_logger(__name__)

bp = Blueprint("main", __name__)

# Risk ID must be alphanumeric with dashes/underscores, max 50 chars (OWASP A03)
_RISK_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,50}$")


# ---------------------------------------------------------------------------
# State helpers — stored per app instance so tests are isolated
# ---------------------------------------------------------------------------


def _state():
    """Return the mutable risk state dict for the current app instance."""
    if "risks_state" not in current_app.extensions:
        current_app.extensions["risks_state"] = {
            "scan_results": [],
            "resolved_ids": set(),
        }
    return current_app.extensions["risks_state"]


def _validate_id(risk_id: str) -> bool:
    return bool(_RISK_ID_RE.match(risk_id))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@bp.route("/")
def dashboard():
    return render_template("dashboard.html")


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@bp.route("/api/scan")
def api_scan():
    """Trigger infrastructure scan and return results."""
    logger.info("Skaneerimine algas (API)")
    risks = scan_infrastructure()
    state = _state()
    state["scan_results"] = risks
    # Keep resolved_ids that still exist in the new scan
    existing_ids = {r.id for r in risks}
    state["resolved_ids"] &= existing_ids
    logger.info("Skaneerimine lõpetatud, leitud %d riski", len(risks))
    return jsonify([r.to_dict() for r in risks])


@bp.route("/api/threats")
def api_threats():
    """Return active (unresolved) risks from the last scan."""
    state = _state()
    active = [
        r.to_dict() for r in state["scan_results"] if r.id not in state["resolved_ids"]
    ]
    return jsonify(active)


@bp.route("/api/resolve/<risk_id>", methods=["POST"])
def api_resolve(risk_id: str):
    """Mark a risk as resolved."""
    if not _validate_id(risk_id):
        logger.warning("Vigane riski ID: %s", risk_id[:50])
        return jsonify({"teade": "Vigane riski identifikaator"}), 400

    state = _state()
    known_ids = {r.id for r in state["scan_results"]}
    if risk_id not in known_ids:
        return jsonify({"teade": "Riski ei leitud"}), 404

    state["resolved_ids"].add(risk_id)
    logger.info("Risk lahendatuks märgitud: %s", risk_id)
    return jsonify({"teade": "Risk on lahendatuks märgitud", "id": risk_id})


@bp.route("/api/notify/<risk_id>", methods=["POST"])
def api_notify(risk_id: str):
    """Send notification for a specific risk."""
    if not _validate_id(risk_id):
        logger.warning("Vigane riski ID teavituspäringus: %s", risk_id[:50])
        return jsonify({"teade": "Vigane riski identifikaator"}), 400

    state = _state()
    known_ids = {r.id for r in state["scan_results"]}
    if risk_id not in known_ids:
        return jsonify({"teade": "Riski ei leitud"}), 404

    logger.info("Teavitus saadetud riski kohta: %s", risk_id)
    return jsonify({"teade": "Teavitus on saadetud", "id": risk_id})


@bp.route("/api/status")
def api_status():
    """Return scan statistics: total, critical, resolved counts."""
    state = _state()
    risks = state["scan_results"]
    resolved_ids = state["resolved_ids"]

    total = len(risks)
    critical = sum(1 for r in risks if r.severity == "critical")
    resolved = len(resolved_ids)

    return jsonify(
        {
            "total": total,
            "critical": critical,
            "resolved": resolved,
        }
    )
