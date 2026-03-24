from flask import Blueprint, jsonify, render_template

from cybai.scanner import scan_infrastructure

bp = Blueprint("main", __name__)


@bp.route("/")
def dashboard():
    return render_template("dashboard.html")


@bp.route("/scan", methods=["POST"])
def scan():
    risks = scan_infrastructure()
    return jsonify([r.to_dict() for r in risks])
