import os

from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


def create_app():
    app = Flask(__name__)

    # CORS — only known origins (OWASP A05)
    allowed_origins = os.environ.get(
        "ALLOWED_ORIGINS",
        "http://localhost:5000,http://127.0.0.1:5000",
    ).split(",")
    CORS(app, origins=allowed_origins, supports_credentials=False)

    # Rate limiting — disabled in test mode (OWASP A01)
    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri="memory://",
        enabled=not app.config.get("TESTING", False),
    )

    from cybai.routes import bp, api_scan, api_notify

    app.register_blueprint(bp)

    # Apply rate limits to expensive endpoints
    limiter.limit("10 per minute")(api_scan)
    limiter.limit("20 per minute")(api_notify)

    # Error handlers — JSON only, no stack traces (OWASP A05)
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"teade": "Vigane päring"}), 400

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"teade": "Ressurss ei leitud"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"teade": "Meetod ei ole lubatud"}), 405

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({"teade": "Liiga palju päringuid. Palun oota."}), 429

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"teade": "Serveri sisemine viga"}), 500

    return app
