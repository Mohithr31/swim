"""
TINY MONITOR — Application Factory
Initializes Flask app, security headers, blueprints, and database.
"""

from pathlib import Path
from flask import Flask, jsonify
from app.config import Config
from app.database import init_db
from app.routes.api_routes import api_bp
from app.routes.views import views_bp


def create_app(test_config: dict = None) -> Flask:
    """Application factory for TINY MONITOR."""
    base_dir = Path(__file__).resolve().parent.parent

    app = Flask(
        __name__,
        static_folder=str(base_dir / "static"),
        template_folder=str(base_dir / "templates")
    )

    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    # Max upload limit
    app.config["MAX_CONTENT_LENGTH"] = Config.MAX_UPLOAD_SIZE_BYTES

    # Ensure storage paths exist and database is initialized
    Config.ensure_directories()
    db_path = Path(app.config["DATABASE_PATH"]) if "DATABASE_PATH" in app.config else None
    init_db(db_path=db_path)

    # Register blueprints
    app.register_blueprint(views_bp)
    app.register_blueprint(api_bp)

    # Security Headers Middleware
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # Safe error handlers (no raw stack trace exposure)
    @app.errorhandler(404)
    def handle_404(e):
        return jsonify({"error": "Resource not found."}), 404

    @app.errorhandler(413)
    def handle_413(e):
        return jsonify({"error": "Uploaded file is too large (Maximum allowed: 50MB)."}), 413

    @app.errorhandler(500)
    def handle_500(e):
        return jsonify({"error": "An internal server error occurred."}), 500

    return app
