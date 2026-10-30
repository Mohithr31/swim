"""
TINY MONITOR — Web Views Blueprint
Renders the single-page application dashboard.
"""

from flask import Blueprint, render_template

views_bp = Blueprint("views", __name__)


@views_bp.route("/")
def index():
    """Render the main single-page cyber forensics dashboard."""
    return render_template("index.html")
