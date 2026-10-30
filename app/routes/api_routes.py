"""
TINY MONITOR — REST API Blueprint
Provides RESTful endpoints with input validation, transaction safety, and clean error messages.
"""

from pathlib import Path
from flask import Blueprint, jsonify, request, send_file
from werkzeug.utils import secure_filename

from app.config import Config
from app.services.case_service import CaseService
from app.services.evidence_service import EvidenceService
from app.services.report_service import ReportService
from app.services.timeline_service import TimelineService
from app.services.tinyfish_service import (
    TinyFishAuthError,
    TinyFishError,
    TinyFishQuotaError,
    TinyFishRateLimitError,
    TinyFishService,
)

api_bp = Blueprint("api", __name__, url_prefix="/api")


# --- Status & Health Endpoints ---

@api_bp.route("/status", methods=["GET"])
def get_system_status():
    """Return TinyFish integration status, environment configuration, and database stats."""
    tinyfish_status = TinyFishService.get_status()
    dashboard_metrics = CaseService.get_dashboard_metrics()
    return jsonify({
        "system": "TINY MONITOR",
        "version": "1.0.0",
        "environment": Config.ENV,
        "tinyfish": tinyfish_status,
        "metrics": {
            "total_cases": dashboard_metrics["total_cases"],
            "open_cases": dashboard_metrics["open_cases"],
            "total_evidence": dashboard_metrics["total_evidence"],
            "verified_evidence": dashboard_metrics["verified_evidence"],
            "failed_integrity": dashboard_metrics["failed_integrity"],
            "total_lookups": dashboard_metrics["total_lookups"]
        }
    })


@api_bp.route("/tinyfish/test", methods=["POST"])
def test_tinyfish_connection():
    """Trigger live connectivity and authentication test against TinyFish Search API."""
    result = TinyFishService.test_connection()
    status_code = 200 if result["status"] == "CONFIGURED_AND_TESTED" else 400
    if result["status"] == "NOT_CONFIGURED":
        status_code = 404
    elif result["status"] == "AUTH_FAILED":
        status_code = 401
    return jsonify(result), status_code


# --- Dashboard Endpoints ---

@api_bp.route("/dashboard/metrics", methods=["GET"])
def get_dashboard_metrics():
    """Return comprehensive metrics, recent activity, and threat lookups."""
    data = CaseService.get_dashboard_metrics()
    data["tinyfish_status"] = TinyFishService.get_status()
    return jsonify(data)


# --- Case Management Endpoints ---

@api_bp.route("/cases", methods=["GET"])
def list_cases():
    """List all cases with optional status filter."""
    status_filter = request.args.get("status")
    cases = CaseService.list_cases(status=status_filter)
    return jsonify({"cases": cases, "count": len(cases)})


@api_bp.route("/cases", methods=["POST"])
def create_case():
    """Create a new DFIR case."""
    data = request.get_json() or {}
    title = data.get("title")
    investigator = data.get("investigator") or "Investigator"
    severity = data.get("severity", "MEDIUM")
    description = data.get("description", "")

    if not title or not title.strip():
        return jsonify({"error": "Case title is required."}), 400

    try:
        new_case = CaseService.create_case(
            title=title,
            investigator=investigator,
            severity=severity,
            description=description
        )
        return jsonify({"case": new_case, "message": "Case created successfully."}), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@api_bp.route("/cases/<int:case_id>", methods=["GET"])
def get_case(case_id: int):
    """Retrieve detailed case information with evidence and lookups."""
    case = CaseService.get_case_by_id(case_id)
    if not case:
        return jsonify({"error": f"Case with ID {case_id} not found."}), 404

    evidence = EvidenceService.list_case_evidence(case_id)
    lookups = TimelineService.list_threat_lookups(case_id=case_id)
    timeline = TimelineService.get_case_timeline(case_id)
    notes = CaseService.get_notes(case_id)

    return jsonify({
        "case": case,
        "evidence": evidence,
        "threat_lookups": lookups,
        "timeline": timeline,
        "notes": notes
    })


@api_bp.route("/cases/<int:case_id>", methods=["PATCH"])
def update_case(case_id: int):
    """Update case status, severity, title, or description."""
    data = request.get_json() or {}
    actor = data.get("actor") or "Investigator"

    try:
        updated = CaseService.update_case(
            case_id=case_id,
            title=data.get("title"),
            description=data.get("description"),
            severity=data.get("severity"),
            status=data.get("status"),
            actor=actor
        )
        return jsonify({"case": updated, "message": "Case updated successfully."})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@api_bp.route("/cases/<int:case_id>/notes", methods=["GET"])
def get_case_notes(case_id: int):
    """Get all investigator notes for a case."""
    notes = CaseService.get_notes(case_id)
    return jsonify({"notes": notes, "count": len(notes)})


@api_bp.route("/cases/<int:case_id>/notes", methods=["POST"])
def add_case_note(case_id: int):
    """Attach an investigator note to a case."""
    data = request.get_json() or {}
    note = data.get("note")
    author = data.get("author") or "Investigator"

    if not note or not note.strip():
        return jsonify({"error": "Note text is required."}), 400

    try:
        created = CaseService.add_note(case_id=case_id, author=author, note=note)
        return jsonify({"note": created, "message": "Note added successfully."}), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@api_bp.route("/cases/<int:case_id>/timeline", methods=["GET"])
def get_case_timeline(case_id: int):
    """Get chronological timeline events for a case."""
    events = TimelineService.get_case_timeline(case_id)
    return jsonify({"timeline": events, "count": len(events)})


# --- Digital Evidence Endpoints ---

@api_bp.route("/cases/<int:case_id>/evidence", methods=["GET"])
def list_case_evidence(case_id: int):
    """List all digital evidence items for a case."""
    evidence = EvidenceService.list_case_evidence(case_id)
    return jsonify({"evidence": evidence, "count": len(evidence)})


@api_bp.route("/cases/<int:case_id>/evidence", methods=["POST"])
def upload_evidence(case_id: int):
    """Upload digital evidence, calculate SHA-256 hash, and record in audit log."""
    case = CaseService.get_case_by_id(case_id)
    if not case:
        return jsonify({"error": f"Case with ID {case_id} not found."}), 404

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded in form field 'file'."}), 400

    uploaded_file = request.files["file"]
    if not uploaded_file.filename or not uploaded_file.filename.strip():
        return jsonify({"error": "Uploaded filename is empty."}), 400

    acquired_by = request.form.get("acquired_by") or "Investigator"
    description = request.form.get("description") or ""
    mime_type = uploaded_file.mimetype or "application/octet-stream"

    try:
        evidence = EvidenceService.store_evidence(
            case_id=case_id,
            file_stream=uploaded_file.stream,
            original_filename=uploaded_file.filename,
            acquired_by=acquired_by,
            description=description,
            mime_type=mime_type
        )
        return jsonify({
            "evidence": evidence,
            "message": f"Evidence '{evidence['filename']}' acquired and SHA-256 baseline computed."
        }), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Failed to store evidence: {str(exc)}"}), 500


@api_bp.route("/evidence/<int:evidence_id>/verify", methods=["POST"])
def verify_evidence_integrity(evidence_id: int):
    """Recalculate SHA-256 hash of evidence on disk and verify integrity baseline."""
    data = request.get_json() or {}
    verified_by = data.get("verified_by") or "Investigator"

    try:
        updated = EvidenceService.verify_integrity(evidence_id=evidence_id, verified_by=verified_by)
        return jsonify({
            "evidence": updated,
            "status": updated["integrity_status"],
            "sha256": updated["sha256_hash"],
            "verified_at": updated["last_verified_at"],
            "notes": updated["verification_notes"]
        })
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": f"Verification failed: {str(exc)}"}), 500


# --- Threat Intelligence (TinyFish) Endpoints ---

@api_bp.route("/threat-intel/classify", methods=["POST"])
def classify_indicator():
    """Classify indicator type (ip, domain, url, hash, cve, general)."""
    data = request.get_json() or {}
    indicator = data.get("indicator", "")
    itype = TinyFishService.classify_indicator(indicator)
    query, purpose = TinyFishService.build_threat_query(indicator, itype)
    return jsonify({
        "indicator": indicator,
        "indicator_type": itype,
        "suggested_query": query,
        "suggested_purpose": purpose
    })


@api_bp.route("/threat-intel/search", methods=["POST"])
def search_threat_intel():
    """
    Execute real TinyFish Search API threat intelligence lookup.
    Persists query and source-backed results to database and links to case.
    """
    data = request.get_json() or {}
    indicator = data.get("indicator", "").strip()
    case_id = data.get("case_id")
    investigator = data.get("investigator") or "Investigator"
    domain_type = data.get("domain_type") or "web"

    if not indicator:
        return jsonify({"error": "Indicator or search query is required."}), 400

    # Auto-classify and formulate threat query
    indicator_type = data.get("indicator_type") or TinyFishService.classify_indicator(indicator)
    suggested_query, suggested_purpose = TinyFishService.build_threat_query(indicator, indicator_type)

    query = data.get("query") or suggested_query
    purpose = data.get("purpose") or suggested_purpose

    try:
        # Call genuine TinyFish Search API
        search_response = TinyFishService.search(
            query=query,
            purpose=purpose,
            domain_type=domain_type
        )
        results = search_response.get("results", [])
        status = "SUCCESS" if results else "ZERO_RESULTS"
        error_msg = None

        # Save to database
        saved_lookup = TimelineService.save_threat_lookup(
            case_id=case_id,
            indicator=indicator,
            indicator_type=indicator_type,
            query=query,
            purpose=purpose,
            status=status,
            results_count=len(results),
            results=results,
            error_message=None,
            investigator=investigator
        )

        return jsonify({
            "lookup": saved_lookup,
            "results": results,
            "total_results": len(results),
            "status": status,
            "source": "TinyFish Search API",
            "message": f"Retrieved {len(results)} intelligence leads via TinyFish."
        })

    except TinyFishAuthError as exc:
        TimelineService.save_threat_lookup(
            case_id=case_id,
            indicator=indicator,
            indicator_type=indicator_type,
            query=query,
            purpose=purpose,
            status="FAILED",
            results_count=0,
            results=[],
            error_message=exc.message,
            investigator=investigator
        )
        return jsonify({
            "error": exc.message,
            "status": "AUTH_FAILED",
            "error_code": exc.error_code
        }), 401

    except TinyFishQuotaError as exc:
        TimelineService.save_threat_lookup(
            case_id=case_id,
            indicator=indicator,
            indicator_type=indicator_type,
            query=query,
            purpose=purpose,
            status="FAILED",
            results_count=0,
            results=[],
            error_message=exc.message,
            investigator=investigator
        )
        return jsonify({
            "error": exc.message,
            "status": "QUOTA_EXHAUSTED",
            "error_code": exc.error_code
        }), 402

    except TinyFishRateLimitError as exc:
        return jsonify({
            "error": exc.message,
            "status": "RATE_LIMIT_EXCEEDED",
            "error_code": exc.error_code
        }), 429

    except TinyFishError as exc:
        TimelineService.save_threat_lookup(
            case_id=case_id,
            indicator=indicator,
            indicator_type=indicator_type,
            query=query,
            purpose=purpose,
            status="FAILED",
            results_count=0,
            results=[],
            error_message=exc.message,
            investigator=investigator
        )
        return jsonify({
            "error": exc.message,
            "status": "REQUEST_FAILED",
            "error_code": exc.error_code
        }), exc.status_code or 500

    except Exception as exc:
        return jsonify({"error": f"Internal lookup error: {str(exc)}"}), 500


@api_bp.route("/threat-intel/history", methods=["GET"])
def get_threat_intel_history():
    """Retrieve previous threat intelligence lookups."""
    case_id_param = request.args.get("case_id")
    case_id = int(case_id_param) if case_id_param and case_id_param.isdigit() else None
    lookups = TimelineService.list_threat_lookups(case_id=case_id)
    return jsonify({"lookups": lookups, "count": len(lookups)})


# --- Report Generation Endpoints ---

@api_bp.route("/cases/<int:case_id>/report", methods=["POST"])
def generate_case_report(case_id: int):
    """Generate official PDF forensic report."""
    data = request.get_json() or {}
    generated_by = data.get("generated_by") or "Lead Investigator"

    try:
        report_meta = ReportService.generate_case_pdf(case_id=case_id, generated_by=generated_by)
        download_url = f"/api/reports/download/{report_meta['filename']}"
        report_meta["download_url"] = download_url
        return jsonify({
            "report": report_meta,
            "message": f"Forensic report '{report_meta['filename']}' generated successfully."
        }), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": f"Report generation failed: {str(exc)}"}), 500


@api_bp.route("/reports/download/<filename>", methods=["GET"])
def download_report(filename: str):
    """Download generated PDF report safely with anti-traversal protection."""
    clean_name = secure_filename(filename)
    if not clean_name.endswith(".pdf"):
        return jsonify({"error": "Invalid report file request."}), 400

    target_file = Config.REPORTS_DIR / clean_name
    if not target_file.exists():
        return jsonify({"error": "Report file not found."}), 404

    # Security check: ensure path is within REPORTS_DIR
    if not str(target_file.resolve()).startswith(str(Config.REPORTS_DIR.resolve())):
        return jsonify({"error": "Path traversal detected."}), 403

    return send_file(
        target_file,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=clean_name
    )


# --- Global Timeline Endpoints ---

@api_bp.route("/timeline", methods=["GET"])
def get_global_timeline():
    """Get global chronological timeline across all cases."""
    limit = int(request.args.get("limit", 50))
    events = TimelineService.get_global_timeline(limit=limit)
    return jsonify({"timeline": events, "count": len(events)})
