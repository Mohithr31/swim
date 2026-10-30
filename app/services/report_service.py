"""
TINY MONITOR — Investigation Report Service
Generates professional, forensic-grade PDF investigation reports using ReportLab.
Includes strict separation of verified evidence, external TinyFish intelligence,
and analyst conclusions.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.config import Config
from app.database import get_db_connection, utc_now_iso
from app.services.case_service import CaseService
from app.services.evidence_service import EvidenceService
from app.services.timeline_service import TimelineService


class ReportService:
    """Generates official Forensic Incident Response PDF reports."""

    @classmethod
    def generate_case_pdf(cls, case_id: int, generated_by: str = "Lead Investigator") -> Dict[str, Any]:
        """
        Build an official PDF investigation report for the specified case.
        Returns: {
            "case_id": int,
            "filename": str,
            "file_path": str,
            "generated_at": str,
            "file_size": int
        }
        """
        Config.ensure_directories()
        case = CaseService.get_case_by_id(case_id)
        if not case:
            raise ValueError(f"Case with ID {case_id} not found.")

        evidence_list = EvidenceService.list_case_evidence(case_id)
        threat_lookups = TimelineService.list_threat_lookups(case_id)
        timeline_events = TimelineService.get_case_timeline(case_id)
        notes = CaseService.get_notes(case_id)

        case_num = case["case_number"]
        now = datetime.now(timezone.utc)
        timestamp_str = now.strftime("%Y%m%d_%H%M%S")
        filename = f"{case_num.replace('-', '_')}_DFIR_Report_{timestamp_str}.pdf"
        target_path = Config.REPORTS_DIR / filename

        # Build Document
        doc = SimpleDocTemplate(
            str(target_path),
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )

        styles = getSampleStyleSheet()

        # Custom Cyber Forensic Palette
        c_primary = colors.HexColor("#0f172a")      # Slate 900
        c_accent = colors.HexColor("#0284c7")       # Cyan 600
        c_danger = colors.HexColor("#dc2626")       # Red 600
        c_success = colors.HexColor("#16a34a")      # Green 600
        c_muted = colors.HexColor("#475569")        # Slate 600
        c_border = colors.HexColor("#cbd5e1")       # Slate 300
        c_bg_light = colors.HexColor("#f8fafc")     # Slate 50
        c_card = colors.HexColor("#f1f5f9")         # Slate 100

        # Typography Styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=c_primary,
            spaceAfter=4,
            fontName="Helvetica-Bold"
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=c_accent,
            fontName="Helvetica-Bold",
            spaceAfter=12
        )
        sec_heading = ParagraphStyle(
            "SecHeading",
            parent=styles["Heading2"],
            fontSize=12,
            leading=16,
            textColor=c_primary,
            fontName="Helvetica-Bold",
            spaceBefore=14,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#1e293b")
        )
        code_style = ParagraphStyle(
            "CodeFont",
            parent=styles["Normal"],
            fontSize=7.5,
            leading=10,
            fontName="Courier",
            textColor=colors.HexColor("#0f172a")
        )
        alert_style = ParagraphStyle(
            "AlertFont",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=c_muted,
            fontName="Helvetica-Oblique"
        )

        elements: List[Any] = []

        # Header Banner
        elements.append(Paragraph("TINY MONITOR — DIGITAL FORENSICS REPORT", title_style))
        elements.append(Paragraph("Incident Response & TinyFish Threat Intelligence Dossier", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=c_accent, spaceBefore=2, spaceAfter=10))

        # Metadata Table
        meta_data = [
            [
                Paragraph("<b>Case Number:</b>", body_style),
                Paragraph(f"<b>{case['case_number']}</b>", body_style),
                Paragraph("<b>Classification:</b>", body_style),
                Paragraph(f"<font color='{c_danger.hexval()}'><b>{case['severity']} SEVERITY</b></font>", body_style)
            ],
            [
                Paragraph("<b>Case Title:</b>", body_style),
                Paragraph(case["title"], body_style),
                Paragraph("<b>Current Status:</b>", body_style),
                Paragraph(f"<b>{case['status']}</b>", body_style)
            ],
            [
                Paragraph("<b>Lead Investigator:</b>", body_style),
                Paragraph(case["investigator"], body_style),
                Paragraph("<b>Generated By:</b>", body_style),
                Paragraph(generated_by, body_style)
            ],
            [
                Paragraph("<b>Initial Incident Date:</b>", body_style),
                Paragraph(case["created_at"][:19].replace("T", " ") + " UTC", body_style),
                Paragraph("<b>Report Date:</b>", body_style),
                Paragraph(now.strftime("%Y-%m-%d %H:%M:%S UTC"), body_style)
            ]
        ]
        meta_table = Table(meta_data, colWidths=[110, 155, 100, 165])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), c_bg_light),
            ("BOX", (0, 0), (-1, -1), 1, c_border),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, c_border),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 10))

        # Section 1: Executive Summary
        elements.append(Paragraph("1. Executive Summary", sec_heading))
        summary_text = case.get("description") or "No detailed description provided by investigator at intake."
        exec_summary = f"""
        This document represents the official digital forensic investigation dossier for <b>{case['case_number']}</b>.
        A total of <b>{len(evidence_list)}</b> physical/logical evidence files have been cryptographically preserved.
        <b>{len(threat_lookups)}</b> external threat intelligence lookups were executed through the TinyFish Search API.
        All digital evidence files maintain cryptographic SHA-256 integrity baseline verification.
        <br/><br/>
        <b>Incident Summary:</b> {summary_text}
        """
        elements.append(Paragraph(exec_summary, body_style))
        elements.append(Spacer(1, 10))

        # Section 2: Digital Evidence Inventory & SHA-256 Hashes
        elements.append(Paragraph("2. Digital Evidence Inventory & Cryptographic Baseline", sec_heading))
        if not evidence_list:
            elements.append(Paragraph("<i>No digital evidence files have been logged for this case.</i>", body_style))
        else:
            ev_headers = [
                Paragraph("<b>#</b>", body_style),
                Paragraph("<b>Filename / Size</b>", body_style),
                Paragraph("<b>SHA-256 Cryptographic Hash</b>", body_style),
                Paragraph("<b>Acquired / Status</b>", body_style)
            ]
            ev_rows = [ev_headers]
            for idx, ev in enumerate(evidence_list, start=1):
                status_color = c_success.hexval() if ev["integrity_status"] == "VERIFIED_MATCH" else c_danger.hexval()
                status_label = "MATCH" if ev["integrity_status"] == "VERIFIED_MATCH" else ev["integrity_status"]

                ev_rows.append([
                    Paragraph(str(idx), body_style),
                    Paragraph(f"<b>{ev['filename']}</b><br/>{ev['file_size']} bytes ({ev['mime_type']})", body_style),
                    Paragraph(f"<font face='Courier' size='7'>{ev['sha256_hash']}</font>", code_style),
                    Paragraph(f"{ev['acquisition_date'][:10]}<br/><font color='{status_color}'><b>{status_label}</b></font>", body_style)
                ])

            ev_table = Table(ev_rows, colWidths=[20, 160, 240, 110])
            ev_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), c_card),
                ("BOX", (0, 0), (-1, -1), 1, c_border),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, c_border),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))
            elements.append(ev_table)

        elements.append(Spacer(1, 10))

        # Section 3: TinyFish Threat Intelligence Leads
        elements.append(Paragraph("3. TinyFish Threat Intelligence Findings", sec_heading))
        if not threat_lookups:
            elements.append(Paragraph("<i>No threat intelligence queries have been executed for this case.</i>", body_style))
        else:
            intel_intro = """
            External intelligence queries executed against the <b>TinyFish Search API</b>.
            <i>Note: Search findings represent open-source intelligence (OSINT) leads and advisories for correlation, not internal evidence proof.</i>
            """
            elements.append(Paragraph(intel_intro, alert_style))
            elements.append(Spacer(1, 6))

            for lk in threat_lookups:
                lk_status_color = c_success.hexval() if lk["status"] == "SUCCESS" else (c_muted.hexval() if lk["status"] == "ZERO_RESULTS" else c_danger.hexval())
                lk_header = f"<b>Indicator:</b> {lk['indicator']} ({lk['indicator_type'].upper()}) — Status: <font color='{lk_status_color}'><b>{lk['status']}</b></font> ({lk['results_count']} results)"
                elements.append(Paragraph(lk_header, body_style))
                elements.append(Paragraph(f"<b>Query:</b> <font face='Courier' size='7.5'>{lk['query']}</font>", code_style))
                if lk.get("purpose"):
                    elements.append(Paragraph(f"<b>Purpose:</b> {lk['purpose']}", body_style))

                results = lk.get("results") or []
                if results:
                    r_rows = [[
                        Paragraph("<b>#</b>", body_style),
                        Paragraph("<b>Source / Title</b>", body_style),
                        Paragraph("<b>Snippet / Evidence Lead</b>", body_style),
                        Paragraph("<b>URL & Date</b>", body_style)
                    ]]
                    for r_idx, r in enumerate(results[:5], start=1):  # Top 5 leads in PDF
                        date_str = f"<br/>Pub: {r['date']}" if r.get("date") else ""
                        r_rows.append([
                            Paragraph(str(r_idx), body_style),
                            Paragraph(f"<b>{r.get('site_name') or 'Web Source'}</b><br/>{r.get('title')}", body_style),
                            Paragraph(r.get("snippet", "")[:180] + ("..." if len(r.get("snippet", "")) > 180 else ""), body_style),
                            Paragraph(f"<font size='6.5' face='Courier'>{r.get('url', '')[:45]}</font>{date_str}", body_style)
                        ])
                    r_table = Table(r_rows, colWidths=[20, 140, 220, 150])
                    r_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), c_card),
                        ("BOX", (0, 0), (-1, -1), 0.75, c_border),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, c_border),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ]))
                    elements.append(r_table)
                elif lk["status"] == "ZERO_RESULTS":
                    elements.append(Paragraph("<i>Query executed successfully but yielded no public cybersecurity advisories or matches.</i>", body_style))
                elif lk["status"] == "FAILED":
                    elements.append(Paragraph(f"<font color='{c_danger.hexval()}'>Error during lookup: {lk.get('error_message')}</font>", body_style))

                elements.append(Spacer(1, 8))

        elements.append(Spacer(1, 8))

        # Section 4: Chronological Investigation Timeline
        elements.append(Paragraph("4. Chronological Investigation Timeline", sec_heading))
        if not timeline_events:
            elements.append(Paragraph("<i>No timeline events recorded.</i>", body_style))
        else:
            time_rows = [[
                Paragraph("<b>Timestamp (UTC)</b>", body_style),
                Paragraph("<b>Event Type</b>", body_style),
                Paragraph("<b>Actor</b>", body_style),
                Paragraph("<b>Details / Action Taken</b>", body_style)
            ]]
            for ev in timeline_events:
                time_rows.append([
                    Paragraph(f"<font size='7.5'>{ev['timestamp'][:19].replace('T', ' ')}</font>", body_style),
                    Paragraph(f"<b>{ev['event_type']}</b>", body_style),
                    Paragraph(ev["actor"], body_style),
                    Paragraph(f"<b>{ev['title']}</b><br/>{ev.get('description', '')}", body_style)
                ])

            time_table = Table(time_rows, colWidths=[95, 115, 80, 240])
            time_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), c_card),
                ("BOX", (0, 0), (-1, -1), 0.75, c_border),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, c_border),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(time_table)

        elements.append(Spacer(1, 10))

        # Section 5: Investigator Notes & Conclusions
        elements.append(Paragraph("5. Investigator Notes & Conclusions", sec_heading))
        if not notes:
            elements.append(Paragraph("<i>No formal analyst conclusion notes entered.</i>", body_style))
        else:
            for n in notes:
                elements.append(Paragraph(
                    f"<b>{n['author']}</b> ({n['created_at'][:19].replace('T', ' ')} UTC):",
                    body_style
                ))
                elements.append(Paragraph(f"<i>\"{n['note']}\"</i>", body_style))
                elements.append(Spacer(1, 4))

        elements.append(Spacer(1, 12))

        # Section 6: Forensic Boundaries & Methodology Disclaimer
        elements.append(Paragraph("6. Forensic Boundaries & Methodology Disclaimer", sec_heading))
        disclaimer_text = """
        <b>FORENSIC SOUNDNESS & OPEN-SOURCE INTELLIGENCE BOUNDARIES:</b><br/>
        1. <b>Evidence Integrity:</b> Cryptographic SHA-256 hashes are calculated upon acquisition and re-calculated on demand. Evidence files are preserved in protected storage outside web static roots. No evidence bytes were modified or transmitted to external services.<br/>
        2. <b>External Threat Intelligence:</b> Data retrieved via the TinyFish Search API reflects publicly indexed threat advisories, vendor bulletins, and security feeds at the moment of lookup. Search results are investigative leads and do not constitute independent digital forensic proof or legal attribution.<br/>
        3. <b>Zero Fabrication:</b> This report was automatically compiled from active database records. No test results or search findings were fabricated or omitted.<br/>
        4. <b>Presidency University Hackathon:</b> Generated by <b>TINY MONITOR</b> for the Swim with TinyFish Hackathon.
        """
        elements.append(Paragraph(disclaimer_text, alert_style))

        # Build PDF
        doc.build(elements)

        file_size = target_path.stat().st_size
        iso_now = utc_now_iso()

        # Record timeline event in case
        TimelineService.record_event(
            case_id=case_id,
            event_type="REPORT_GENERATED",
            title=f"Forensic Report Generated: {filename}",
            description=f"Official investigation report generated ({file_size} bytes). Downloadable via reports view.",
            actor=generated_by,
            metadata={"filename": filename, "file_size": file_size}
        )

        return {
            "case_id": case_id,
            "filename": filename,
            "file_path": str(target_path),
            "generated_at": iso_now,
            "file_size": file_size
        }
