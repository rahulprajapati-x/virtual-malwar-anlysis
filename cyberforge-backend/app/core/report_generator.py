"""
CyberForge — Forensic Report Generator
Generates court-admissible PDF reports for analyzed samples using ReportLab.
"""
import io
import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

NAVY      = colors.HexColor("#0D1122")
BLUE      = colors.HexColor("#2D6BE4")
RED       = colors.HexColor("#EF4444")
ORANGE    = colors.HexColor("#F97316")
YELLOW    = colors.HexColor("#EAB308")
GREEN     = colors.HexColor("#22C55E")
GRAY      = colors.HexColor("#64748B")
LIGHTGRAY = colors.HexColor("#E2E8F0")

THREAT_COLORS = {
    "CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW,
    "LOW": GREEN, "CLEAN": GREEN,
}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("ReportTitle", parent=ss["Title"], fontSize=22,
                           textColor=NAVY, spaceAfter=4))
    ss.add(ParagraphStyle("ReportSubtitle", parent=ss["Normal"], fontSize=10,
                           textColor=GRAY, spaceAfter=14))
    ss.add(ParagraphStyle("SectionHeader", parent=ss["Heading2"], fontSize=13,
                           textColor=NAVY, spaceBefore=16, spaceAfter=8,
                           borderWidth=0, borderPadding=0))
    ss.add(ParagraphStyle("BodyText2", parent=ss["Normal"], fontSize=9.5,
                           textColor=colors.HexColor("#1E293B"), leading=14))
    ss.add(ParagraphStyle("MonoText", parent=ss["Normal"], fontName="Courier",
                           fontSize=8.5, textColor=colors.HexColor("#1E293B")))
    ss.add(ParagraphStyle("Footer", parent=ss["Normal"], fontSize=7.5,
                           textColor=GRAY, alignment=TA_CENTER))
    return ss


def _header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, A4[1] - 14*mm, A4[0], 14*mm, fill=True, stroke=False)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawString(15*mm, A4[1] - 9.5*mm, "CYBER FORGE — DIGITAL FORENSICS REPORT")
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(A4[0] - 15*mm, A4[1] - 9.5*mm, "CONFIDENTIAL — LAW ENFORCEMENT USE ONLY")

    canvas.setFillColor(GRAY)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(15*mm, 8*mm, f"Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    canvas.drawRightString(A4[0] - 15*mm, 8*mm, f"Page {doc.page}")
    canvas.restoreState()


def _kv_table(rows, col_widths=(45*mm, 130*mm)):
    style = getSampleStyleSheet()
    data = []
    for k, v in rows:
        data.append([
            Paragraph(f"<b>{k}</b>", style["Normal"]),
            Paragraph(str(v), style["Normal"]),
        ])
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LIGHTGRAY),
        ("TEXTCOLOR", (0, 0), (0, -1), NAVY),
    ]))
    return t


def generate_forensic_report(sample, case=None) -> bytes:
    """
    Generate a complete forensic analysis PDF report for a sample.

    Args:
        sample: Sample ORM object (with .analysis_data populated)
        case:   Optional Case ORM object for case context

    Returns:
        PDF file as bytes
    """
    ss = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=22*mm, bottomMargin=16*mm,
        leftMargin=15*mm, rightMargin=15*mm,
    )

    data = sample.analysis_data or {}
    story = []

    # ── Title ──────────────────────────────────────────────────
    story.append(Paragraph("Malware Analysis &amp; Forensic Report", ss["ReportTitle"]))
    story.append(Paragraph(
        f"Sample: <b>{sample.filename}</b> &nbsp;|&nbsp; Report ID: {sample.id}",
        ss["ReportSubtitle"]
    ))
    story.append(HRFlowable(width="100%", thickness=1.2, color=NAVY, spaceAfter=10))

    # ── Threat Verdict Banner ─────────────────────────────────
    threat_color = THREAT_COLORS.get(sample.threat_level, GRAY)
    verdict_table = Table(
        [[Paragraph(
            f'<font color="white"><b>THREAT LEVEL: {sample.threat_level}</b> &nbsp;&nbsp;|&nbsp;&nbsp; '
            f'RISK SCORE: {sample.risk_score}/100</font>',
            ParagraphStyle("Verdict", fontSize=12, alignment=TA_CENTER)
        )]],
        colWidths=[180*mm]
    )
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), threat_color),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 10))

    # ── Case Context ───────────────────────────────────────────
    if case:
        story.append(Paragraph("Case Information", ss["SectionHeader"]))
        story.append(_kv_table([
            ("Case Number", case.case_number),
            ("Case Name", case.name),
            ("Investigating Analyst", case.analyst or "—"),
            ("Agency / Unit", case.agency or "—"),
            ("Case Status", case.status),
        ]))

    # ── File Identification ────────────────────────────────────
    story.append(Paragraph("File Identification", ss["SectionHeader"]))
    story.append(_kv_table([
        ("Filename", sample.filename),
        ("File Size", f"{sample.file_size:,} bytes"),
        ("File Type", sample.file_type),
        ("MIME Type", sample.mime_type or "—"),
        ("Submitted By", sample.submitted_by or "—"),
        ("Submission Time (UTC)", sample.submitted_at.strftime("%Y-%m-%d %H:%M:%S")),
        ("Analysis Completed (UTC)", sample.analyzed_at.strftime("%Y-%m-%d %H:%M:%S") if sample.analyzed_at else "—"),
    ]))

    # ── Cryptographic Hashes ────────────────────────────────────
    story.append(Paragraph("Cryptographic Hashes (Chain of Custody)", ss["SectionHeader"]))
    hash_rows = [
        ("SHA-256", sample.sha256 or "—"),
        ("SHA-1", sample.sha1 or "—"),
        ("MD5", sample.md5 or "—"),
    ]
    if sample.imphash:
        hash_rows.append(("Import Hash", sample.imphash))
    if sample.ssdeep_hash:
        hash_rows.append(("Fuzzy Hash (ssdeep)", sample.ssdeep_hash))
    story.append(_kv_table(hash_rows))

    # ── VirusTotal Verdict ──────────────────────────────────────
    vt = data.get("virustotal")
    if vt and vt.get("found"):
        story.append(Paragraph("Threat Intelligence — VirusTotal", ss["SectionHeader"]))
        story.append(_kv_table([
            ("Detection Ratio", f"{vt['detection_ratio']} engines"),
            ("Verdict", vt["verdict"]),
            ("Known Threat Names", ", ".join(vt.get("threat_names", [])[:5]) or "—"),
            ("First Seen", vt.get("first_seen") or "—"),
        ]))

    # ── YARA Detections ─────────────────────────────────────────
    yara = data.get("yara", {})
    if yara.get("matches"):
        story.append(Paragraph(f"YARA Signature Matches ({len(yara['matches'])})", ss["SectionHeader"]))
        cell_style = ParagraphStyle("TableCell", fontSize=7.5, leading=9.5)
        rows = [["Rule", "Family", "Severity", "Description"]]
        for m in yara["matches"][:15]:
            rows.append([
                Paragraph(m["rule"], cell_style),
                Paragraph(m["family"], cell_style),
                Paragraph(m["severity"], cell_style),
                Paragraph((m.get("description") or "")[:90], cell_style),
            ])
        t = Table(rows, colWidths=[42*mm, 28*mm, 22*mm, 88*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, 0), 7.5),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.3, LIGHTGRAY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("YARA Signature Matches", ss["SectionHeader"]))
        story.append(Paragraph("No YARA signatures matched this sample.", ss["BodyText2"]))

    story.append(PageBreak())

    # ── MITRE ATT&CK Techniques ─────────────────────────────────
    mitre = data.get("mitre", [])
    story.append(Paragraph(f"MITRE ATT&amp;CK Technique Mapping ({len(mitre)})", ss["SectionHeader"]))
    if mitre:
        cell_style2 = ParagraphStyle("TableCell2", fontSize=7.5, leading=9.5)
        rows = [["ID", "Technique", "Tactic", "Confidence"]]
        for t in mitre[:20]:
            rows.append([
                Paragraph(t["id"], cell_style2),
                Paragraph(t["name"], cell_style2),
                Paragraph(t["tactic"], cell_style2),
                Paragraph(t["confidence"], cell_style2),
            ])
        tbl = Table(rows, colWidths=[22*mm, 58*mm, 50*mm, 30*mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, 0), 7.5),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.3, LIGHTGRAY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(tbl)
    else:
        story.append(Paragraph("No MITRE ATT&CK techniques identified.", ss["BodyText2"]))

    # ── Behavioral Analysis ──────────────────────────────────────
    behaviors = data.get("behaviors", [])
    story.append(Paragraph("Behavioral Analysis Summary", ss["SectionHeader"]))
    for b in behaviors[:12]:
        sev_color = THREAT_COLORS.get(b["severity"], GRAY)
        story.append(KeepTogether([
            Paragraph(
                f'<font color="{sev_color.hexval()}"><b>[{b["severity"]}]</b></font> <b>{b["title"]}</b>',
                ss["BodyText2"]
            ),
            Paragraph(b.get("description", ""), ss["BodyText2"]),
            Spacer(1, 6),
        ]))

    # ── IOCs ───────────────────────────────────────────────────
    iocs = data.get("iocs", {})
    story.append(Paragraph("Indicators of Compromise (IOCs)", ss["SectionHeader"]))
    ioc_sections = [
        ("Domains", iocs.get("domains", [])),
        ("IP Addresses", iocs.get("ips", [])),
        ("URLs", iocs.get("urls", [])),
        ("Registry Keys", iocs.get("registry_keys", [])),
        ("File Paths / Drops", iocs.get("file_paths", [])),
        ("Mutexes", iocs.get("mutexes", [])),
        ("Cryptocurrency Wallets", iocs.get("crypto_wallets", [])),
    ]
    any_iocs = False
    for label, values in ioc_sections:
        if values:
            any_iocs = True
            story.append(Paragraph(f"<b>{label}</b> ({len(values)})", ss["BodyText2"]))
            for v in values[:10]:
                story.append(Paragraph(v, ss["MonoText"]))
            story.append(Spacer(1, 6))
    if not any_iocs:
        story.append(Paragraph("No IOCs were extracted from this sample.", ss["BodyText2"]))

    # ── Examiner Certification ──────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Examiner Certification", ss["SectionHeader"]))
    story.append(Paragraph(
        "This report was generated by the CyberForge Forensics Platform using automated static "
        "analysis, YARA signature detection, MITRE ATT&CK technique mapping, and threat intelligence "
        "correlation. All cryptographic hashes were computed directly from the submitted file to "
        "establish chain of custody. This report is intended to assist a qualified digital forensic "
        "examiner in their investigation and should be reviewed and validated by a human analyst before "
        "use as evidence in any legal proceeding.",
        ss["BodyText2"]
    ))
    story.append(Spacer(1, 30))
    story.append(_kv_table([
        ("Report Generated", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")),
        ("Platform Version", "CyberForge v2.0"),
        ("Examiner Signature", "_______________________________"),
        ("Date", "_______________________________"),
    ]))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()
