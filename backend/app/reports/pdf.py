"""Render report dicts into professional, screenshot-ready PDFs (ReportLab)."""
from __future__ import annotations

import io
from datetime import datetime
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

# --- palette (print/screenshot friendly on white) ---
NAVY = colors.HexColor("#0f2a4a")
NAVY_2 = colors.HexColor("#16365c")
ACCENT = colors.HexColor("#0ea5e9")
INK = colors.HexColor("#1f2937")
MUTED = colors.HexColor("#6b7280")
LINE = colors.HexColor("#e2e8f0")
ZEBRA = colors.HexColor("#f5f8fc")
HEAD_BG = colors.HexColor("#1e3a5f")

SEV_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#2563eb"),
}

_styles = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=_styles["Heading1"], fontName="Helvetica-Bold", fontSize=18, textColor=colors.white, leading=22)
SUB = ParagraphStyle("sub", parent=_styles["Normal"], fontSize=9, textColor=colors.HexColor("#bcd3ec"))
SECTION = ParagraphStyle("section", parent=_styles["Heading2"], fontName="Helvetica-Bold", fontSize=12, textColor=NAVY, spaceBefore=10, spaceAfter=6)
BODY = ParagraphStyle("body", parent=_styles["Normal"], fontSize=9, textColor=INK, leading=12)
KPI_LABEL = ParagraphStyle("kpilabel", parent=_styles["Normal"], fontSize=7.5, textColor=MUTED, leading=10)
KPI_VALUE = ParagraphStyle("kpivalue", parent=_styles["Normal"], fontName="Helvetica-Bold", fontSize=20, textColor=NAVY, leading=22)
CELL = ParagraphStyle("cell", parent=_styles["Normal"], fontSize=8.5, textColor=INK, leading=11)
CELL_MUTED = ParagraphStyle("cellmuted", parent=_styles["Normal"], fontSize=8, textColor=MUTED, leading=10)


def _fmt_dt(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return iso


def _on_page(canvas, doc):
    canvas.saveState()
    # top banner
    canvas.setFillColor(NAVY)
    canvas.rect(0, A4[1] - 32 * mm, A4[0], 32 * mm, fill=1, stroke=0)
    canvas.setFillColor(ACCENT)
    canvas.rect(0, A4[1] - 33 * mm, A4[0], 1 * mm, fill=1, stroke=0)
    meta = doc._report_meta
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 18)
    canvas.drawString(18 * mm, A4[1] - 18 * mm, "SentinelSSH")
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.HexColor("#bcd3ec"))
    canvas.drawString(18 * mm, A4[1] - 24 * mm, meta["title"] + "  ·  " + meta["subtitle"])
    canvas.drawRightString(A4[0] - 18 * mm, A4[1] - 24 * mm, "Generated " + _fmt_dt(meta["generated_at"]))
    # footer
    canvas.setStrokeColor(LINE)
    canvas.line(18 * mm, 14 * mm, A4[0] - 18 * mm, 14 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "SentinelSSH — SOC Threat Intelligence  ·  Confidential")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, "Page %d" % doc.page)
    canvas.restoreState()


def _doc(buf, meta) -> BaseDocTemplate:
    doc = BaseDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=40 * mm, bottomMargin=20 * mm,
    )
    doc._report_meta = meta
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
    doc.addPageTemplates([PageTemplate(id="tpl", frames=[frame], onPage=_on_page)])
    return doc


def _kpi_grid(summary: Dict[str, Any]) -> Table:
    labels = [
        ("Total Attacks", "total_attacks"), ("Total Incidents", "total_incidents"),
        ("Active Incidents", "active_incidents"), ("Critical Incidents", "critical_incidents"),
        ("Unique IPs", "unique_ips"), ("Last 24 Hours", "last_24h"),
    ]
    cells = []
    for label, key in labels:
        cells.append([Paragraph(label.upper(), KPI_LABEL), Paragraph(str(summary.get(key, 0)), KPI_VALUE)])
    # arrange into 3 columns x 2 rows of mini-tables
    boxes = [Table([[c[0]], [c[1]]], colWidths=[52 * mm]) for c in cells]
    for b in boxes:
        b.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), ZEBRA),
            ("BOX", (0, 0), (-1, -1), 0.5, LINE),
            ("LINEBEFORE", (0, 0), (0, -1), 2, ACCENT),
            ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
    grid = Table([[boxes[0], boxes[1], boxes[2]], [boxes[3], boxes[4], boxes[5]]],
                 colWidths=[57 * mm] * 3)
    grid.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return grid


def _data_table(header: List[str], rows: List[List[Any]], col_widths: List[float]) -> Table:
    body = [[Paragraph(str(h).upper(), ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=8, textColor=colors.white)) for h in header]]
    for r in rows:
        body.append([Paragraph(str(c), CELL) for c in r])
    t = Table(body, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ZEBRA]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    t.setStyle(TableStyle(style))
    return t


def _sev_badge(severity: str) -> Paragraph:
    color = SEV_COLORS.get((severity or "").lower(), MUTED)
    return Paragraph(f'<font color="{color.hexval()}"><b>{(severity or "").upper()}</b></font>', CELL)


# ---------------- report renderers ----------------

def executive_pdf(data: Dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    doc = _doc(buf, data["meta"])
    e = []
    e.append(Paragraph("Key Performance Indicators", SECTION))
    e.append(_kpi_grid(data["summary"]))
    e.append(Spacer(1, 6))

    e.append(Paragraph("Top Source Countries", SECTION))
    rows = [[c["value"] or "Unknown", c["count"]] for c in data["top_countries"]]
    e.append(_data_table(["Country", "Attacks"], rows or [["No data", 0]], [120 * mm, 54 * mm]))

    e.append(Paragraph("Top MITRE ATT&CK Techniques", SECTION))
    rows = [[t["id"], t["name"], t["tactic"], t["count"]] for t in data["top_mitre"]]
    e.append(_data_table(["ID", "Technique", "Tactic", "Count"], rows or [["—", "No data", "", 0]],
                         [22 * mm, 78 * mm, 52 * mm, 22 * mm]))
    doc.build(e)
    return buf.getvalue()


def threats_pdf(data: Dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    doc = _doc(buf, data["meta"])
    e = []

    def kv_section(title, items, c1):
        e.append(Paragraph(title, SECTION))
        rows = [[it["value"] or "—", it["count"]] for it in items]
        e.append(_data_table([c1, "Count"], rows or [["No data", 0]], [120 * mm, 54 * mm]))

    kv_section("Top Usernames", data["top_usernames"], "Username")
    kv_section("Top Passwords", data["top_passwords"], "Password")
    kv_section("Top Source IPs", data["top_source_ips"], "Source IP")

    e.append(Paragraph("Attack Trends — Last 24 Hours", SECTION))
    trends = data["attack_trends"]
    peak = max((b["count"] for b in trends), default=0)
    rows = []
    for b in trends:
        bar = "█" * int((b["count"] / peak) * 30) if peak else ""
        rows.append([b["label"], b["count"], bar])
    e.append(_data_table(["Hour (UTC)", "Attacks", "Distribution"], rows,
                         [28 * mm, 22 * mm, 124 * mm]))
    doc.build(e)
    return buf.getvalue()


def incidents_pdf(data: Dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    doc = _doc(buf, data["meta"])
    e = []
    e.append(Paragraph(f"Incident Report — {data['incident_count']} incident(s)", SECTION))
    e.append(Paragraph("Ordered by peak risk score. Each entry includes severity, MITRE techniques, "
                       "detected behaviors and the activity timeline.", BODY))
    e.append(Spacer(1, 4))

    for inc in data["incidents"]:
        mitre = ", ".join(f"{t['id']} ({t['name']})" for t in inc["mitre"]) or "—"
        behaviors = ", ".join(inc["behaviors"]) or "—"
        header = Table([[
            Paragraph(f"<b>Incident #{inc['id']}</b> — {inc['source_ip']} "
                      f"({inc['country'] or 'Unknown'})", CELL),
            _sev_badge(inc["severity"]),
            Paragraph(f"<b>Risk {inc['risk_score']}</b>", CELL),
        ]], colWidths=[112 * mm, 32 * mm, 30 * mm])
        header.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), ZEBRA),
            ("LINEBELOW", (0, 0), (-1, -1), 1, ACCENT),
            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("ALIGN", (1, 0), (2, 0), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        e.append(header)

        detail_rows = [
            [Paragraph("<b>Status</b>", CELL_MUTED), Paragraph(str(inc["status"]), CELL),
             Paragraph("<b>Attempts</b>", CELL_MUTED), Paragraph(str(inc["attempt_count"]), CELL)],
            [Paragraph("<b>First Seen</b>", CELL_MUTED), Paragraph(_fmt_dt(inc["timeline"]["first_seen"]), CELL),
             Paragraph("<b>Last Seen</b>", CELL_MUTED), Paragraph(_fmt_dt(inc["timeline"]["last_seen"]), CELL)],
            [Paragraph("<b>MITRE</b>", CELL_MUTED), Paragraph(mitre, CELL), "", ""],
            [Paragraph("<b>Behaviors</b>", CELL_MUTED), Paragraph(behaviors, CELL), "", ""],
        ]
        dt = Table(detail_rows, colWidths=[24 * mm, 62 * mm, 24 * mm, 64 * mm])
        dt.setStyle(TableStyle([
            ("SPAN", (1, 2), (3, 2)), ("SPAN", (1, 3), (3, 3)),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ]))
        e.append(dt)
        e.append(Spacer(1, 8))

    if not data["incidents"]:
        e.append(Paragraph("No incidents recorded.", BODY))
    doc.build(e)
    return buf.getvalue()


PDF_RENDERERS = {
    "executive": executive_pdf,
    "threats": threats_pdf,
    "incidents": incidents_pdf,
}
