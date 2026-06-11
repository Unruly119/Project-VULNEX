# src/report_generator.py  — ISO/IEC 27001 PDF Report
# ใช้ reportlab เท่านั้น (pip install reportlab)

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from datetime import datetime
import os, io

# ── สี ISO/Corporate ────────────────────────────────────────────
C_NAVY   = colors.HexColor("#0a2342")
C_STEEL  = colors.HexColor("#1e4d8c")
C_CYAN   = colors.HexColor("#0ea5e9")
C_LIME   = colors.HexColor("#16a34a")
C_AMBER  = colors.HexColor("#d97706")
C_RED    = colors.HexColor("#dc2626")
C_CRIT   = colors.HexColor("#7f1d1d")
C_LGRAY  = colors.HexColor("#f8fafc")
C_MGRAY  = colors.HexColor("#e2e8f0")
C_DGRAY  = colors.HexColor("#475569")
C_BLACK  = colors.HexColor("#0f172a")
C_WHITE  = colors.white

SEV_COLOR = {
    "CRITICAL": C_CRIT,
    "HIGH":     C_RED,
    "MEDIUM":   C_AMBER,
    "LOW":      C_LIME,
    "INFO":     C_STEEL,
}

# ── Font setup ──────────────────────────────────────────────────
def _setup_fonts():
    """ลงทะเบียน font ที่รองรับภาษาไทย"""
    candidates = [
        "/usr/share/fonts/truetype/tlwg/Sarabun.ttf",
        "/usr/share/fonts/truetype/thai-scalable/Sarabun.ttf",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "C:/Windows/Fonts/THSarabunNew.ttf",
        "C:/Windows/Fonts/Tahoma.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                pdfmetrics.registerFont(TTFont("ThaiFont", path))
                pdfmetrics.registerFont(TTFont("ThaiFontBold", path))
                return "ThaiFont"
            except Exception:
                continue
    return "Helvetica"   # fallback (ไม่รองรับไทย แต่ไม่ crash)

# ── Styles ──────────────────────────────────────────────────────
def _build_styles(base_font):
    bold_font = base_font  # ใช้ font เดิมชั่วคราว
    s = getSampleStyleSheet()

    styles = {
        "cover_title": ParagraphStyle("cover_title",
            fontName=bold_font, fontSize=22, leading=28,
            textColor=C_WHITE, alignment=TA_CENTER, spaceAfter=6),
        "cover_sub": ParagraphStyle("cover_sub",
            fontName=base_font, fontSize=12, leading=18,
            textColor=colors.HexColor("#93c5fd"), alignment=TA_CENTER),
        "cover_meta": ParagraphStyle("cover_meta",
            fontName=base_font, fontSize=9, leading=13,
            textColor=colors.HexColor("#bfdbfe"), alignment=TA_CENTER),
        "h1": ParagraphStyle("h1",
            fontName=bold_font, fontSize=14, leading=18,
            textColor=C_NAVY, spaceBefore=16, spaceAfter=6,
            borderPad=4, leftIndent=0),
        "h2": ParagraphStyle("h2",
            fontName=bold_font, fontSize=11, leading=15,
            textColor=C_STEEL, spaceBefore=12, spaceAfter=4),
        "h3": ParagraphStyle("h3",
            fontName=bold_font, fontSize=10, leading=13,
            textColor=C_DGRAY, spaceBefore=8, spaceAfter=3),
        "body": ParagraphStyle("body",
            fontName=base_font, fontSize=9, leading=14,
            textColor=C_BLACK, spaceAfter=4, alignment=TA_JUSTIFY),
        "body_sm": ParagraphStyle("body_sm",
            fontName=base_font, fontSize=8, leading=12,
            textColor=C_DGRAY, spaceAfter=3),
        "mono": ParagraphStyle("mono",
            fontName="Courier", fontSize=8, leading=12,
            textColor=C_NAVY, backColor=C_LGRAY,
            leftIndent=8, rightIndent=8, spaceAfter=4),
        "label": ParagraphStyle("label",
            fontName=bold_font, fontSize=8, leading=11,
            textColor=C_WHITE),
        "cell": ParagraphStyle("cell",
            fontName=base_font, fontSize=8, leading=12,
            textColor=C_BLACK),
        "cell_bold": ParagraphStyle("cell_bold",
            fontName=bold_font, fontSize=8, leading=12,
            textColor=C_BLACK),
        "footer": ParagraphStyle("footer",
            fontName=base_font, fontSize=7, leading=10,
            textColor=C_DGRAY, alignment=TA_CENTER),
        "toc": ParagraphStyle("toc",
            fontName=base_font, fontSize=9, leading=14,
            textColor=C_STEEL, leftIndent=12, spaceAfter=3),
    }
    return styles

# ── Helper drawables ────────────────────────────────────────────
def _rule(color=C_MGRAY, thickness=0.5):
    return HRFlowable(width="100%", thickness=thickness,
                      color=color, spaceAfter=6, spaceBefore=4)

def _sev_badge_style(sev):
    c = SEV_COLOR.get(sev, C_STEEL)
    return [
        ("BACKGROUND", (0,0), (-1,-1), c),
        ("TEXTCOLOR",  (0,0), (-1,-1), C_WHITE),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("FONTSIZE",   (0,0), (-1,-1), 7),
        ("TOPPADDING", (0,0), (-1,-1), 2),
        ("BOTTOMPADDING",(0,0),(-1,-1),2),
        ("LEFTPADDING", (0,0),(-1,-1),4),
        ("RIGHTPADDING",(0,0),(-1,-1),4),
    ]

# ── Score color ─────────────────────────────────────────────────
def _score_color(score):
    if score >= 70: return C_LIME
    if score >= 40: return C_AMBER
    return C_RED

# ── Cover page ──────────────────────────────────────────────────
def _cover(story, styles, scan_data, ai_data, org_name):
    score = ai_data.get("score", 0)
    risk  = ai_data.get("risk_level", "HIGH")
    url   = scan_data.get("url", "")
    now   = datetime.now()

    # Navy background header via Table
    cover_data = [[
        Paragraph("INFORMATION SECURITY ASSESSMENT REPORT", styles["cover_title"])
    ]]
    cover_tbl = Table(cover_data, colWidths=[17*cm])
    cover_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0,0),(-1,-1), C_NAVY),
        ("TOPPADDING",  (0,0),(-1,-1), 28),
        ("BOTTOMPADDING",(0,0),(-1,-1),28),
        ("LEFTPADDING", (0,0),(-1,-1), 16),
        ("RIGHTPADDING",(0,0),(-1,-1), 16),
    ]))
    story.append(cover_tbl)
    story.append(Spacer(1, 0.4*cm))

    # Sub title strip
    sub_data = [[
        Paragraph("Website Vulnerability Assessment | Passive Security Scan", styles["cover_sub"])
    ]]
    sub_tbl = Table(sub_data, colWidths=[17*cm])
    sub_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0,0),(-1,-1), C_STEEL),
        ("TOPPADDING",  (0,0),(-1,-1), 8),
        ("BOTTOMPADDING",(0,0),(-1,-1),8),
    ]))
    story.append(sub_tbl)
    story.append(Spacer(1, 1.0*cm))

    # Score box
    sc_color = _score_color(score)
    score_data = [[
        Paragraph(f"<b>{score}</b>", ParagraphStyle("sc",
            fontName="Helvetica-Bold", fontSize=40, textColor=sc_color,
            alignment=TA_CENTER)),
        "",
        Paragraph(
            f"<b>Security Score</b><br/>Risk Level: <b>{risk}</b><br/>"
            f"<font size='8'>เกณฑ์: 70+ ปลอดภัย | 40-69 พอใช้ | &lt;40 อันตราย</font>",
            ParagraphStyle("scl", fontName="Helvetica", fontSize=10,
                           textColor=C_NAVY, leading=16)),
    ]]
    score_tbl = Table(score_data, colWidths=[4*cm, 0.5*cm, 12.5*cm])
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(0,0), colors.HexColor("#f8fafc")),
        ("BOX",        (0,0),(0,0), 1.5, sc_color),
        ("ALIGN",      (0,0),(0,0), "CENTER"),
        ("VALIGN",     (0,0),(-1,-1),"MIDDLE"),
        ("TOPPADDING", (0,0),(0,0), 10),
        ("BOTTOMPADDING",(0,0),(0,0),10),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 0.8*cm))

    # Meta table
    meta_rows = [
        ["Target URL",        url],
        ["Organization",      org_name],
        ["Assessment Date",   now.strftime("%d %B %Y  %H:%M")],
        ["Report Reference",  f"PTCShield-{now.strftime('%Y%m%d%H%M')}"],
        ["Standard",          "ISO/IEC 27001:2022 — Control A.8.8 (Technical Vulnerability)"],
        ["Classification",    "CONFIDENTIAL — For Authorized Personnel Only"],
        ["Tool",              "PTC AI Web Shield v1.0 — Passive Scan (No Active Attack)"],
    ]
    meta_tbl = Table(meta_rows, colWidths=[5*cm, 12*cm])
    meta_tbl.setStyle(TableStyle([
        ("FONTNAME",   (0,0),(0,-1), "Helvetica-Bold"),
        ("FONTNAME",   (1,0),(1,-1), "Helvetica"),
        ("FONTSIZE",   (0,0),(-1,-1), 8.5),
        ("TEXTCOLOR",  (0,0),(0,-1), C_NAVY),
        ("TEXTCOLOR",  (1,0),(1,-1), C_BLACK),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[C_LGRAY, C_WHITE]),
        ("TOPPADDING", (0,0),(-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("LEFTPADDING",(0,0),(-1,-1), 8),
        ("GRID",       (0,0),(-1,-1), 0.3, C_MGRAY),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 0.6*cm))

    # Disclaimer
    disc = ("This report was generated using passive scanning techniques only. "
            "No active attacks, payload injection, or intrusive testing were performed. "
            "Findings are based on publicly observable HTTP headers, SSL certificate data, "
            "and HTML content. This report is intended to support ISO/IEC 27001 Annex A.8.8 "
            "Technical Vulnerability Management review.")
    story.append(Paragraph(disc, styles["body_sm"]))
    story.append(PageBreak())

# ── Executive Summary ────────────────────────────────────────────
def _exec_summary(story, styles, scan_data, ai_data, server_data):
    story.append(Paragraph("1. EXECUTIVE SUMMARY", styles["h1"]))
    story.append(_rule(C_NAVY, 1.5))

    score    = ai_data.get("score", 0)
    risk     = ai_data.get("risk_level", "HIGH")
    url      = scan_data.get("url","")
    n_miss   = len(scan_data.get("headers",{}).get("headers_missing",[]))
    ssl_ok   = scan_data.get("ssl",{}).get("valid", False)
    days     = scan_data.get("ssl",{}).get("days_left", 0)
    vulns    = server_data.get("vulnerabilities", [])
    n_cve    = len(vulns)
    stype    = server_data.get("server_type","unknown").upper()
    sver     = server_data.get("server_version","N/A")
    dos      = server_data.get("dos_risk", False)

    summary_rows = [
        ["Metric", "Value", "Status"],
        ["Security Score",          f"{score}/100",              "CRITICAL" if score<40 else ("MEDIUM" if score<70 else "PASS")],
        ["Overall Risk Level",      risk,                        risk],
        ["Security Headers Missing",f"{n_miss} headers",        "FAIL" if n_miss>2 else ("WARN" if n_miss>0 else "PASS")],
        ["SSL/TLS Certificate",     "Valid" if ssl_ok else "INVALID", "PASS" if ssl_ok else "FAIL"],
        ["SSL Days Remaining",      f"{days} days",              "WARN" if 0<days<=30 else ("FAIL" if days<=0 else "PASS")],
        ["Web Server",              f"{stype} {sver}",           "WARN" if sver else "INFO"],
        ["Known CVEs Found",        str(n_cve),                  "FAIL" if n_cve>0 else "PASS"],
        ["HTTP/2 DoS Risk",         "YES — CVE-2023-44487" if dos else "No", "FAIL" if dos else "PASS"],
    ]

    status_colors = {"CRITICAL":C_CRIT,"FAIL":C_RED,"WARN":C_AMBER,"PASS":C_LIME,"MEDIUM":C_AMBER,"HIGH":C_RED,"INFO":C_STEEL}

    tbl_style = [
        ("BACKGROUND",  (0,0),(-1,0),   C_NAVY),
        ("TEXTCOLOR",   (0,0),(-1,0),   C_WHITE),
        ("FONTNAME",    (0,0),(-1,0),   "Helvetica-Bold"),
        ("FONTNAME",    (0,1),(1,-1),   "Helvetica-Bold"),
        ("FONTNAME",    (1,1),(1,-1),   "Helvetica"),
        ("FONTSIZE",    (0,0),(-1,-1),  8.5),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_LGRAY, C_WHITE]),
        ("TOPPADDING",  (0,0),(-1,-1),  5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ("LEFTPADDING", (0,0),(-1,-1),  8),
        ("GRID",        (0,0),(-1,-1),  0.3, C_MGRAY),
        ("ALIGN",       (2,0),(2,-1),   "CENTER"),
        ("VALIGN",      (0,0),(-1,-1),  "MIDDLE"),
    ]
    # Color status cells
    for i, row in enumerate(summary_rows[1:], 1):
        st = row[2]
        c  = status_colors.get(st, C_STEEL)
        tbl_style.append(("BACKGROUND", (2,i),(2,i), c))
        tbl_style.append(("TEXTCOLOR",  (2,i),(2,i), C_WHITE))
        tbl_style.append(("FONTNAME",   (2,i),(2,i), "Helvetica-Bold"))

    t = Table(summary_rows, colWidths=[6.5*cm, 7*cm, 3.5*cm])
    t.setStyle(TableStyle(tbl_style))
    story.append(t)
    story.append(Spacer(1, 0.4*cm))

    # ISO control reference
    story.append(Paragraph("ISO/IEC 27001:2022 Control Reference", styles["h2"]))
    iso_rows = [
        ["Control",   "Title",                                  "Relevance"],
        ["A.8.8",     "Management of technical vulnerabilities","Known CVE detection"],
        ["A.8.23",    "Web filtering",                          "HTTP security headers"],
        ["A.8.26",    "Application security requirements",      "TLS/SSL configuration"],
        ["A.8.9",     "Configuration management",               "Server version disclosure"],
        ["A.5.30",    "ICT readiness for business continuity",  "DoS vulnerability (HTTP/2)"],
    ]
    it = Table(iso_rows, colWidths=[2.5*cm, 9*cm, 5.5*cm])
    it.setStyle(TableStyle([
        ("BACKGROUND",  (0,0),(-1,0),  C_STEEL),
        ("TEXTCOLOR",   (0,0),(-1,0),  C_WHITE),
        ("FONTNAME",    (0,0),(-1,0),  "Helvetica-Bold"),
        ("FONTNAME",    (0,1),(-1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0),(-1,-1), 8),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_LGRAY,C_WHITE]),
        ("GRID",        (0,0),(-1,-1), 0.3, C_MGRAY),
        ("TOPPADDING",  (0,0),(-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LEFTPADDING", (0,0),(-1,-1), 6),
        ("VALIGN",      (0,0),(-1,-1), "MIDDLE"),
    ]))
    story.append(it)
    story.append(PageBreak())

# ── Section 2: Technical Findings ───────────────────────────────
def _technical_findings(story, styles, scan_data, server_data):
    story.append(Paragraph("2. TECHNICAL FINDINGS", styles["h1"]))
    story.append(_rule(C_NAVY, 1.5))

    # 2.1 Web Server Analysis
    story.append(Paragraph("2.1 Web Server Analysis (A.8.8, A.8.9)", styles["h2"]))
    sraw  = server_data.get("server_raw","Not disclosed")
    stype = server_data.get("server_type","unknown")
    sver  = server_data.get("server_version","")
    http_v= server_data.get("http_version","Unknown")
    h2    = server_data.get("h2_enabled", False)
    exposed = server_data.get("version_exposed", False)
    dos   = server_data.get("dos_risk", False)

    ws_rows = [
        ["Parameter",           "Value",            "Finding",       "Risk"],
        ["Server Header",       sraw or "Hidden",   "Version " + ("EXPOSED" if exposed else "hidden"), "LOW" if exposed else "PASS"],
        ["Server Type",         stype.upper(),      "Detected",      "INFO"],
        ["Server Version",      sver or "N/A",      "Exposed" if exposed else "Concealed", "LOW" if exposed else "PASS"],
        ["HTTP Version",        http_v,             "HTTP/2 enabled" if h2 else "HTTP/1.1 only", "WARN" if h2 else "INFO"],
        ["HTTP/2 DoS Risk",     "YES" if dos else "No", "CVE-2023-44487" if dos else "N/A", "HIGH" if dos else "PASS"],
    ]
    risk_col_colors = {"HIGH":C_RED,"CRITICAL":C_CRIT,"MEDIUM":C_AMBER,"LOW":colors.HexColor("#ca8a04"),"PASS":C_LIME,"INFO":C_STEEL,"WARN":C_AMBER}
    ws_style = [
        ("BACKGROUND",  (0,0),(-1,0),  C_NAVY),
        ("TEXTCOLOR",   (0,0),(-1,0),  C_WHITE),
        ("FONTNAME",    (0,0),(-1,0),  "Helvetica-Bold"),
        ("FONTNAME",    (0,1),(-1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0),(-1,-1), 8),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_LGRAY,C_WHITE]),
        ("GRID",        (0,0),(-1,-1), 0.3, C_MGRAY),
        ("TOPPADDING",  (0,0),(-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LEFTPADDING", (0,0),(-1,-1), 6),
        ("VALIGN",      (0,0),(-1,-1), "MIDDLE"),
        ("ALIGN",       (3,0),(3,-1),  "CENTER"),
    ]
    for i, row in enumerate(ws_rows[1:], 1):
        c = risk_col_colors.get(row[3], C_STEEL)
        ws_style += [
            ("BACKGROUND",(3,i),(3,i),c),
            ("TEXTCOLOR", (3,i),(3,i),C_WHITE),
            ("FONTNAME",  (3,i),(3,i),"Helvetica-Bold"),
        ]
    wt = Table(ws_rows, colWidths=[4.5*cm, 5*cm, 5*cm, 2.5*cm])
    wt.setStyle(TableStyle(ws_style))
    story.append(wt)
    story.append(Spacer(1, 0.3*cm))

    # Version disclosure explanation
    if exposed:
        story.append(Paragraph(
            "<b>Finding WS-01 — Server Version Disclosure (Low Risk)</b><br/>"
            f"Server header value: <i>{sraw}</i><br/>"
            "การเปิดเผย version ของ web server ทำให้ผู้โจมตีทราบว่าควรใช้ exploit ใด "
            "แม้ความเสี่ยงจะต่ำแต่เป็น Information Disclosure ที่ควรแก้ไข<br/>"
            "<b>Remediation:</b> ซ่อน Server header ใน nginx: <font name='Courier'>server_tokens off;</font> | "
            "ใน Apache: <font name='Courier'>ServerTokens Prod; ServerSignature Off;</font>",
            styles["body"]))

    # 2.2 HTTP/2 DoS
    if dos:
        story.append(Spacer(1, 0.2*cm))
        dos_data = [[
            Paragraph("<b>CRITICAL FINDING — CVE-2023-44487: HTTP/2 Rapid Reset DoS</b>", styles["label"])
        ]]
        dos_tbl = Table(dos_data, colWidths=[17*cm])
        dos_tbl.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),C_CRIT),
            ("TOPPADDING",(0,0),(-1,-1),8),
            ("BOTTOMPADDING",(0,0),(-1,-1),8),
            ("LEFTPADDING",(0,0),(-1,-1),10),
        ]))
        story.append(dos_tbl)
        detail = server_data.get("dos_detail","")
        story.append(Paragraph(
            f"<b>Description:</b> HTTP/2 Rapid Reset Attack ใช้ stream cancellation ซ้ำๆ เพื่อทำให้ server "
            f"ประมวลผลล้น เป็น Zero-day ที่ถูกใช้โจมตีในป่าในเดือนกันยายน–ตุลาคม 2566 "
            f"มีผลกระทบต่อ nginx เวอร์ชัน &lt; 1.25.3 ที่เปิดใช้ HTTP/2<br/>"
            f"<b>Detail:</b> {detail}<br/>"
            f"<b>CVSS Score:</b> 7.5 (High)<br/>"
            f"<b>ISO Control:</b> A.5.30 — ICT readiness for business continuity<br/>"
            f"<b>Immediate Action:</b> อัปเกรด nginx เป็น 1.25.3+ หรือเพิ่ม "
            f"<font name='Courier'>limit_conn</font> และ <font name='Courier'>limit_req</font> "
            f"เป็นมาตรการชั่วคราว",
            styles["body"]))

    story.append(Spacer(1, 0.4*cm))

    # 2.3 Security Headers
    story.append(Paragraph("2.2 Security HTTP Headers Analysis (A.8.23, A.8.26)", styles["h2"]))
    headers_found   = scan_data.get("headers",{}).get("headers_found",{})
    headers_missing = scan_data.get("headers",{}).get("headers_missing",[])
    hdr_score       = scan_data.get("headers",{}).get("score",0)

    hdr_def = {
        "Content-Security-Policy":   ("CRITICAL","ป้องกัน XSS Attack","A.8.26"),
        "Strict-Transport-Security": ("HIGH",    "บังคับ HTTPS","A.8.26"),
        "X-Frame-Options":           ("HIGH",    "ป้องกัน Clickjacking","A.8.23"),
        "X-Content-Type-Options":    ("MEDIUM",  "ป้องกัน MIME Sniffing","A.8.23"),
        "Referrer-Policy":           ("LOW",     "ควบคุม Referrer Info","A.8.9"),
        "Permissions-Policy":        ("LOW",     "จำกัด Browser APIs","A.8.26"),
    }
    hdr_rows = [["Header","Status","Severity","Purpose","ISO Control"]]
    for hdr, (sev, purpose, ctrl) in hdr_def.items():
        present = hdr in headers_found
        hdr_rows.append([
            hdr, "PRESENT" if present else "MISSING",
            "" if present else sev, purpose, ctrl
        ])

    hdr_style = [
        ("BACKGROUND",  (0,0),(-1,0), C_NAVY),
        ("TEXTCOLOR",   (0,0),(-1,0), C_WHITE),
        ("FONTNAME",    (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTNAME",    (0,1),(-1,-1),"Helvetica"),
        ("FONTSIZE",    (0,0),(-1,-1), 7.5),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_LGRAY,C_WHITE]),
        ("GRID",        (0,0),(-1,-1), 0.3, C_MGRAY),
        ("TOPPADDING",  (0,0),(-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LEFTPADDING", (0,0),(-1,-1), 5),
        ("VALIGN",      (0,0),(-1,-1),"MIDDLE"),
        ("ALIGN",       (1,0),(2,-1), "CENTER"),
    ]
    for i, row in enumerate(hdr_rows[1:], 1):
        if row[1] == "PRESENT":
            hdr_style += [("BACKGROUND",(1,i),(1,i),C_LIME),("TEXTCOLOR",(1,i),(1,i),C_WHITE),("FONTNAME",(1,i),(1,i),"Helvetica-Bold")]
        elif row[1] == "MISSING":
            hdr_style += [("BACKGROUND",(1,i),(1,i),C_RED),("TEXTCOLOR",(1,i),(1,i),C_WHITE),("FONTNAME",(1,i),(1,i),"Helvetica-Bold")]
            sev = row[2]
            c = SEV_COLOR.get(sev, C_STEEL)
            hdr_style += [("BACKGROUND",(2,i),(2,i),c),("TEXTCOLOR",(2,i),(2,i),C_WHITE),("FONTNAME",(2,i),(2,i),"Helvetica-Bold")]

    ht = Table(hdr_rows, colWidths=[5.5*cm, 2.2*cm, 2.2*cm, 4.3*cm, 2.8*cm])
    ht.setStyle(TableStyle(hdr_style))
    story.append(ht)
    story.append(Paragraph(f"Headers Score: {hdr_score}/100", styles["body_sm"]))
    story.append(PageBreak())

# ── Section 3: SSL ───────────────────────────────────────────────
def _ssl_section(story, styles, scan_data):
    story.append(Paragraph("3. SSL/TLS CERTIFICATE ANALYSIS (A.8.26)", styles["h1"]))
    story.append(_rule(C_NAVY, 1.5))

    ssl = scan_data.get("ssl", {})
    rows = [
        ["Parameter",          "Value",                          "Assessment"],
        ["HTTPS Enabled",      "Yes" if ssl.get("has_ssl") else "No",    "PASS" if ssl.get("has_ssl") else "FAIL"],
        ["Certificate Valid",  "Valid" if ssl.get("valid") else "INVALID","PASS" if ssl.get("valid") else "FAIL"],
        ["Expiry Date",        ssl.get("expires","N/A"),         "INFO"],
        ["Days Remaining",     str(ssl.get("days_left",0)),      "WARN" if 0<ssl.get("days_left",0)<=30 else ("FAIL" if ssl.get("days_left",0)<=0 else "PASS")],
        ["Certificate Issuer", ssl.get("issuer","Unknown"),      "INFO"],
        ["Warning",            ssl.get("warning","None"),        "WARN" if ssl.get("warning") else "PASS"],
    ]
    rc = {"PASS":C_LIME,"FAIL":C_RED,"WARN":C_AMBER,"INFO":C_STEEL}
    ssl_style = [
        ("BACKGROUND",(0,0),(-1,0),C_NAVY),("TEXTCOLOR",(0,0),(-1,0),C_WHITE),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTNAME",(0,1),(-1,-1),"Helvetica"),
        ("FONTSIZE",(0,0),(-1,-1),8.5),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_LGRAY,C_WHITE]),
        ("GRID",(0,0),(-1,-1),0.3,C_MGRAY),
        ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("LEFTPADDING",(0,0),(-1,-1),8),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ALIGN",(2,0),(2,-1),"CENTER"),
    ]
    for i, row in enumerate(rows[1:], 1):
        c = rc.get(row[2], C_STEEL)
        ssl_style += [("BACKGROUND",(2,i),(2,i),c),("TEXTCOLOR",(2,i),(2,i),C_WHITE),("FONTNAME",(2,i),(2,i),"Helvetica-Bold")]
    st = Table(rows, colWidths=[5*cm, 8*cm, 4*cm])
    st.setStyle(TableStyle(ssl_style))
    story.append(st)
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "<b>ISO/IEC 27001 A.8.26 Note:</b> TLS 1.2+ ควรเป็น minimum requirement "
        "ควรปิด TLS 1.0 และ TLS 1.1 และตั้งค่า cipher suite ที่รองรับ Perfect Forward Secrecy (PFS) "
        "การใช้ Let's Encrypt ควรมีระบบ auto-renew เพื่อป้องกัน cert หมดอายุ",
        styles["body"]))
    story.append(PageBreak())

# ── Section 4: CVE ───────────────────────────────────────────────
def _cve_section(story, styles, server_data):
    story.append(Paragraph("4. CVE VULNERABILITY REPORT (A.8.8)", styles["h1"]))
    story.append(_rule(C_NAVY, 1.5))

    vulns = server_data.get("vulnerabilities", [])
    if not vulns:
        story.append(Paragraph("✅ ไม่พบ CVE ที่ทราบสำหรับ web server version นี้", styles["body"]))
        story.append(PageBreak())
        return

    for i, v in enumerate(vulns, 1):
        sev = v.get("severity","INFO")
        c   = SEV_COLOR.get(sev, C_STEEL)

        # CVE header bar
        cve_hdr = [[Paragraph(f"CVE #{i}: {v.get('cve','N/A')}  |  Severity: {sev}", styles["label"])]]
        ct = Table(cve_hdr, colWidths=[17*cm])
        ct.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),c),
            ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
            ("LEFTPADDING",(0,0),(-1,-1),10),
        ]))
        story.append(ct)

        detail_rows = [
            ["CVE ID",      v.get("cve","N/A")],
            ["Severity",    sev],
            ["Description", v.get("desc","")],
            ["Remediation", v.get("fix","")],
            ["ISO Control", "A.8.8 — Management of Technical Vulnerabilities"],
            ["Action",      "Immediate patch required" if sev in ("CRITICAL","HIGH") else "Schedule patch in next maintenance window"],
        ]
        dt = Table(detail_rows, colWidths=[4*cm, 13*cm])
        dt.setStyle(TableStyle([
            ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
            ("FONTNAME",(1,0),(1,-1),"Helvetica"),
            ("FONTSIZE",(0,0),(-1,-1),8.5),
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[C_LGRAY,C_WHITE]),
            ("GRID",(0,0),(-1,-1),0.3,C_MGRAY),
            ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
            ("LEFTPADDING",(0,0),(-1,-1),8),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ]))
        story.append(dt)
        story.append(Spacer(1, 0.3*cm))

    story.append(PageBreak())

# ── Section 5: AI Analysis ───────────────────────────────────────
def _ai_section(story, styles, ai_data):
    story.append(Paragraph("5. AI-ASSISTED ANALYSIS (Gemini 2.0)", styles["h1"]))
    story.append(_rule(C_NAVY, 1.5))
    story.append(Paragraph(
        "ผลวิเคราะห์ต่อไปนี้สร้างโดย Google Gemini 2.0 Flash จากข้อมูล passive scan "
        "โดยผ่าน prompt engineering ที่ออกแบบเฉพาะสำหรับบริบทความปลอดภัยเว็บไซต์สถานศึกษาไทย",
        styles["body"]))
    story.append(Spacer(1, 0.2*cm))

    analysis = ai_data.get("analysis","ไม่มีข้อมูล")
    # split by ## sections
    for line in analysis.split("\n"):
        line = line.strip()
        if not line:
            story.append(Spacer(1, 0.15*cm))
        elif line.startswith("## "):
            story.append(Paragraph(line[3:], styles["h2"]))
        elif line.startswith("# "):
            story.append(Paragraph(line[2:], styles["h1"]))
        elif line.startswith("- ") or line.startswith("• "):
            story.append(Paragraph("• " + line[2:], ParagraphStyle("bul",
                fontName="Helvetica", fontSize=9, leading=13,
                leftIndent=14, spaceAfter=2, textColor=C_BLACK)))
        elif line.startswith("**") and line.endswith("**"):
            story.append(Paragraph(f"<b>{line[2:-2]}</b>", styles["body"]))
        else:
            story.append(Paragraph(line, styles["body"]))

    story.append(PageBreak())

# ── Section 6: Remediation Plan ─────────────────────────────────
def _remediation(story, styles, scan_data, server_data):
    story.append(Paragraph("6. REMEDIATION PLAN & TIMELINE", styles["h1"]))
    story.append(_rule(C_NAVY, 1.5))

    vulns    = server_data.get("vulnerabilities",[])
    missing  = scan_data.get("headers",{}).get("headers_missing",[])
    ssl_warn = scan_data.get("ssl",{}).get("warning","")
    dos      = server_data.get("dos_risk",False)

    items = []
    priority = 1

    if dos:
        items.append((priority, "CRITICAL", "HTTP/2 DoS Vulnerability",
                      "อัปเกรด nginx เป็น 1.25.3+ หรือเพิ่ม limit_conn/limit_req",
                      "Immediate (24h)", "A.5.30, A.8.8"))
        priority+=1

    for v in vulns:
        if v["severity"] in ("CRITICAL","HIGH"):
            items.append((priority, v["severity"], v["cve"],
                          v.get("fix","Patch immediately"), "Immediate (24-72h)", "A.8.8"))
            priority+=1

    if "Content-Security-Policy" in missing:
        items.append((priority,"HIGH","Missing Content-Security-Policy",
                      "เพิ่ม CSP header ใน nginx/Apache config หรือ meta tag",
                      "Short-term (1 week)","A.8.26"))
        priority+=1
    if "X-Frame-Options" in missing:
        items.append((priority,"HIGH","Missing X-Frame-Options",
                      "เพิ่ม Header: X-Frame-Options: DENY หรือ SAMEORIGIN",
                      "Short-term (1 week)","A.8.23"))
        priority+=1
    if "Strict-Transport-Security" in missing:
        items.append((priority,"MEDIUM","Missing HSTS",
                      "เพิ่ม Strict-Transport-Security: max-age=31536000; includeSubDomains",
                      "Short-term (1 week)","A.8.26"))
        priority+=1
    for h in ["X-Content-Type-Options","Referrer-Policy","Permissions-Policy"]:
        if h in missing:
            items.append((priority,"LOW",f"Missing {h}",
                          f"เพิ่ม {h} header ตามค่า recommended",
                          "Medium-term (1 month)","A.8.23"))
            priority+=1
    if ssl_warn:
        items.append((priority,"MEDIUM","SSL Certificate Expiry Warning",
                      "ต่ออายุ SSL certificate และตั้งระบบ auto-renew",
                      "Short-term (this week)","A.8.26"))
        priority+=1
    if server_data.get("version_exposed"):
        items.append((priority,"LOW","Server Version Disclosure",
                      "ซ่อน Server header (server_tokens off; / ServerTokens Prod)",
                      "Medium-term (1 month)","A.8.9"))
        priority+=1

    if not items:
        story.append(Paragraph("✅ ไม่พบรายการที่ต้องแก้ไขเร่งด่วน", styles["body"]))
        story.append(PageBreak())
        return

    rows = [["#","Priority","Finding","Remediation Action","Timeline","ISO Control"]]
    for item in items:
        rows.append(list(item))

    rem_style = [
        ("BACKGROUND",(0,0),(-1,0),C_NAVY),("TEXTCOLOR",(0,0),(-1,0),C_WHITE),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTNAME",(0,1),(-1,-1),"Helvetica"),
        ("FONTSIZE",(0,0),(-1,-1),7.5),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_LGRAY,C_WHITE]),
        ("GRID",(0,0),(-1,-1),0.3,C_MGRAY),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LEFTPADDING",(0,0),(-1,-1),5),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("ALIGN",(0,0),(1,-1),"CENTER"),
    ]
    for i, row in enumerate(rows[1:], 1):
        c = SEV_COLOR.get(row[1], C_STEEL)
        rem_style += [
            ("BACKGROUND",(1,i),(1,i),c),
            ("TEXTCOLOR",(1,i),(1,i),C_WHITE),
            ("FONTNAME",(1,i),(1,i),"Helvetica-Bold"),
        ]
    rt = Table(rows, colWidths=[0.6*cm,2*cm,4*cm,5*cm,2.5*cm,2.9*cm])
    rt.setStyle(TableStyle(rem_style))
    story.append(rt)
    story.append(PageBreak())

# ── Section 7: Appendix ──────────────────────────────────────────
def _appendix(story, styles, scan_data, server_data):
    story.append(Paragraph("7. APPENDIX — RAW TECHNICAL DATA", styles["h1"]))
    story.append(_rule(C_NAVY, 1.5))

    story.append(Paragraph("A. HTTP Response Headers (All)", styles["h2"]))
    found = scan_data.get("headers",{}).get("headers_found",{})
    if found:
        for k, v in found.items():
            story.append(Paragraph(f"<font name='Courier'>{k}: {v[:80]}{'...' if len(v)>80 else ''}</font>",
                                   styles["mono"]))
    else:
        story.append(Paragraph("No security headers found.", styles["body"]))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("B. HTML Analysis Summary", styles["h2"]))
    html_d = scan_data.get("html",{})
    h_rows = [
        ["Parameter",         "Value"],
        ["Page Title",        str(html_d.get("title","N/A"))[:60]],
        ["External Scripts",  str(len(html_d.get("external_scripts",[])))],
        ["Insecure Forms",    str(len(html_d.get("insecure_forms",[])))],
        ["Total Links",       str(html_d.get("total_links",0))],
    ]
    ht = Table(h_rows, colWidths=[5*cm, 12*cm])
    ht.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(0,-1),C_LGRAY),("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
        ("FONTNAME",(1,0),(1,-1),"Helvetica"),("FONTSIZE",(0,0),(-1,-1),8.5),
        ("GRID",(0,0),(-1,-1),0.3,C_MGRAY),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LEFTPADDING",(0,0),(-1,-1),8),
    ]))
    story.append(ht)

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("C. Tool & Methodology", styles["h2"]))
    story.append(Paragraph(
        "Tool: PTC AI Web Shield v1.0<br/>"
        "Method: Passive HTTP scanning (HEAD + GET requests only)<br/>"
        "AI Engine: Google Gemini 2.0 Flash<br/>"
        "Standard: ISO/IEC 27001:2022 Annex A Controls<br/>"
        "Disclaimer: This tool performs passive reconnaissance only. "
        "No active exploitation or vulnerability testing was performed. "
        "Results should be verified by a qualified security professional before remediation.",
        styles["body"]))

# ── Page numbering ───────────────────────────────────────────────
class _PageNum:
    def __init__(self, title):
        self.title = title
    def __call__(self, canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_DGRAY)
        canvas.drawString(2*cm, 1*cm, self.title)
        canvas.drawRightString(19*cm, 1*cm, f"Page {doc.page}")
        canvas.drawCentredString(10.5*cm, 1*cm, "CONFIDENTIAL — PTC AI Web Shield")
        canvas.restoreState()

# ── Main build function ──────────────────────────────────────────
def build_report(scan_data: dict, ai_data: dict, server_data: dict,
                 org_name: str = "วิทยาลัยเทคนิคปัตตานี") -> bytes:
    """
    สร้าง PDF ISO/IEC 27001 report
    คืนค่าเป็น bytes เพื่อส่งให้ Streamlit download
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
        title="PTC AI Web Shield — Security Assessment Report",
    )

    font = _setup_fonts()
    styles = _build_styles(font)

    story = []
    _cover(story, styles, scan_data, ai_data, org_name)
    _exec_summary(story, styles, scan_data, ai_data, server_data)
    _technical_findings(story, styles, scan_data, server_data)
    _ssl_section(story, styles, scan_data)
    _cve_section(story, styles, server_data)
    _ai_section(story, styles, ai_data)
    _remediation(story, styles, scan_data, server_data)
    _appendix(story, styles, scan_data, server_data)

    url = scan_data.get("url","target")
    doc.build(story, onFirstPage=_PageNum(url), onLaterPages=_PageNum(url))
    return buf.getvalue()

if __name__ == "__main__":
    # quick self-test with mock data
    mock_scan = {
        "url":"https://test.school.ac.th",
        "headers":{"score":33,"headers_found":{"Strict-Transport-Security":"max-age=31536000"},"headers_missing":["Content-Security-Policy","X-Frame-Options","X-Content-Type-Options","Referrer-Policy","Permissions-Policy"]},
        "ssl":{"has_ssl":True,"valid":True,"days_left":25,"issuer":"Let's Encrypt","warning":"⚠️ SSL จะหมดอายุใน 25 วัน!"},
        "html":{"title":"Test School","external_scripts":["https://cdn.other.com/js"],"insecure_forms":[],"total_links":42},
    }
    mock_ai = {"analysis":"## สรุป\nเว็บไซต์มีความเสี่ยงสูง\n## ปัญหา\n- ขาด CSP","risk_level":"HIGH","score":33}
    mock_srv = {
        "server_raw":"nginx/1.18.0","server_type":"nginx","server_version":"1.18.0",
        "version_exposed":True,"http_version":"HTTP/2","h2_enabled":True,
        "vulnerabilities":[{"cve":"CVE-2023-44487","severity":"HIGH","desc":"HTTP/2 Rapid Reset DoS","fix":"อัปเกรด nginx 1.25.3+"}],
        "dos_risk":True,"dos_detail":"nginx 1.18.0 + HTTP/2 → CVE-2023-44487","risk_level":"HIGH",
    }
    pdf = build_report(mock_scan, mock_ai, mock_srv)
    with open("/tmp/test_report.pdf","wb") as f:
        f.write(pdf)
    print(f"✅ PDF written: {len(pdf):,} bytes → /tmp/test_report.pdf")
