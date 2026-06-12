# src/report_generator.py  — Single-Page Comprehensive Report (แบบตัวอย่าง)
# ออกแบบให้ได้ 1 หน้า A4 เหมือน PDF ตัวอย่าง: ภาษาไทยเป็นหลัก
# ข้อมูลมาจาก scan_data, ai_data, server_data จริงทั้งหมด

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from datetime import datetime
import os, io

# ── สี ─────────────────────────────────────────────────────────
C_NAVY   = colors.HexColor("#1e3a5f")
C_STEEL  = colors.HexColor("#2563a8")
C_LIME   = colors.HexColor("#16a34a")
C_AMBER  = colors.HexColor("#d97706")
C_RED    = colors.HexColor("#dc2626")
C_CRIT   = colors.HexColor("#7f1d1d")
C_LGRAY  = colors.HexColor("#f8fafc")
C_MGRAY  = colors.HexColor("#e2e8f0")
C_DGRAY  = colors.HexColor("#475569")
C_BLACK  = colors.HexColor("#0f172a")
C_WHITE  = colors.white
C_PASS_BG = colors.HexColor("#dcfce7")
C_FAIL_BG = colors.HexColor("#fee2e2")
C_PASS_BORDER = colors.HexColor("#16a34a")
C_FAIL_BORDER = colors.HexColor("#dc2626")

SEV_COLOR = {
    "CRITICAL": C_CRIT, "HIGH": C_RED,
    "MEDIUM":   C_AMBER, "LOW":  C_LIME,
    "SECURE":   C_LIME,  "INFO": C_STEEL,
}

# ── Font setup ──────────────────────────────────────────────────
def _setup_fonts():
    """
    Register a Thai-capable font family (regular + bold) for ReportLab.

    Root-cause fix for Thai text rendering as solid black squares:

      BUG 1 — Missing registerFontFamily():
        Registering only the regular variant without calling
        registerFontFamily() causes Paragraph <b> tags to look up
        "ThaiFont-Bold" and, failing to find it, fall through to
        Helvetica-Bold.  Helvetica-Bold has zero Thai Unicode glyph
        coverage, so every Thai character in a bold context renders
        as a solid black square (U+25A0).

      BUG 2 — DejaVuSans in fallback chain:
        DejaVuSans.ttf was the last Linux fallback.  It registers
        without errors but contains no Thai glyphs, so it silently
        "succeeds" while still producing boxes for all Thai text.
        Removed from the candidate list.

    Fix:
      1. Register both regular AND bold variants (reuses the same
         font file as bold when no dedicated bold file is present —
         no synthesised bold but Thai glyphs are always available).
      2. Call registerFontFamily() to link the pair so <b> tags
         resolve to the Thai-capable bold font.
      3. Guard against redundant re-registration across requests
         (ReportLab stores fonts in a process-wide global registry).
    """
    # Guard: avoid re-registering on every PDF request.
    if "ThaiFont" in pdfmetrics.getRegisteredFontNames():
        return "ThaiFont"

    REG  = "ThaiFont"
    BOLD = "ThaiFont-Bold"

    # Resolve assets/fonts/ relative to this source file (works on any platform)
    _here = os.path.dirname(os.path.abspath(__file__))
    _assets = os.path.join(_here, "..", "assets", "fonts")

    # (regular_path, bold_path, is_ttc)
    # NOTE: NotoSansThai (variable font) has no Latin glyphs in ReportLab — excluded.
    #       Tahoma (Windows) and Sarabun (Linux/Vercel) cover Thai + Latin + Bold correctly.
    candidates = [
        # ── Bundled in repo (assets/fonts/) — highest priority, works everywhere ──
        # Tahoma: Thai + Latin + Bold — static font, full glyph coverage
        (os.path.join(_assets, "Tahoma.ttf"),
         os.path.join(_assets, "Tahoma-Bold.ttf"), False),
        # Windows — dedicated Thai fonts
        ("C:/Windows/Fonts/THSarabunNew.ttf",  "C:/Windows/Fonts/THSarabunNewBold.ttf",  False),
        ("C:/Windows/Fonts/cordia.ttc",          "C:/Windows/Fonts/cordiab.ttc",            True),
        ("C:/Windows/Fonts/browalia.ttc",         "C:/Windows/Fonts/browaliab.ttc",          True),
        ("C:/Windows/Fonts/angsana.ttc",          "C:/Windows/Fonts/angsanab.ttc",           True),
        ("C:/Windows/Fonts/Tahoma.ttf",           "C:/Windows/Fonts/tahomabd.ttf",           False),
        # Linux / Vercel — Thai-capable fonts (Noto first, then TLWG Sarabun)
        ("/usr/share/fonts/truetype/noto/NotoSansThai-Regular.ttf",
         "/usr/share/fonts/truetype/noto/NotoSansThai-Bold.ttf",                             False),
        ("/usr/share/fonts/opentype/noto/NotoSansThai-Regular.otf",
         "/usr/share/fonts/opentype/noto/NotoSansThai-Bold.otf",                             False),
        ("/usr/share/fonts/truetype/tlwg/Sarabun.ttf",
         "/usr/share/fonts/truetype/tlwg/Sarabun-Bold.ttf",                                  False),
        ("/usr/share/fonts/truetype/thai-scalable/Sarabun.ttf",
         "/usr/share/fonts/truetype/thai-scalable/Sarabun-Bold.ttf",                         False),
    ]

    for reg_path, bold_path, is_ttc in candidates:
        if not os.path.exists(reg_path):
            continue
        try:
            # Register regular variant
            if is_ttc:
                pdfmetrics.registerFont(TTFont(REG, reg_path, subfontIndex=0))
            else:
                pdfmetrics.registerFont(TTFont(REG, reg_path))

            # Register bold variant.
            # When no dedicated bold file exists, reuse the regular file so that
            # <b>-tagged Thai text still uses a Thai-capable font instead of
            # falling back to Helvetica-Bold (no Thai glyphs).
            try:
                if bold_path and os.path.exists(bold_path):
                    if is_ttc:
                        pdfmetrics.registerFont(TTFont(BOLD, bold_path, subfontIndex=0))
                    else:
                        pdfmetrics.registerFont(TTFont(BOLD, bold_path))
                else:
                    raise FileNotFoundError("no dedicated bold file")
            except Exception:
                # Fallback: register the same regular font as the bold slot.
                if is_ttc:
                    pdfmetrics.registerFont(TTFont(BOLD, reg_path, subfontIndex=0))
                else:
                    pdfmetrics.registerFont(TTFont(BOLD, reg_path))

            # CRITICAL: link regular ↔ bold so that Paragraph <b> tags
            # resolve to BOLD (Thai-capable) instead of Helvetica-Bold.
            pdfmetrics.registerFontFamily(
                REG,
                normal=REG,
                bold=BOLD,
                italic=REG,
                boldItalic=BOLD,
            )
            return REG

        except Exception:
            continue

    return "Helvetica"

# ── Styles ──────────────────────────────────────────────────────
def _styles(f):
    return {
        "title": ParagraphStyle("title", fontName=f, fontSize=14, leading=18,
            textColor=C_NAVY, alignment=TA_CENTER, spaceAfter=2),
        "subtitle": ParagraphStyle("subtitle", fontName=f, fontSize=9, leading=13,
            textColor=C_DGRAY, alignment=TA_CENTER, spaceAfter=1),
        "section": ParagraphStyle("section", fontName=f, fontSize=9, leading=12,
            textColor=C_WHITE),
        "body": ParagraphStyle("body", fontName=f, fontSize=8, leading=11,
            textColor=C_BLACK, alignment=TA_JUSTIFY),
        "body_sm": ParagraphStyle("body_sm", fontName=f, fontSize=7.5, leading=10,
            textColor=C_DGRAY),
        "cell": ParagraphStyle("cell", fontName=f, fontSize=8, leading=10,
            textColor=C_BLACK),
        "cell_b": ParagraphStyle("cell_b", fontName=f, fontSize=8, leading=10,
            textColor=C_BLACK),
        "badge": ParagraphStyle("badge", fontName=f, fontSize=8, leading=10,
            textColor=C_WHITE, alignment=TA_CENTER),
        "code": ParagraphStyle("code", fontName=f, fontSize=7.5, leading=10,
            textColor=C_NAVY, backColor=C_LGRAY, leftIndent=6),
        "footer": ParagraphStyle("footer", fontName=f, fontSize=7, leading=9,
            textColor=C_DGRAY, alignment=TA_CENTER),
    }

def _rule(c=C_MGRAY, t=0.5):
    return HRFlowable(width="100%", thickness=t, color=c, spaceAfter=3, spaceBefore=2)

def _section_bar(text, s):
    tbl = Table([[Paragraph(text, s["section"])]], colWidths=[17*cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,-1), C_NAVY),
        ("TOPPADDING", (0,0),(-1,-1), 4), ("BOTTOMPADDING",(0,0),(-1,-1), 4),
        ("LEFTPADDING",(0,0),(-1,-1), 8),
    ]))
    return tbl

# ── Risk level → สี badge ──────────────────────────────────────
def _risk_color(risk):
    return {
        "CRITICAL": C_CRIT, "HIGH": C_RED,
        "MEDIUM": C_AMBER,  "LOW": C_LIME,
    }.get(str(risk).upper(), C_AMBER)

def _risk_th(risk):
    return {
        "CRITICAL": "วิกฤต", "HIGH": "สูง",
        "MEDIUM": "ปานกลาง", "LOW": "ต่ำ",
    }.get(str(risk).upper(), str(risk))

def _score_color(score):
    if score >= 70: return C_LIME
    if score >= 40: return C_AMBER
    return C_RED

# ── ดึงผล PASSED / FAILED จาก scan data จริง ──────────────────
def _build_checklist(scan_data, server_data, ai_data):
    """
    คืนค่า list ของ dict:
      { "result": "PASSED"|"FAILED", "sev": "SECURE"|"LOW"|"MEDIUM"|...,
        "topic": str, "analysis": str }
    เหมือนตาราง Detailed Security Checklist ในตัวอย่าง
    """
    items = []
    ssl   = scan_data.get("ssl", {}) or {}
    hdr   = scan_data.get("headers", {}) or {}
    srv   = server_data or {}
    vulns = srv.get("vulnerabilities", []) or []
    dos   = srv.get("dos_risk", False)
    ver_exp = srv.get("version_exposed", False)
    stype = str(srv.get("server_type", "Web Server")).upper()
    sver  = str(srv.get("server_version", "") or "")
    http_v = str(srv.get("http_version", "HTTP/1.1") or "HTTP/1.1")
    h2_on = srv.get("h2_enabled", False)
    hdr_score = hdr.get("score", 0) or 0
    missing = hdr.get("headers_missing", []) or []
    days = int(ssl.get("days_left", 0) or 0)
    ssl_ok = bool(ssl.get("valid", False))
    score = int(ai_data.get("score", 0))

    # 1. Web Server up-to-date / CVE
    if vulns:
        cve_list = ", ".join(v.get("cve","?") for v in vulns[:3])
        items.append({
            "result": "FAILED", "sev": "HIGH",
            "topic": f"Web Server มี CVE ที่พบ ({stype} {sver})",
            "analysis": f"พบช่องโหว่: {cve_list} — ต้องอัปเดตซอฟต์แวร์ทันที",
        })
    else:
        items.append({
            "result": "PASSED", "sev": "SECURE",
            "topic": f"Web Server อัปเดตล่าสุด ({stype} {sver or 'N/A'})",
            "analysis": f"ตรวจพบ {stype} {sver} ซึ่งเป็นเวอร์ชันปัจจุบัน ไม่พบ CVE ร้ายแรง",
        })

    # 2. HTTP Protocol Safety
    if dos:
        items.append({
            "result": "FAILED", "sev": "CRITICAL",
            "topic": "HTTP/2 DoS Risk (CVE-2023-44487)",
            "analysis": "ระบบใช้งาน HTTP/2 และมีความเสี่ยง Rapid Reset DoS — อัปเกรด server ด่วน",
        })
    else:
        proto_note = "HTTP/1.1 ปลอดภัยจาก HTTP/2 DoS" if not h2_on else "HTTP/2 เปิดใช้งาน แต่ไม่พบ DoS Risk"
        items.append({
            "result": "PASSED", "sev": "SECURE",
            "topic": f"ความปลอดภัยโพรโทคอล ({http_v})",
            "analysis": proto_note,
        })

    # 3. SSL/TLS
    if not ssl_ok:
        items.append({
            "result": "FAILED", "sev": "CRITICAL",
            "topic": "SSL/TLS Certificate ไม่ถูกต้อง",
            "analysis": ssl.get("warning", "ใบรับรองหมดอายุหรือไม่ถูกต้อง — ต้องแก้ไขทันที"),
        })
    elif days <= 30:
        items.append({
            "result": "FAILED", "sev": "MEDIUM",
            "topic": f"SSL/TLS Certificate ใกล้หมดอายุ ({days} วัน)",
            "analysis": f"ใบรับรองเหลืออายุ {days} วัน ออกโดย {ssl.get('issuer','Unknown')} — ต่ออายุโดยด่วน",
        })
    else:
        items.append({
            "result": "PASSED", "sev": "SECURE",
            "topic": f"SSL/TLS Certificate ({days} วัน)",
            "analysis": f"ใบรับรองถูกต้อง ออกโดย {ssl.get('issuer','Unknown')} เหลืออายุ {days} วัน",
        })

    # 4. Server Banner
    if ver_exp:
        items.append({
            "result": "FAILED", "sev": "LOW",
            "topic": "Server Banner เปิดเผย Version",
            "analysis": f'ค่า "Server: {srv.get("server_raw","")}" ถูกส่งออกใน Header — '
                        "ควรซ่อนด้วย ServerTokens Prod / server_tokens off",
        })
    else:
        items.append({
            "result": "PASSED", "sev": "SECURE",
            "topic": "Server Banner ซ่อน Version แล้ว",
            "analysis": "ไม่พบการเปิดเผย Version บน Header — ผ่านมาตรฐาน Hardening",
        })

    # 5. Security Headers
    if hdr_score < 60 or len(missing) >= 2:
        miss_str = ", ".join(missing[:3]) + ("..." if len(missing) > 3 else "")
        items.append({
            "result": "FAILED", "sev": "MEDIUM",
            "topic": f"HTTP Security Headers (คะแนน {hdr_score}/100)",
            "analysis": f"ขาด Headers สำคัญ: {miss_str} — เสี่ยงต่อ XSS และ Clickjacking",
        })
    else:
        items.append({
            "result": "PASSED", "sev": "SECURE",
            "topic": f"HTTP Security Headers (คะแนน {hdr_score}/100)",
            "analysis": "Security Headers ครบถ้วนตามมาตรฐาน",
        })

    # 6. DNS / Email
    dns = scan_data.get("dns", {}) or {}
    if not dns.get("error"):
        spf_ok = bool((dns.get("spf") or {}).get("present"))
        dmarc_p = (dns.get("dmarc") or {}).get("policy", "none")
        if not spf_ok or dmarc_p in ("none", "", None):
            items.append({
                "result": "FAILED", "sev": "MEDIUM",
                "topic": "DNS / Email Security (SPF, DMARC)",
                "analysis": f"SPF={'ตั้งค่าแล้ว' if spf_ok else 'ไม่มี'}, DMARC p={dmarc_p} — เสี่ยงต่อการปลอมแปลง Email",
            })
        else:
            items.append({
                "result": "PASSED", "sev": "SECURE",
                "topic": "DNS / Email Security (SPF, DMARC)",
                "analysis": f"SPF ตั้งค่าแล้ว, DMARC p={dmarc_p} — ปลอดภัยจาก Email Spoofing",
            })

    return items

# ── Hardening code block ────────────────────────────────────────
def _build_hardening(scan_data, server_data):
    """สร้าง list คำแนะนำ config จาก FAILED items"""
    lines = []
    hdr   = scan_data.get("headers", {}) or {}
    missing = hdr.get("headers_missing", []) or []
    srv = server_data or {}
    ver_exp = srv.get("version_exposed", False)
    dos = srv.get("dos_risk", False)
    stype = str(srv.get("server_type", "")).lower()

    is_apache = "apache" in stype
    is_nginx  = "nginx" in stype or not is_apache

    if ver_exp:
        if is_apache:
            lines += ["# ซ่อนปายชื่อและเลขเวอร์ชันเซิร์ฟเวอร์ (Apache)",
                      "ServerTokens Prod", "ServerSignature Off", ""]
        else:
            lines += ["# ซ่อนปายชื่อและเลขเวอร์ชันเซิร์ฟเวอร์ (nginx)",
                      "server_tokens off;", ""]

    if missing:
        if is_apache:
            lines.append("# เติม HTTP Security Headers ที่ขาดหายไป (Apache)")
        else:
            lines.append("# เติม HTTP Security Headers ที่ขาดหายไป (nginx)")

        hdr_map = {
            "Content-Security-Policy":
                'Header set Content-Security-Policy "default-src \'self\';"',
            "X-Frame-Options":
                'Header set X-Frame-Options "SAMEORIGIN"',
            "X-Content-Type-Options":
                'Header set X-Content-Type-Options "nosniff"',
            "Strict-Transport-Security":
                'Header set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
            "Referrer-Policy":
                'Header set Referrer-Policy "strict-origin-when-cross-origin"',
            "Permissions-Policy":
                'Header set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
        }
        for h in missing:
            if h in hdr_map:
                lines.append(hdr_map[h])

    if dos:
        lines += ["", "# ลด HTTP/2 DoS Risk (nginx)",
                  "limit_conn_zone $binary_remote_addr zone=conn_limit:10m;",
                  "limit_req_zone  $binary_remote_addr zone=req_limit:10m rate=20r/s;"]

    return lines

# ── Hardening Guidelines section ───────────────────────────────
def _hardening_section(story, s, checklist, scan_data, server_data):
    story.append(Spacer(1, 0.15*cm))
    story.append(_section_bar("4. แผนงานปรับแต่งระบบเพื่อความปลอดภัยสูงสุด (Hardening Guidelines)", s))
    story.append(Spacer(1, 0.1*cm))

    failed_items = [c for c in checklist if c["result"] == "FAILED"]
    if not failed_items:
        story.append(Paragraph("✅ ไม่พบรายการที่ต้องแก้ไข — ระบบผ่านการตรวจสอบทุกหัวข้อ", s["body"]))
        return

    intro = "ดำเนินการแก้ไขไฟล์คอนฟิกหลักของ Web Server เพื่ออุดช่องโหว่ในส่วนที่ขึ้นสถานะ FAILED ทันที:"
    story.append(Paragraph(intro, s["body"]))
    story.append(Spacer(1, 0.08*cm))

    code_lines = _build_hardening(scan_data, server_data)
    if code_lines:
        for line in code_lines:
            story.append(Paragraph(line if line else " ", s["code"]))

    story.append(Spacer(1, 0.08*cm))

    # AI recommendation snippet
    failed_topics = " · ".join(c["topic"] for c in failed_items[:3])
    story.append(Paragraph(
        f"<b>สรุปจาก AI:</b> พบ {len(failed_items)} รายการที่ต้องแก้ไข — {failed_topics}",
        s["body"]))

# ── Main build function ─────────────────────────────────────────
def build_report(scan_data: dict, ai_data: dict, server_data: dict,
                 org_name: str = "วิทยาลัยเทคนิคปัตตานี") -> bytes:
    """
    สร้าง PDF 1 หน้า แบบ Comprehensive Security Audit Report
    ภาษาไทยเป็นหลัก ข้อมูลมาจาก scan/ai/server จริง
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=1.6*cm, rightMargin=1.6*cm,
        topMargin=1.4*cm, bottomMargin=1.4*cm,
        title="รายงานความปลอดภัยเว็บไซต์ — Project VULNEX",
    )

    f = _setup_fonts()
    s = _styles(f)

    score  = int(ai_data.get("score", 0))
    risk   = str(ai_data.get("risk_level", "HIGH")).upper()
    url    = scan_data.get("url", "")
    srv    = server_data or {}
    stype  = str(srv.get("server_type", "Web Server")).upper()
    sver   = str(srv.get("server_version", "") or "")
    http_v = str(srv.get("http_version", "HTTP/1.1") or "HTTP/1.1")
    now_dt = datetime.now()
    month_th = ["", "มกราคม","กุมภาพันธ์","มีนาคม","เมษายน",
                "พฤษภาคม","มิถุนายน","กรกฎาคม","สิงหาคม",
                "กันยายน","ตุลาคม","พฤศจิกายน","ธันวาคม"]
    now = f"{now_dt.day} {month_th[now_dt.month]} {now_dt.year}"

    checklist = _build_checklist(scan_data, server_data, ai_data)
    passed = sum(1 for c in checklist if c["result"] == "PASSED")
    failed = sum(1 for c in checklist if c["result"] == "FAILED")

    story = []

    # ── Title block ──────────────────────────────────────────
    story.append(Paragraph(
        "รายงานผลการตรวจประเมินความปลอดภัยเทคโนโลยีเว็บ",
        s["title"]))
    story.append(Paragraph("(Comprehensive Security Audit Report)", s["subtitle"]))
    story.append(Spacer(1, 0.06*cm))

    meta_row = [[
        Paragraph(f"ระบบเป้าหมาย: <b>{url}</b>  |  "
                  f"แพลตฟอร์มหลัก: {stype} {sver}  |  "
                  f"วันที่ตรวจสอบ: {now}", s["body_sm"])
    ]]
    mt = Table(meta_row, colWidths=[17*cm])
    mt.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,-1), colors.HexColor("#f1f5f9")),
        ("TOPPADDING", (0,0),(-1,-1), 3), ("BOTTOMPADDING",(0,0),(-1,-1),3),
        ("LEFTPADDING",(0,0),(-1,-1), 6),
        ("BOX",        (0,0),(-1,-1), 0.5, C_MGRAY),
    ]))
    story.append(mt)
    story.append(Spacer(1, 0.12*cm))

    # ── Section 1: Executive Summary ────────────────────────
    story.append(_section_bar("1. บทสรุปผู้บริหาร (Executive Summary)", s))
    story.append(Spacer(1, 0.08*cm))

    # AI summary — ตัดย่อหน้าแรกออกมา
    ai_analysis = str(ai_data.get("analysis", "") or "")
    summary_text = ""
    for line in ai_analysis.split("\n"):
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("##"):
            summary_text = line[:360]
            break
    if not summary_text:
        summary_text = (
            f"ระบบมีความเสี่ยงอยู่ในระดับ {_risk_th(risk)} "
            f"(คะแนน {score}/100) จากการตรวจสอบแบบ Passive Scan "
            "ระบบควรปรับปรุงการตั้งค่า Security Headers และซ่อนข้อมูล Server Version"
        )
    story.append(Paragraph(summary_text, s["body"]))
    story.append(Spacer(1, 0.1*cm))

    # ── Section 2: Dashboard ─────────────────────────────────
    story.append(_section_bar("2. สรุปสถานะรายการตรวจสอบความปลอดภัย (Comprehensive Dashboard)", s))
    story.append(Spacer(1, 0.08*cm))

    risk_c = _risk_color(risk)
    score_c = _score_color(score)

    dash_data = [
        [
            Paragraph("ระดับความเสี่ยงรวม", s["body_sm"]),
            Paragraph("ผลการตรวจประเมิน", s["body_sm"]),
            Paragraph("เวอร์ชันเซิร์ฟเวอร์", s["body_sm"]),
            Paragraph("โพรโทคอลเครือข่าย", s["body_sm"]),
        ],
        [
            Paragraph(f"<b>{_risk_th(risk).upper()} RISK</b>", s["badge"]),
            Paragraph(f"<b>ผ่าน {passed} / ไม่ผ่าน {failed}</b>", s["badge"]),
            Paragraph(f"<b>{stype}/{sver or 'N/A'}</b>", s["badge"]),
            Paragraph(f"<b>{http_v}</b>", s["badge"]),
        ],
    ]
    dash_tbl = Table(dash_data, colWidths=[4.25*cm]*4)
    dash_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,1),(0,1), risk_c),
        ("BACKGROUND", (1,1),(1,1), score_c),
        ("BACKGROUND", (2,1),(2,1), C_STEEL),
        ("BACKGROUND", (3,1),(3,1), C_NAVY),
        ("TEXTCOLOR",  (0,1),(3,1), C_WHITE),
        ("ALIGN",      (0,0),(-1,-1), "CENTER"),
        ("VALIGN",     (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,1),(3,1), 5), ("BOTTOMPADDING",(0,1),(3,1),5),
        ("TOPPADDING", (0,0),(3,0), 3), ("BOTTOMPADDING",(0,0),(3,0),3),
        ("FONTSIZE",   (0,0),(-1,-1), 8),
        ("BOX",        (0,0),(-1,-1), 0.5, C_MGRAY),
        ("INNERGRID",  (0,0),(-1,-1), 0.3, C_MGRAY),
    ]))
    story.append(dash_tbl)
    story.append(Spacer(1, 0.12*cm))

    # ── Section 3: Detailed Checklist ───────────────────────
    story.append(_section_bar("3. ตารางบันทึกผลการตรวจสอบแบบละเอียด (Detailed Security Checklist)", s))
    story.append(Spacer(1, 0.06*cm))
    story.append(Paragraph(
        "* รายงานนี้แสดงผลการตรวจครบทุกหัวข้อเพื่อใช้เป็นหลักฐานอ้างอิงสถานะความปลอดภัยของระบบ (Security Baseline)",
        s["body_sm"]))
    story.append(Spacer(1, 0.06*cm))

    # Header row
    chk_rows = [[
        Paragraph("<b>ผลตรวจ</b>",      s["cell_b"]),
        Paragraph("<b>ความรุนแรง</b>",   s["cell_b"]),
        Paragraph("<b>หัวข้อ / ข้อมูลที่ตรวจพบ</b>", s["cell_b"]),
        Paragraph("<b>บทวิเคราะห์สถานะความปลอดภัย (Analysis & Evidence)</b>", s["cell_b"]),
    ]]

    chk_style = [
        ("BACKGROUND", (0,0),(-1,0), C_LGRAY),
        ("FONTSIZE",   (0,0),(-1,-1), 7.5),
        ("TOPPADDING", (0,0),(-1,-1), 4), ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LEFTPADDING",(0,0),(-1,-1), 5),
        ("VALIGN",     (0,0),(-1,-1), "MIDDLE"),
        ("GRID",       (0,0),(-1,-1), 0.3, C_MGRAY),
        ("ALIGN",      (0,0),(1,-1),  "CENTER"),
    ]

    for i, item in enumerate(checklist, 1):
        res = item["result"]
        sev = item["sev"]
        is_pass = res == "PASSED"

        res_c = C_LIME if is_pass else C_RED
        sev_c = SEV_COLOR.get(sev, C_STEEL)

        chk_rows.append([
            Paragraph(f"<b>{'✅' if is_pass else '❌'} {res}</b>", s["badge"]),
            Paragraph(f"<b>{sev}</b>", s["badge"]),
            Paragraph(item["topic"], s["cell"]),
            Paragraph(item["analysis"], s["cell"]),
        ])

        row_bg = C_PASS_BG if is_pass else C_FAIL_BG
        chk_style += [
            ("BACKGROUND", (0,i),(0,i), res_c),
            ("BACKGROUND", (1,i),(1,i), sev_c),
            ("TEXTCOLOR",  (0,i),(1,i), C_WHITE),
            ("BACKGROUND", (2,i),(3,i), row_bg),
        ]

    chk_tbl = Table(chk_rows, colWidths=[2.2*cm, 1.8*cm, 5.5*cm, 7.5*cm])
    chk_tbl.setStyle(TableStyle(chk_style))
    story.append(chk_tbl)

    # ── Section 4: Hardening ────────────────────────────────
    _hardening_section(story, s, checklist, scan_data, server_data)

    # ── Footer ──────────────────────────────────────────────
    story.append(Spacer(1, 0.15*cm))
    story.append(_rule(C_MGRAY, 0.4))
    story.append(Paragraph(
        f"รายงานฉบับสมบูรณ์ (Comprehensive Audit) — จัดทำโดยระบบ Project VULNEX "
        f"ร่วมกับมาตรฐาน Security Baseline 2026  |  {org_name}  |  หน้า 1 จาก 1",
        s["footer"]))

    # ── Build ────────────────────────────────────────────────
    doc.build(story)
    return buf.getvalue()


if __name__ == "__main__":
    mock_scan = {
        "url": "https://www.apache-secure-demo.co.th",
        "headers": {
            "score": 40,
            "headers_found": {"X-Content-Type-Options": "nosniff"},
            "headers_missing": ["Content-Security-Policy", "X-Frame-Options",
                                "Strict-Transport-Security", "Referrer-Policy"],
        },
        "ssl": {"has_ssl": True, "valid": True, "days_left": 120,
                "issuer": "DigiCert", "warning": ""},
        "dns": {"score": 70, "spf": {"present": True}, "dmarc": {"policy": "none"},
                "error": None},
        "html": {"title": "Demo Site", "external_scripts": [], "insecure_forms": [], "total_links": 10},
    }
    mock_ai = {
        "score": 55,
        "risk_level": "MEDIUM",
        "analysis": (
            "ระบบมีการติดตั้งและอัปเดตตัวซอฟต์แวร์เป็นเวอร์ชันล่าสุด รวมถึงการเลือกใช้โพรโทคอล "
            "HTTP/1.1 ซึ่งปลอดภัยจากภัยคุกคาม DoS บน HTTP/2 อย่างสมบูรณ์ อย่างไรก็ตาม "
            "ระบบยังจำเป็นต้องปรับปรุงโครงสร้างการตั้งค่าเพื่อซ่อนป้ายชื่อเวอร์ชัน "
            "และเสริม Security Headers เพื่อป้องกันการโจมตีฝั่งไคลเอนต์"
        ),
    }
    mock_srv = {
        "server_raw": "Apache/2.4.62",
        "server_type": "apache", "server_version": "2.4.62",
        "version_exposed": True, "http_version": "HTTP/1.1", "h2_enabled": False,
        "vulnerabilities": [], "dos_risk": False, "dos_detail": "",
    }
    pdf = build_report(mock_scan, mock_ai, mock_srv, "Test Org")
    import tempfile
    out = os.path.join(tempfile.gettempdir(), "vulnex_comprehensive_test.pdf")
    with open(out, "wb") as fh:
        fh.write(pdf)
    print(f"PDF: {len(pdf):,} bytes -> {out}")