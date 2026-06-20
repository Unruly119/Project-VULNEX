# src/report_generator.py  — Project VULNEX  (rewrite v2)
# แก้ไข 3 bugs หลัก + Score Donut gauge + layout ปรับปรุง
#
#  BUG-1  ASCII/Latin ไม่ขึ้น
#         → ฟอนต์ ThaiFont (NotoSansThai / Tahoma) ไม่มี Latin glyph ใน ReportLab
#         → Fix: ใช้ฟอนต์ที่มีทั้ง Thai + Latin ครบ (FreeSerif / Tahoma บน Windows)
#           และ/หรือ wrap ข้อความ ASCII ด้วย <font name="Helvetica">...</font>
#           ในทุก ParagraphStyle ที่อาจมีตัวอักษร ASCII ปนกัน
#
#  BUG-2  Emoji ✅❌ ไม่รองรับ
#         → ReportLab built-in + TTF ทั่วไปไม่มี color-emoji glyph
#         → Fix: เปลี่ยนเป็นข้อความไทย "ผ่าน" / "ไม่ผ่าน" ทั้งหมด
#
#  BUG-3  Code block ว่างเปล่า (ข้อความไม่แสดง)
#         → ParagraphStyle "code" ใช้ ThaiFont ซึ่งไม่มี Latin glyph → กลายเป็นกล่องดำ
#         → Fix: style "code" ใช้ fontName="Helvetica-Bold" โดยตรง
#           (code config เป็น ASCII ล้วน ไม่ต้องการ Thai glyph)
#
#  BONUS  Score Donut gauge  +  layout ปรับปรุง (header gradient, spacing)

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether,
)
from reportlab.platypus.flowables import Flowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY, TA_RIGHT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.fonts import addMapping
from datetime import datetime
import os, io, math

# ─────────────────────────────────────────────────────────────────
# สี
# ─────────────────────────────────────────────────────────────────
C_NAVY    = colors.HexColor("#1e3a5f")
C_NAVY2   = colors.HexColor("#162d4a")
C_STEEL   = colors.HexColor("#2563a8")
C_LIME    = colors.HexColor("#16a34a")
C_AMBER   = colors.HexColor("#d97706")
C_RED     = colors.HexColor("#dc2626")
C_CRIT    = colors.HexColor("#7f1d1d")
C_LGRAY   = colors.HexColor("#f8fafc")
C_MGRAY   = colors.HexColor("#e2e8f0")
C_DGRAY   = colors.HexColor("#475569")
C_BLACK   = colors.HexColor("#0f172a")
C_WHITE   = colors.white
C_PASS_BG = colors.HexColor("#dcfce7")
C_FAIL_BG = colors.HexColor("#fee2e2")
C_CODE_BG = colors.HexColor("#1e293b")   # dark code block

SEV_COLOR = {
    "CRITICAL": C_CRIT, "HIGH": C_RED,
    "MEDIUM":   C_AMBER, "LOW":  C_LIME,
    "SECURE":   C_LIME,  "INFO": C_STEEL,
}

# จัดลำดับความรุนแรง — ใช้เรียงรายการจากร้ายแรงสุด → ปลอดภัยสุด
# (FAILED มี sev เป็น CRITICAL/HIGH/MEDIUM/LOW, PASSED เป็น SECURE)
# จึงทำให้รายการที่ "ไม่ผ่าน" ลอยขึ้นบนสุดเสมอ
SEV_ORDER = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "SECURE": 4, "INFO": 5,
}

# ─────────────────────────────────────────────────────────────────
# BUG-1 FIX: Font setup — ใช้ฟอนต์ที่มีทั้ง Thai + Latin glyph ครบ
# ─────────────────────────────────────────────────────────────────
def _setup_fonts() -> str:
    """
    หาและลงทะเบียนฟอนต์ที่มี glyph ครอบคลุมทั้ง Thai + Latin + ตัวเลข
    คืนค่าชื่อ font family ที่ลงทะเบียนสำเร็จ

    Root-cause ของ BUG-1:
    - NotoSansThai / Sarabun เป็น "Thai-only" font — ไม่มี Latin glyph ใน TTF
      เมื่อ ReportLab พบ codepoint ที่ไม่มีใน cmap จะแสดงเป็นกล่องดำ
    - แก้โดยใช้ฟอนต์ที่มี Thai + Latin ครบในไฟล์เดียว (FreeSerif, Tahoma, THSarabunNew)
    - ลงทะเบียน regular + bold แล้ว registerFontFamily() เพื่อให้ <b> tag ทำงาน
    """
    REG  = "ThaiFont"
    BOLD = "ThaiFont-Bold"

    if REG in pdfmetrics.getRegisteredFontNames():
        return REG

    _here    = os.path.dirname(os.path.abspath(__file__))
    _assets  = os.path.normpath(os.path.join(_here, "..", "assets", "fonts"))
    _gprompt = os.path.join(_here, "Font", "google_font")

    candidates = [
        # ── Google Prompt (Thai webfont) — ให้ตรงกับ frontend ──
        # ใช้ไฟล์ TTF (ReportLab อ่าน woff2 ไม่ได้) ที่ดาวน์โหลดมาจาก
        # Google Fonts; มี glyph ทั้ง Thai + Latin ครบในไฟล์เดียว ดังนั้น
        # ข้อความไทยใน PDF จะ render ด้วย Prompt เหมือนหน้าเว็บ
        (
            os.path.join(_gprompt, "Prompt-Regular.ttf"),
            os.path.join(_gprompt, "Prompt-Bold.ttf"),
        ),
        # ── Windows (Tahoma = Thai + Latin + Bold ครบ) ──
        (
            os.path.join(_assets, "Tahoma.ttf"),
            os.path.join(_assets, "Tahoma-Bold.ttf"),
        ),
        (
            "C:/Windows/Fonts/Tahoma.ttf",
            "C:/Windows/Fonts/tahomabd.ttf",
        ),
        (
            "C:/Windows/Fonts/THSarabunNew.ttf",
            "C:/Windows/Fonts/THSarabunNewBold.ttf",
        ),
        # ── Linux / Server (FreeSerif = Thai + Latin + Bold ครบใน 1 family) ──
        (
            "/usr/share/fonts/truetype/freefont/FreeSerif.ttf",
            "/usr/share/fonts/truetype/freefont/FreeSerifBold.ttf",
        ),
    ]

    for reg_path, bold_path in candidates:
        if not os.path.exists(reg_path):
            continue
        try:
            pdfmetrics.registerFont(TTFont(REG, reg_path))

            # Bold: ถ้าไม่มีไฟล์ bold ใช้ regular แทนเพื่อไม่ให้ตกไป Helvetica-Bold
            if bold_path and os.path.exists(bold_path):
                pdfmetrics.registerFont(TTFont(BOLD, bold_path))
            else:
                pdfmetrics.registerFont(TTFont(BOLD, reg_path))

            # สำคัญ: addMapping เพื่อให้ <b> tag resolve ไป BOLD ไม่ใช่ Helvetica-Bold
            # ใช้ addMapping (ไม่ใช่ registerFontFamily) เพราะ ps2tt ใช้ lowercase key
            addMapping(REG, 0, 0, REG)    # normal
            addMapping(REG, 1, 0, BOLD)   # bold
            addMapping(REG, 0, 1, REG)    # italic
            addMapping(REG, 1, 1, BOLD)   # bold+italic
            return REG

        except Exception:
            continue

    # Fallback สุดท้าย: Helvetica รองรับ Latin แต่ไม่มี Thai — ยังดีกว่า crash
    return "Helvetica"


# ─────────────────────────────────────────────────────────────────
# BUG-1 FIX (เพิ่มเติม): helper ครอบข้อความ ASCII ด้วย Helvetica tag
# ใช้ใน Paragraph ที่ mix Thai + ASCII (URL, version string, ฯลฯ)
# ─────────────────────────────────────────────────────────────────
def _h(text: str) -> str:
    """ครอบข้อความด้วย <font name="Helvetica"> สำหรับ content ที่เป็น ASCII ล้วน"""
    return f'<font name="Helvetica">{text}</font>'

def _hb(text: str) -> str:
    """ครอบข้อความด้วย <font name="Helvetica-Bold"> สำหรับ ASCII ที่ต้องการ Bold"""
    return f'<font name="Helvetica-Bold">{text}</font>'


# ─────────────────────────────────────────────────────────────────
# Styles  — BUG-3 FIX: "code" ใช้ Helvetica-Bold โดยตรง
# ─────────────────────────────────────────────────────────────────
def _styles(f: str, scale: float = 1.0) -> dict:
    """
    f = ชื่อ Thai font family ที่ลงทะเบียนแล้ว
    scale = ตัวคูณขนาดฟอนต์ (ใช้บีบเนื้อหาให้พอดี 1 หน้าเมื่อมีรายการมาก)
    BUG-3 FIX: style "code" และ "code_comment" ใช้ fontName Helvetica ชุด built-in
    เพราะ config snippet เป็น ASCII ล้วน ไม่ต้องการ Thai glyph
    """
    bold_f = f + "-Bold"
    sz = lambda v: round(v * scale, 2)   # noqa: E731 — ย่อขนาดฟอนต์ตาม scale
    return {
        "title": ParagraphStyle(
            "title", fontName=f, fontSize=sz(15), leading=sz(20),
            textColor=C_WHITE, alignment=TA_CENTER, spaceAfter=1,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", fontName=f, fontSize=sz(9), leading=sz(13),
            textColor=colors.HexColor("#cbd5e1"), alignment=TA_CENTER, spaceAfter=1,
        ),
        "section": ParagraphStyle(
            "section", fontName=f, fontSize=sz(9), leading=sz(12), textColor=C_WHITE,
        ),
        "body": ParagraphStyle(
            "body", fontName=f, fontSize=sz(8.5), leading=sz(12),
            textColor=C_BLACK, alignment=TA_JUSTIFY,
        ),
        "body_sm": ParagraphStyle(
            "body_sm", fontName=f, fontSize=sz(7.5), leading=sz(10), textColor=C_DGRAY,
        ),
        "cell": ParagraphStyle(
            "cell", fontName=f, fontSize=sz(8), leading=sz(11), textColor=C_BLACK,
        ),
        "cell_b": ParagraphStyle(
            "cell_b", fontName=bold_f,
            fontSize=sz(8), leading=sz(11), textColor=C_BLACK,
        ),
        "badge": ParagraphStyle(
            "badge", fontName=f, fontSize=sz(8), leading=sz(10),
            textColor=C_WHITE, alignment=TA_CENTER,
        ),
        "badge_dark": ParagraphStyle(
            "badge_dark", fontName=f, fontSize=sz(8), leading=sz(10),
            textColor=C_BLACK, alignment=TA_CENTER,
        ),
        # BUG-3 FIX ─ fontName = Helvetica-Bold (ไม่ใช่ ThaiFont)
        # Code snippet เป็น ASCII ล้วน Helvetica-Bold แสดงได้สมบูรณ์
        # ขยายขนาดตัวอักษรของ code block ให้เด่นและเต็มพื้นที่กระดาษมากขึ้น
        "code": ParagraphStyle(
            "code", fontName="Helvetica-Bold", fontSize=sz(10), leading=sz(14),
            textColor=colors.HexColor("#e2e8f0"), backColor=C_CODE_BG,
            leftIndent=8, rightIndent=4, spaceAfter=2,
        ),
        "code_comment": ParagraphStyle(
            "code_comment", fontName="Helvetica", fontSize=sz(10), leading=sz(14),
            textColor=colors.HexColor("#94a3b8"), backColor=C_CODE_BG,
            leftIndent=8, rightIndent=4, spaceAfter=1,
        ),
        "footer": ParagraphStyle(
            "footer", fontName=f, fontSize=sz(7), leading=sz(9),
            textColor=C_DGRAY, alignment=TA_CENTER,
        ),
    }


# ─────────────────────────────────────────────────────────────────
# Score Donut Gauge (Flowable)
# ─────────────────────────────────────────────────────────────────
class DonutGauge(Flowable):
    """
    วาด Score Donut ด้วย ReportLab Canvas โดยตรง
    - วงแหวนสีตามคะแนน (เขียว/เหลือง/แดง)
    - ตัวเลขกลางวงใช้ Helvetica-Bold (ASCII) — ไม่มีปัญหา BUG-1
    - label ด้านล่างใช้ Thai font รับมาจากภายนอก
    """

    def __init__(self, score: int, thai_font: str,
                 width: float = 120, height: float = 120,
                 label: str = "คะแนนรวม"):
        Flowable.__init__(self)
        self.score      = max(0, min(100, int(score)))
        self.thai_font  = thai_font
        self.width      = width
        self.height     = height
        self.label      = label

    def wrap(self, availW, availH):
        return self.width, self.height

    def draw(self):
        c  = self.canv
        cx = self.width  / 2
        cy = self.height / 2 + 8   # เลื่อนขึ้นเล็กน้อยเพื่อเว้นพื้นที่ label ล่าง
        R  = 42
        lw = 13   # ความหนาวงแหวน

        # ── BG ring ──
        c.setStrokeColor(C_MGRAY)
        c.setLineWidth(lw)
        c.circle(cx, cy, R, stroke=1, fill=0)

        # ── Score arc ──
        score_color = (
            C_LIME  if self.score >= 70 else
            C_AMBER if self.score >= 40 else
            C_RED
        )
        c.setStrokeColor(score_color)
        c.setLineWidth(lw)
        extent = -360.0 * self.score / 100.0
        c.arc(cx - R, cy - R, cx + R, cy + R, startAng=90, extent=extent)

        # ── Center score number (Helvetica-Bold = ASCII safe) ──
        c.setFont("Helvetica-Bold", 22)
        c.setFillColor(C_BLACK)
        c.drawCentredString(cx, cy - 6, str(self.score))

        c.setFont("Helvetica", 8)
        c.setFillColor(C_DGRAY)
        c.drawCentredString(cx, cy - 17, "/100")

        # ── Thai label ด้านล่าง (Thai font) ──
        c.setFont(self.thai_font, 8)
        c.setFillColor(C_DGRAY)
        c.drawCentredString(cx, cy - R - 16, self.label)

        # ── Risk tag ──
        risk_label, risk_color = _score_to_risk(self.score)
        tag_w, tag_h = 48, 14
        tx = cx - tag_w / 2
        ty = cy - 33
        c.setFillColor(risk_color)
        c.roundRect(tx, ty, tag_w, tag_h, 4, stroke=0, fill=1)
        c.setFont(self.thai_font, 7.5)
        c.setFillColor(C_WHITE)
        c.drawCentredString(cx, ty + 3, risk_label)


# ─────────────────────────────────────────────────────────────────
# Helper utils
# ─────────────────────────────────────────────────────────────────
def _score_to_risk(score: int):
    if score >= 70:
        return "ความเสี่ยงต่ำ", C_LIME
    if score >= 40:
        return "ความเสี่ยงปานกลาง", C_AMBER
    return "ความเสี่ยงสูง", C_RED


def _rule(c=C_MGRAY, t=0.5):
    return HRFlowable(width="100%", thickness=t, color=c,
                      spaceAfter=3, spaceBefore=2)


def _section_bar(text: str, s: dict):
    tbl = Table([[Paragraph(text, s["section"])]], colWidths=[17 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    return tbl


def _risk_color(risk: str):
    return {
        "CRITICAL": C_CRIT, "HIGH": C_RED,
        "MEDIUM":   C_AMBER, "LOW":  C_LIME,
    }.get(str(risk).upper(), C_AMBER)


def _risk_th(risk: str) -> str:
    return {
        "CRITICAL": "วิกฤต", "HIGH": "สูง",
        "MEDIUM": "ปานกลาง", "LOW": "ต่ำ",
    }.get(str(risk).upper(), str(risk))


# ─────────────────────────────────────────────────────────────────
# สร้าง checklist จาก scan data
# ─────────────────────────────────────────────────────────────────
def _build_checklist(scan_data: dict, server_data: dict, ai_data: dict) -> list:
    items  = []
    ssl    = scan_data.get("ssl",  {}) or {}
    hdr    = scan_data.get("headers", {}) or {}
    srv    = server_data or {}
    vulns  = srv.get("vulnerabilities", []) or []
    dos    = srv.get("dos_risk",  False)
    ver_exp = srv.get("version_exposed", False)
    stype  = str(srv.get("server_type",    "Web Server")).upper()
    sver   = str(srv.get("server_version", "") or "")
    http_v = str(srv.get("http_version",   "HTTP/1.1") or "HTTP/1.1")
    h2_on  = srv.get("h2_enabled", False)
    hdr_score = hdr.get("score", 0) or 0
    missing   = hdr.get("headers_missing", []) or []
    days    = int(ssl.get("days_left", 0) or 0)
    ssl_ok  = bool(ssl.get("valid", False))

    # 1. Web Server CVE
    if vulns:
        cve_list = ", ".join(v.get("cve", "?") for v in vulns[:3])
        items.append({
            "result": "FAILED", "sev": "HIGH",
            "topic":    f"Web Server มี CVE ที่พบ ({stype} {sver})",
            "analysis": f"พบช่องโหว่: {cve_list} — ต้องอัปเดตซอฟต์แวร์ทันที",
        })
    else:
        items.append({
            "result": "PASSED", "sev": "SECURE",
            "topic":    f"Web Server อัปเดตล่าสุด ({stype} {sver or 'N/A'})",
            "analysis": f"ตรวจพบ {stype} {sver} ซึ่งเป็นเวอร์ชันปัจจุบัน ไม่พบ CVE ร้ายแรง",
        })

    # 2. HTTP Protocol
    if dos:
        items.append({
            "result": "FAILED", "sev": "CRITICAL",
            "topic":    "HTTP/2 DoS Risk (CVE-2023-44487)",
            "analysis": "ระบบใช้งาน HTTP/2 และมีความเสี่ยง Rapid Reset DoS — อัปเกรด server ด่วน",
        })
    else:
        proto_note = ("HTTP/1.1 ปลอดภัยจาก HTTP/2 DoS"
                      if not h2_on else "HTTP/2 เปิดใช้งาน แต่ไม่พบ DoS Risk")
        items.append({
            "result": "PASSED", "sev": "SECURE",
            "topic":    f"ความปลอดภัยโพรโทคอล ({http_v})",
            "analysis": proto_note,
        })

    # 3. SSL/TLS
    if not ssl_ok:
        items.append({
            "result": "FAILED", "sev": "CRITICAL",
            "topic":    "SSL/TLS Certificate ไม่ถูกต้อง",
            "analysis": ssl.get("warning", "ใบรับรองหมดอายุหรือไม่ถูกต้อง — ต้องแก้ไขทันที"),
        })
    elif days <= 30:
        items.append({
            "result": "FAILED", "sev": "MEDIUM",
            "topic":    f"SSL/TLS Certificate ใกล้หมดอายุ ({days} วัน)",
            "analysis": (f"ใบรับรองเหลืออายุ {days} วัน "
                         f"ออกโดย {ssl.get('issuer', 'Unknown')} — ต่ออายุโดยด่วน"),
        })
    else:
        items.append({
            "result": "PASSED", "sev": "SECURE",
            "topic":    f"SSL/TLS Certificate ({days} วัน)",
            "analysis": (f"ใบรับรองถูกต้อง ออกโดย {ssl.get('issuer', 'Unknown')} "
                         f"เหลืออายุ {days} วัน"),
        })

    # 4. Server Banner
    if ver_exp:
        items.append({
            "result": "FAILED", "sev": "LOW",
            "topic":    "Server Banner เปิดเผย Version",
            "analysis": (f'ค่า Server: {srv.get("server_raw", "")} ถูกส่งออกใน Header '
                         "— ควรซ่อนด้วย ServerTokens Prod / server_tokens off"),
        })
    else:
        items.append({
            "result": "PASSED", "sev": "SECURE",
            "topic":    "Server Banner ซ่อน Version แล้ว",
            "analysis": "ไม่พบการเปิดเผย Version บน Header — ผ่านมาตรฐาน Hardening",
        })

    # 5. Security Headers
    if hdr_score < 60 or len(missing) >= 2:
        miss_str = ", ".join(missing[:3]) + ("..." if len(missing) > 3 else "")
        items.append({
            "result": "FAILED", "sev": "MEDIUM",
            "topic":    f"HTTP Security Headers (คะแนน {hdr_score}/100)",
            "analysis": f"ขาด Headers สำคัญ: {miss_str} — เสี่ยงต่อ XSS และ Clickjacking",
        })
    else:
        items.append({
            "result": "PASSED", "sev": "SECURE",
            "topic":    f"HTTP Security Headers (คะแนน {hdr_score}/100)",
            "analysis": "Security Headers ครบถ้วนตามมาตรฐาน",
        })

    # 6. DNS / Email
    dns = scan_data.get("dns", {}) or {}
    if not dns.get("error"):
        spf_ok   = bool((dns.get("spf")   or {}).get("present"))
        dmarc_p  = (dns.get("dmarc") or {}).get("policy", "none")
        if not spf_ok or dmarc_p in ("none", "", None):
            items.append({
                "result": "FAILED", "sev": "MEDIUM",
                "topic":    "DNS / Email Security (SPF, DMARC)",
                "analysis": (f"SPF={'ตั้งค่าแล้ว' if spf_ok else 'ไม่มี'}, "
                             f"DMARC p={dmarc_p} — เสี่ยงต่อการปลอมแปลง Email"),
            })
        else:
            items.append({
                "result": "PASSED", "sev": "SECURE",
                "topic":    "DNS / Email Security (SPF, DMARC)",
                "analysis": f"SPF ตั้งค่าแล้ว, DMARC p={dmarc_p} — ปลอดภัยจาก Email Spoofing",
            })

    # เรียงจากร้ายแรงสุด → ปลอดภัยสุด (CRITICAL ก่อน, SECURE/ผ่าน ท้ายสุด)
    # stable sort คงลำดับเดิมไว้สำหรับรายการที่มีความรุนแรงเท่ากัน
    items.sort(key=lambda it: SEV_ORDER.get(it["sev"], 9))

    return items


# ─────────────────────────────────────────────────────────────────
# สร้าง hardening code lines
# ─────────────────────────────────────────────────────────────────
def _build_hardening(scan_data: dict, server_data: dict) -> list:
    """คืน 'กลุ่ม' คำแนะนำ hardening เรียงตามความรุนแรง (ร้ายแรงสุดก่อน)

    แต่ละกลุ่ม = {
        "sev":   ระดับความรุนแรง — ใช้เลือกสีหัวข้อให้ตรงกับหมวดใน Section 3,
        "title": ชื่อหมวด (ไทย),
        "lines": บรรทัด config (ASCII; ขึ้นต้น '#' = comment),
    }
    การจัดกลุ่ม + สีหัวข้อ + เรียงลำดับ ช่วยให้ผู้ดูแลเห็นชัดว่าควรแก้อะไรก่อน
    และ config แต่ละชุดสังกัดช่องโหว่หมวดใด
    """
    hdr     = scan_data.get("headers", {}) or {}
    missing = hdr.get("headers_missing", []) or []
    srv     = server_data or {}
    ver_exp = srv.get("version_exposed", False)
    dos     = srv.get("dos_risk", False)
    stype   = str(srv.get("server_type", "")).lower()
    is_apache = "apache" in stype

    groups = []

    # CRITICAL — HTTP/2 Rapid Reset DoS
    if dos:
        groups.append({
            "sev": "CRITICAL",
            "title": "ลดความเสี่ยง HTTP/2 Rapid Reset DoS (CVE-2023-44487)",
            "lines": [
                "# Mitigate HTTP/2 Rapid Reset DoS (nginx)",
                "limit_conn_zone $binary_remote_addr zone=conn_limit:10m;",
                "limit_req_zone  $binary_remote_addr zone=req_limit:10m rate=20r/s;",
            ],
        })

    # MEDIUM — Security Headers
    if missing:
        comment = "# Security Headers (Apache)" if is_apache else "# Security Headers (nginx)"
        hdr_lines = [comment]
        hdr_map = {
            "Content-Security-Policy":
                'Header set Content-Security-Policy "default-src \'self\';"',
            "X-Frame-Options":
                'Header set X-Frame-Options "SAMEORIGIN"',
            "X-Content-Type-Options":
                'Header set X-Content-Type-Options "nosniff"',
            "Strict-Transport-Security":
                'Header set Strict-Transport-Security "max-age=31536000"',
            "Referrer-Policy":
                'Header set Referrer-Policy "strict-origin-when-cross-origin"',
            "Permissions-Policy":
                'Header set Permissions-Policy "camera=(), microphone=()"',
        }
        for h in missing:
            if h in hdr_map:
                hdr_lines.append(hdr_map[h])
        groups.append({
            "sev": "MEDIUM",
            "title": "เพิ่ม HTTP Security Headers",
            "lines": hdr_lines,
        })

    # LOW — Hide server version banner
    if ver_exp:
        if is_apache:
            ver_lines = [
                "# Hide server version (Apache)",
                "ServerTokens Prod",
                "ServerSignature Off",
            ]
        else:
            ver_lines = [
                "# Hide server version (nginx)",
                "server_tokens off;",
            ]
        groups.append({
            "sev": "LOW",
            "title": "ซ่อน Version ของ Web Server",
            "lines": ver_lines,
        })

    # เรียงตามความรุนแรง — ร้ายแรงสุดก่อน
    groups.sort(key=lambda g: SEV_ORDER.get(g["sev"], 9))
    return groups


# ─────────────────────────────────────────────────────────────────
# Section 4 — Hardening
# ─────────────────────────────────────────────────────────────────
def _hardening_group_bar(title: str, sev: str, s: dict):
    """หัวข้อย่อยของกลุ่ม hardening — แถบสีตามระดับความรุนแรง
    (อ้างอิงสีหมวดเดียวกับตารางในหัวข้อ 3 เพื่อให้เชื่อมโยงกันได้ทันที)"""
    sev_c = SEV_COLOR.get(sev, C_STEEL)
    # ป้ายความรุนแรงเป็น ASCII → ครอบ Helvetica (_h) ให้คงฟอนต์อังกฤษเดิม
    label = Paragraph(f'{_h(sev)}&nbsp;&nbsp;&nbsp;{title}', s["section"])
    tbl = Table([[label]], colWidths=[17 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), sev_c),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    return tbl


def _hardening_section(story: list, s: dict, f: str,
                        checklist: list, scan_data: dict, server_data: dict,
                        scale: float = 1.0):
    _sp = lambda v: Spacer(1, v * scale * cm)   # noqa: E731 — ย่อระยะตาม scale
    story.append(_sp(0.15))
    story.append(_section_bar(
        "4. แผนงานปรับแต่งระบบเพื่อความปลอดภัยสูงสุด (Hardening Guidelines)", s))
    story.append(_sp(0.04))

    failed_items = [c for c in checklist if c["result"] == "FAILED"]
    if not failed_items:
        story.append(Paragraph(
            "ไม่พบรายการที่ต้องแก้ไข — ระบบผ่านการตรวจสอบทุกหัวข้อ",
            s["body"]))
        return

    groups = _build_hardening(scan_data, server_data)
    if not groups:
        # มีรายการไม่ผ่าน แต่ไม่มีชุด config สำเร็จรูป (เช่น SSL/DNS) — ชี้ไปหัวข้อ 3
        story.append(Paragraph(
            "รายการที่ไม่ผ่านต้องแก้ไขที่ระดับใบรับรอง / DNS / ผู้ให้บริการ "
            "ซึ่งไม่มีชุดคำสั่ง config สำเร็จรูป — ดูคำแนะนำเฉพาะรายการในตารางหัวข้อ 3",
            s["body"].clone("body_indent", leftIndent=8)))
        return

    intro = ("ดำเนินการแก้ไขไฟล์คอนฟิกหลักของ Web Server ตามลำดับความสำคัญ "
             "(เรียงจากร้ายแรงสุดก่อน) โดยสีหัวข้อของแต่ละชุดอ้างอิงระดับความรุนแรง "
             "เดียวกับตารางในหัวข้อ 3:")
    # leftIndent=8 ให้ตรงกับ leftIndent ของ code/code_comment style ด้านล่าง
    story.append(Paragraph(intro, s["body"].clone("body_indent", leftIndent=8)))
    story.append(_sp(0.1))

    for g in groups:
        # รวมหัวข้อสี + บรรทัด config เป็นบล็อกเดียว ไม่ให้หลุดหน้ากัน
        block = [_hardening_group_bar(g["title"], g["sev"], s), _sp(0.05)]
        for line in g["lines"]:
            # BUG-3 FIX: code style ใช้ Helvetica-Bold — แสดง ASCII ได้สมบูรณ์
            if line.startswith("#"):
                block.append(Paragraph(line if line else " ", s["code_comment"]))
            else:
                block.append(Paragraph(line if line else " ", s["code"]))
        block.append(_sp(0.12))
        story.append(KeepTogether(block))

    story.append(_sp(0.08))


# ─────────────────────────────────────────────────────────────────
# Header Banner (canvas on-page)  — gradient-like double-row
# ─────────────────────────────────────────────────────────────────
class HeaderBanner(Flowable):
    """
    วาด Header แบบ gradient สอง row — title + subtitle
    ใช้ Thai font สำหรับข้อความ, Helvetica สำหรับ ASCII mixed
    """

    def __init__(self, title_th: str, subtitle_th: str, url: str,
                 thai_font: str, width: float, date_str: str):
        Flowable.__init__(self)
        self.title_th   = title_th
        self.subtitle_th = subtitle_th
        self.url        = url
        self.thai_font  = thai_font
        self.width      = width
        self.date_str   = date_str
        self.height     = 60

    def wrap(self, availW, availH):
        return self.width, self.height

    def draw(self):
        c = self.canv
        w, h = self.width, self.height

        # ── Gradient แบบ manual (แถว gradient ซ้อน) ──
        steps = 10
        for i in range(steps):
            t   = i / steps
            r   = int(0x1e + t * (0x2c - 0x1e))
            g   = int(0x3a + t * (0x4d - 0x3a))
            b   = int(0x5f + t * (0x7d - 0x5f))
            stripe_h = h / steps
            c.setFillColorRGB(r/255, g/255, b/255)
            c.rect(0, h - (i + 1) * stripe_h, w, stripe_h, stroke=0, fill=1)

        # ── Bottom accent line ──
        c.setFillColor(C_STEEL)
        c.rect(0, 0, w, 3, stroke=0, fill=1)

        # ── Title (Thai font) ──
        c.setFillColor(C_WHITE)
        c.setFont(self.thai_font, 14)
        c.drawCentredString(w / 2, h - 22, self.title_th)

        # ── Subtitle (Thai) ──
        c.setFont(self.thai_font, 9)
        c.setFillColor(colors.HexColor("#cbd5e1"))
        c.drawCentredString(w / 2, h - 36, self.subtitle_th)

        # ── Meta bar ──
        c.setFillColor(colors.HexColor("#0f172a"))
        c.setFillAlpha(0.45)
        c.rect(0, 0, w, 18, stroke=0, fill=1)
        c.setFillAlpha(1.0)

        # URL (Helvetica — ASCII safe)
        c.setFont("Helvetica", 7.5)
        c.setFillColor(colors.HexColor("#94a3b8"))
        c.drawString(8, 5, f"Target: {self.url}")

        # date (Helvetica)
        c.setFont("Helvetica", 7.5)
        c.drawRightString(w - 8, 5, self.date_str)


# ─────────────────────────────────────────────────────────────────
# Main build function
# ─────────────────────────────────────────────────────────────────
def build_report(scan_data: dict, ai_data: dict, server_data: dict,
                 org_name: str = "Your Company") -> bytes:
    """
    สร้าง PDF Security Audit Report
    แก้ไขครบ 3 bugs + Score Donut + layout ใหม่
    """
    f = _setup_fonts()
    # cell_b ต้องการชื่อ bold font ที่แน่นอน
    bold_f = (f + "-Bold") if f not in ("Helvetica", "Helvetica-Bold") else "Helvetica-Bold"

    score   = int(ai_data.get("score", 0))
    risk    = str(ai_data.get("risk_level", "HIGH")).upper()
    url     = scan_data.get("url", "")
    srv     = server_data or {}
    stype   = str(srv.get("server_type",    "Web Server")).upper()
    sver    = str(srv.get("server_version", "") or "")
    http_v  = str(srv.get("http_version",   "HTTP/1.1") or "HTTP/1.1")
    now_dt  = datetime.now()
    month_th = ["", "มกราคม", "กุมภาพันธ์", "มีนาคม", "เมษายน",
                "พฤษภาคม", "มิถุนายน", "กรกฎาคม", "สิงหาคม",
                "กันยายน", "ตุลาคม", "พฤศจิกายน", "ธันวาคม"]
    date_th  = f"{now_dt.day} {month_th[now_dt.month]} {now_dt.year + 543}"
    date_en  = now_dt.strftime("%d %b %Y  %H:%M")

    checklist = _build_checklist(scan_data, server_data, ai_data)
    passed = sum(1 for c in checklist if c["result"] == "PASSED")
    failed = sum(1 for c in checklist if c["result"] == "FAILED")

    # ── AI summary สำหรับแสดงใน Section 1 ──
    failed_preview  = [c for c in checklist if c["result"] == "FAILED"]
    ai_summary_line = ""
    if failed_preview:
        failed_topics_str = " · ".join(c["topic"] for c in failed_preview[:3])
        ai_summary_line = (
            f"<b>สรุปจาก AI:</b> พบ {len(failed_preview)} รายการที่ต้องแก้ไข"
            f" — {failed_topics_str}"
        )

    risk_c = _risk_color(risk)

    # ─────────────────────────────────────────────────────────────
    # ประกอบ story ที่ scale หนึ่ง ๆ — ใช้ใน auto-fit loop ด้านล่าง
    # scale < 1.0 จะย่อขนาดฟอนต์/ระยะห่างทั้งฉบับเพื่อบีบให้พอดี 1 หน้า
    # ─────────────────────────────────────────────────────────────
    def _compose(scale: float) -> list:
        s   = _styles(f, scale)
        _sp = lambda v: Spacer(1, v * scale * cm)          # noqa: E731
        pad = lambda v: max(1, round(v * scale))           # noqa: E731
        story = []

        # ── Header Banner ──
        story.append(HeaderBanner(
            title_th="รายงานผลการตรวจประเมินความปลอดภัยเทคโนโลยีเว็บ",
            subtitle_th="Comprehensive Security Audit Report — Project VULNEX",
            url=url,
            thai_font=f,
            width=17 * cm,
            date_str=date_en,
        ))
        story.append(_sp(0.2))

        # ── Section 1: Executive Summary + Donut ──
        story.append(_section_bar("1. บทสรุปการประเมิน (Executive Summary)", s))
        story.append(_sp(0.1))

        # บทสรุปการประเมิน — ไม่ใช้ประโยคจาก AI ที่อาจมีชื่อสถาบันปนมา
        # ใช้ template คงที่ที่อ้างอิงแค่ URL + คะแนน + ระดับความเสี่ยง
        summary_text = (
            f'<b>URL:</b> <font name="Helvetica">{url}</font>  |  '
            f"มีคะแนนความปลอดภัยโดยรวมอยู่ที่ {score}/100 "
            f"ซึ่งถือว่าอยู่ในระดับ{_risk_th(risk)} "
            "ยังมีช่องโหว่ที่ต้องได้รับการแก้ไขอย่างเร่งด่วน"
        )

        # วาง Donut ด้านขวา, summary ด้านซ้าย ใน Table 2 คอลัมน์
        donut = DonutGauge(score=score, thai_font=f, width=110, height=110,
                           label="คะแนนความปลอดภัย")
        summary_para = [
            Paragraph(summary_text, s["body"]),
            _sp(0.08),
        ]
        if ai_summary_line:
            summary_para.append(Paragraph(ai_summary_line, s["body"]))
            summary_para.append(_sp(0.08))
        summary_para.append(Paragraph(
            f"<b>หน่วยงาน:</b> {org_name}  |  "
            f"<b>วันตรวจ:</b> {date_th}",
            s["body_sm"]))

        exec_tbl = Table(
            [[summary_para, donut]],
            colWidths=[12.5 * cm, 4.5 * cm],
        )
        exec_tbl.setStyle(TableStyle([
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING",   (0, 0), (0,  0),  0),
            ("RIGHTPADDING",  (0, 0), (0,  0),  6),
            ("LEFTPADDING",   (1, 0), (1,  0),  0),
            ("RIGHTPADDING",  (1, 0), (1,  0),  0),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(exec_tbl)
        story.append(_sp(0.14))

        # ── Section 2: Dashboard ──
        story.append(_section_bar(
            "2. สรุปสถานะรายการตรวจสอบความปลอดภัย (Security)", s))
        story.append(_sp(0.1))

        # BUG-2 FIX: แถว label + แถวค่า — ไม่ใช้ Emoji ✅❌ แต่ใช้ข้อความไทย
        dash_labels = [
            Paragraph("ระดับความเสี่ยงรวม",   s["body_sm"]),
            Paragraph("ผลการตรวจประเมิน",     s["body_sm"]),
            Paragraph("เวอร์ชันเซิร์ฟเวอร์",  s["body_sm"]),
            Paragraph("โพรโทคอลเครือข่าย",   s["body_sm"]),
        ]
        # BUG-1 FIX: ส่วนที่เป็น ASCII (version string, http version) ครอบด้วย _h()
        dash_values = [
            Paragraph(f"<b>{_risk_th(risk).upper()} RISK</b>", s["badge"]),
            Paragraph(
                f"<b>ผ่าน {_h(str(passed))} / ไม่ผ่าน {_h(str(failed))}</b>",
                s["badge"]),
            Paragraph(f"<b>{_h(stype)}/{_h(sver or 'N/A')}</b>", s["badge"]),
            Paragraph(f"<b>{_h(http_v)}</b>", s["badge"]),
        ]

        dash_tbl = Table([dash_labels, dash_values], colWidths=[4.25 * cm] * 4)
        dash_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 1), (0, 1), risk_c),
            ("BACKGROUND",    (1, 1), (1, 1), _score_to_risk(score)[1]),
            ("BACKGROUND",    (2, 1), (2, 1), C_STEEL),
            ("BACKGROUND",    (3, 1), (3, 1), C_NAVY),
            ("TEXTCOLOR",     (0, 1), (3, 1), C_WHITE),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 1), (3, 1),   pad(5)),
            ("BOTTOMPADDING", (0, 1), (3, 1),   pad(5)),
            ("TOPPADDING",    (0, 0), (3, 0),   pad(3)),
            ("BOTTOMPADDING", (0, 0), (3, 0),   pad(3)),
            ("FONTSIZE",      (0, 0), (-1, -1), round(8 * scale, 2)),
            ("BOX",           (0, 0), (-1, -1), 0.5, C_MGRAY),
            ("INNERGRID",     (0, 0), (-1, -1), 0.3, C_MGRAY),
        ]))
        story.append(dash_tbl)
        story.append(_sp(0.14))

        # ── Section 3: Detailed Checklist ──
        story.append(_section_bar(
            "3. ตารางบันทึกผลการตรวจสอบแบบละเอียด (Detailed Security Checklist)", s))
        story.append(_sp(0.02))
        # leftIndent=5 ให้ตรงกับ LEFTPADDING ของตาราง checklist ด้านล่าง
        story.append(Paragraph(
            f'รายงานแสดงผลการตรวจครบทุกหัวข้อเพื่อใช้เป็น {_h("Security Baseline")} อ้างอิง',
            s["body_sm"].clone("body_sm_indent", leftIndent=5)))
        story.append(_sp(0.06))

        # Header row
        chk_rows = [[
            Paragraph("<b>ผลตรวจ</b>",                                s["cell_b"]),
            Paragraph("<b>ความรุนแรง</b>",                             s["cell_b"]),
            Paragraph("<b>หัวข้อ / ข้อมูลที่ตรวจพบ</b>",              s["cell_b"]),
            Paragraph("<b>บทวิเคราะห์สถานะ (Analysis &amp; Evidence)</b>", s["cell_b"]),
        ]]

        chk_style = [
            ("BACKGROUND",    (0, 0), (-1, 0),  C_LGRAY),
            ("FONTSIZE",      (0, 0), (-1, -1), round(7.5 * scale, 2)),
            ("TOPPADDING",    (0, 0), (-1, -1), pad(4)),
            ("BOTTOMPADDING", (0, 0), (-1, -1), pad(4)),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_MGRAY),
            ("ALIGN",         (0, 0), (1,  -1), "CENTER"),
        ]

        for i, item in enumerate(checklist, 1):
            is_pass  = item["result"] == "PASSED"
            res_c    = C_LIME if is_pass else C_RED
            sev_c    = SEV_COLOR.get(item["sev"], C_STEEL)

            # BUG-2 FIX: ใช้ข้อความไทย "ผ่าน" / "ไม่ผ่าน" แทน emoji ✅❌
            res_label = "ผ่าน"     if is_pass else "ไม่ผ่าน"
            row_bg    = C_PASS_BG if is_pass else C_FAIL_BG

            chk_rows.append([
                Paragraph(f"<b>{res_label}</b>",    s["badge"]),
                Paragraph(f"<b>{item['sev']}</b>",  s["badge"]),
                Paragraph(item["topic"],            s["cell"]),
                Paragraph(item["analysis"],         s["cell"]),
            ])

            chk_style += [
                ("BACKGROUND", (0, i), (0, i), res_c),
                ("BACKGROUND", (1, i), (1, i), sev_c),
                ("TEXTCOLOR",  (0, i), (1, i), C_WHITE),
                ("BACKGROUND", (2, i), (3, i), row_bg),
            ]

        chk_tbl = Table(chk_rows, colWidths=[2.0 * cm, 1.9 * cm, 5.7 * cm, 7.4 * cm])
        chk_tbl.setStyle(TableStyle(chk_style))
        story.append(KeepTogether([chk_tbl]))

        # ── Section 4: Hardening ──
        _hardening_section(story, s, f, checklist, scan_data, server_data, scale)

        # ── Footer ──
        story.append(_sp(0.15))
        story.append(_rule(C_MGRAY, 0.4))
        story.append(Paragraph(
            f"รายงาน Comprehensive Security Audit — Project VULNEX  |  "
            f"มาตรฐาน Security Baseline 2026  |  {org_name}  |  หน้า 1 จาก 1",
            s["footer"]))

        return story

    # ─────────────────────────────────────────────────────────────
    # Auto-fit: รับประกัน 1 หน้า — ค่อย ๆ ย่อ scale จนรายงานพอดีหน้าเดียว
    # (footer ระบุ "หน้า 1 จาก 1" ตายตัว จึงต้องไม่ให้ล้นไปหน้า 2 เมื่อมี
    #  รายการไม่ผ่าน / คำแนะนำ hardening จำนวนมาก)
    # ─────────────────────────────────────────────────────────────
    pdf_bytes = b""
    for scale in (1.0, 0.95, 0.9, 0.85, 0.8, 0.75, 0.7):
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=1.6 * cm, rightMargin=1.6 * cm,
            topMargin=1.2 * cm,  bottomMargin=1.4 * cm,
            title="รายงานความปลอดภัยเว็บไซต์ — Project VULNEX",
        )
        doc.build(_compose(scale))
        pdf_bytes = buf.getvalue()
        if doc.page <= 1:
            break

    return pdf_bytes


# ─────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    mock_scan = {
        "url": "https://www.apache-secure-demo.co.th",
        "headers": {
            "score": 40,
            "headers_found": {"X-Content-Type-Options": "nosniff"},
            "headers_missing": [
                "Content-Security-Policy", "X-Frame-Options",
                "Strict-Transport-Security", "Referrer-Policy",
            ],
        },
        "ssl": {"has_ssl": True, "valid": True, "days_left": 120,
                "issuer": "DigiCert", "warning": ""},
        "dns": {"score": 70, "spf": {"present": True}, "dmarc": {"policy": "none"},
                "error": None},
        "html": {"title": "Demo Site", "external_scripts": [],
                 "insecure_forms": [], "total_links": 10},
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
        "server_raw":      "Apache/2.4.62",
        "server_type":     "apache",
        "server_version":  "2.4.62",
        "version_exposed": True,
        "http_version":    "HTTP/1.1",
        "h2_enabled":      False,
        "vulnerabilities": [],
        "dos_risk":        False,
        "dos_detail":      "",
    }
    pdf = build_report(mock_scan, mock_ai, mock_srv, "Test Org")
    import tempfile
    out = os.path.join(tempfile.gettempdir(), "vulnex_v2_test.pdf")
    with open(out, "wb") as fh:
        fh.write(pdf)
    print(f"PDF: {len(pdf):,} bytes -> {out}")