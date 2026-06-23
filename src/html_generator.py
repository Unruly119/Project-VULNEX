# src/html_generator.py — Project VULNEX
# ─────────────────────────────────────────────────────────────────
# สร้าง "รายงานความปลอดภัย 1 หน้า" เป็น HTML ก่อน แล้วค่อยส่งให้
# report_generator.html_to_pdf() แปลงเป็น PDF 1 หน้า
#
#  ทำไมต้อง HTML ก่อน:
#    - จัดเลย์เอาต์/แก้สไตล์ง่ายกว่าการวาดด้วย ReportLab มาก
#    - เรนเดอร์ด้วย Chromium (Playwright) → ฟอนต์ไทย + เลย์เอาต์ตรงเป๊ะ
#
#  สไตล์ (เลย์เอาต์ + สี) อ้างอิงรายงานสแกนสไตล์ Pentest-Tools/Nessus
#  (พื้นอ่านง่าย, แถบหัวข้อสี, ตารางรายการ, ชิปสีระดับความรุนแรง)
#  — แต่ "หัวข้อ / ข้อมูลที่ใส่ / ข้อจำกัด 1 หน้า" คงเดิมจากรายงานชุดก่อน
#
#  Security:
#    - ค่าที่มาจากการสแกน (URL, server banner, issuer, header ฯลฯ) เป็นข้อมูล
#      ไม่น่าเชื่อถือ → ผ่าน _esc() (HTML-escape + จำกัดความยาว) ทุกจุด
#    - บทวิเคราะห์ AI ตัด emoji ทิ้ง (ดีไซน์เป็น emoji-free) ด้วย _strip_emoji()
from __future__ import annotations

import base64
import html
import math
import os
import re
from datetime import datetime, timezone, timedelta

# Thailand has no DST — a fixed UTC+7 offset gives the correct local scan time
# regardless of the server's timezone (e.g. Streamlit Cloud runs in UTC, which
# previously made the report show a time hours behind the user's actual scan).
_ICT = timezone(timedelta(hours=7))

# ─────────────────────────────────────────────────────────────────
# สี — พาเลตอ้างอิงรายงานสแกน (อ่านง่าย) + แบรนด์ VULNEX (navy)
# ─────────────────────────────────────────────────────────────────
C_NAVY   = "#1e3a5f"
C_NAVY2  = "#2c4d7d"
C_STEEL  = "#2563a8"
C_INK    = "#1f2937"
C_MUTED  = "#64748b"
C_LINE   = "#dddddd"
C_LGRAY  = "#f5f5f5"
C_BLUE   = "#67ace1"          # ลิงก์/Info ตามไฟล์อ้างอิง

# ระดับความรุนแรง (พื้นหลังชิป) — ตามพาเลตไฟล์อ้างอิง
SEV_BG = {
    "CRITICAL": "#91243e", "HIGH": "#dd4b50", "MEDIUM": "#f18c43",
    "LOW": "#f8c851",      "SECURE": "#16a34a", "INFO": "#67ace1",
}
# สีตัวอักษรบนชิป (เหลือง LOW ต้องใช้ตัวอักษรเข้มเพื่อความอ่านง่าย)
SEV_FG = {
    "CRITICAL": "#ffffff", "HIGH": "#ffffff", "MEDIUM": "#ffffff",
    "LOW": "#3f2d00",      "SECURE": "#ffffff", "INFO": "#ffffff",
}
SEV_ORDER = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "SECURE": 4, "INFO": 5,
}

PASS_BG, FAIL_BG     = "#16a34a", "#dd4b50"
PASS_TINT, FAIL_TINT = "#f0fdf4", "#fef2f2"

_EMOJI_RE = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF"
    "\U00002190-\U000021FF\U00002B00-\U00002BFF️•]+"
)


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────
def _esc(value, limit: int = 2000) -> str:
    """HTML-escape + จำกัดความยาว — ใช้กับทุกค่าที่มาจากการสแกน (untrusted)."""
    s = str(value if value is not None else "")
    if len(s) > limit:
        s = s[:limit] + "…"
    return html.escape(s, quote=True)


def _strip_emoji(s: str) -> str:
    return _EMOJI_RE.sub("", s or "")


def _md_inline(text: str) -> str:
    """แปลง markdown ระดับ inline ที่ปลอดภัย: escape ก่อน แล้วค่อยใส่ <b>/<code>."""
    s = _esc(_strip_emoji(text), limit=1200)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`(.+?)`", r'<code>\1</code>', s)
    return s


def _risk_th(risk: str) -> str:
    return {
        "CRITICAL": "วิกฤต", "HIGH": "สูง",
        "MEDIUM": "ปานกลาง", "LOW": "ต่ำ",
    }.get(str(risk).upper(), str(risk))


def _risk_color(risk: str) -> str:
    return {
        "CRITICAL": "#91243e", "HIGH": "#dd4b50",
        "MEDIUM": "#f18c43", "LOW": "#16a34a",
    }.get(str(risk).upper(), "#f18c43")


def _section_text(md: str, prefix: str) -> str:
    """ดึงเนื้อหาใต้หัวข้อ '## <prefix>...' จาก markdown ของบทวิเคราะห์ AI."""
    for blk in re.split(r"(?m)^##\s+", md or ""):
        head, _, body = blk.partition("\n")
        if head.strip().startswith(prefix):
            return body.strip()
    return ""


# ── ชื่อหน่วยงาน — ดึงแบบ deterministic จากตัวเว็บ ไม่พึ่งข้อความ AI ──
# AI มักเดา/แต่งชื่อสถาบัน (เช่นสแกน "ปัตตานี" แต่เขียน "นราธิวาส") ทำให้รายงาน
# เสียความน่าเชื่อถือ — ชื่อจริงอยู่ใน <title> ของหน้าเว็บอยู่แล้ว ใช้ค่านั้นแทน
_ORG_KW = ("วิทยาลัย", "โรงเรียน", "มหาวิทยาลัย", "สถาบัน", "เทศบาล", "สำนักงาน",
           "องค์การบริหารส่วน", "กรม", "คณะ", "โรงพยาบาล", "เทคนิค", "อาชีวศึกษา",
           "ราชภัฏ", "วิทยาเขต", "เทคโนโลยี")
_ORG_BOILER = ("ยินดีต้อนรับเข้าสู่เว็บไซต์ของ", "ยินดีต้อนรับเข้าสู่เว็บไซต์",
               "ยินดีต้อนรับสู่", "ยินดีต้อนรับ", "เว็บไซต์อย่างเป็นทางการของ",
               "เว็บไซต์อย่างเป็นทางการ", "เว็บไซต์", "หน้าแรก", "หน้าหลัก",
               "Welcome to", "Home")


def _domain_of(url: str) -> str:
    m = re.search(r"https?://([^/]+)", url or "")
    host = (m.group(1) if m else (url or "")).split(":")[0].strip()
    return host[4:] if host.startswith("www.") else host


def _name_from_title(title: str) -> str:
    """ดึงชื่อหน่วยงานจาก <title> แบบระมัดระวัง — คืน '' ถ้าไม่มั่นใจ (ให้ fallback ไปโดเมน)."""
    if not title:
        return ""
    t = title
    for b in _ORG_BOILER:
        t = t.replace(b, " ")
    parts = [p.strip(" \t -|:·•") for p in re.split(r"[|｜\-–—:：»·•]", t) if p.strip()]
    for p in parts:
        if any(k in p for k in _ORG_KW):
            return p[:80]
    return ""


def _institution_name(scan_data: dict, org_name: str = "") -> str:
    """ชื่อหน่วยงานที่แสดงในรายงาน: org ที่ผู้ใช้กรอก → ชื่อจาก <title> → โดเมน."""
    org = (org_name or "").strip()
    if org and org.lower() not in ("your company", "n/a"):
        return org
    html_mod = scan_data.get("html", {}) or {}
    name = _name_from_title((html_mod.get("title") or "").strip())
    return name or _domain_of(scan_data.get("url", ""))


# ── ฟอนต์ Prompt (Thai + Latin) ฝัง base64 ให้รายงานพึ่งตัวเองได้ ──
_FONT_CACHE: dict | None = None

# unicode-range เดียวกับที่หน้าเว็บใช้ (subset ไทยของ Google Fonts) — จำกัด
# woff2 น้ำหนัก 500/600 ให้ครอบเฉพาะอักษรไทย ส่วน Latin จะ fall ไปที่ TTF เดิม
_THAI_RANGE = "U+02D7, U+0303, U+0331, U+0E01-0E5B, U+200C-200D, U+25CC"


def _fonts_css() -> str:
    global _FONT_CACHE
    if _FONT_CACHE is None:
        _here = os.path.dirname(os.path.abspath(__file__))
        gdir  = os.path.join(_here, "Font", "google_font")
        faces: list[str] = []
        # TTF เต็ม (Latin + Thai) น้ำหนัก 400/700 — ครอบทุกตัวอักษรทุกภาษา
        for fname, weight in (("Prompt-Regular.ttf", 400), ("Prompt-Bold.ttf", 700)):
            path = os.path.join(gdir, fname)
            try:
                with open(path, "rb") as fh:
                    b64 = base64.b64encode(fh.read()).decode("ascii")
                faces.append(
                    "@font-face{font-family:'Prompt';font-style:normal;"
                    f"font-weight:{weight};font-display:block;"
                    f"src:url(data:font/ttf;base64,{b64}) format('truetype');}}"
                )
            except OSError:
                pass
        # woff2 subset ไทย น้ำหนัก 500/600 — TTF มีแค่ 400/700 ทำให้ข้อความไทย
        # น้ำหนัก 500/600 (เช่น .topic, label ต่าง ๆ) ถูกสังเคราะห์เป็นน้ำหนักใกล้
        # เคียงและดู "ไม่ใช่ Prompt" ในบางหัวข้อ — เติมเฟซจริงให้ครบเหมือนหน้าเว็บ
        # (unicode-range จำกัดเฉพาะไทย → Latin 500/600 ยังใช้ TTF เดิม)
        for fname, weight in (("Prompt-Medium-thai.woff2", 500),
                              ("Prompt-SemiBold-thai.woff2", 600)):
            path = os.path.join(gdir, fname)
            try:
                with open(path, "rb") as fh:
                    b64 = base64.b64encode(fh.read()).decode("ascii")
                faces.append(
                    "@font-face{font-family:'Prompt';font-style:normal;"
                    f"font-weight:{weight};font-display:block;"
                    f"src:url(data:font/woff2;base64,{b64}) format('woff2');"
                    f"unicode-range:{_THAI_RANGE};}}"
                )
            except OSError:
                pass
        _FONT_CACHE = {"css": "\n".join(faces)}
    return _FONT_CACHE["css"]


# ─────────────────────────────────────────────────────────────────
# สร้าง checklist จาก scan data  (ย้ายมาจาก report_generator — logic เดิม)
# ─────────────────────────────────────────────────────────────────
def _build_checklist(scan_data: dict, server_data: dict, ai_data: dict) -> list:
    items   = []
    ssl     = scan_data.get("ssl", {}) or {}
    hdr     = scan_data.get("headers", {}) or {}
    srv     = server_data or {}
    vulns   = srv.get("vulnerabilities", []) or []
    dos     = srv.get("dos_risk", False)
    ver_exp = srv.get("version_exposed", False)
    stype   = str(srv.get("server_type", "Web Server")).upper()
    sver    = str(srv.get("server_version", "") or "")
    http_v  = str(srv.get("http_version", "HTTP/1.1") or "HTTP/1.1")
    h2_on   = srv.get("h2_enabled", False)
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
        spf_ok  = bool((dns.get("spf") or {}).get("present"))
        dmarc_p = (dns.get("dmarc") or {}).get("policy", "none")
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

    # เรียงร้ายแรงสุด → ปลอดภัยสุด (stable: คงลำดับเดิมเมื่อรุนแรงเท่ากัน)
    items.sort(key=lambda it: SEV_ORDER.get(it["sev"], 9))
    return items


# ─────────────────────────────────────────────────────────────────
# สร้างกลุ่มคำแนะนำ hardening  (ย้ายมาจาก report_generator — logic เดิม)
# ─────────────────────────────────────────────────────────────────
def _build_hardening(scan_data: dict, server_data: dict) -> list:
    hdr     = scan_data.get("headers", {}) or {}
    missing = hdr.get("headers_missing", []) or []
    srv     = server_data or {}
    ver_exp = srv.get("version_exposed", False)
    dos     = srv.get("dos_risk", False)
    stype   = str(srv.get("server_type", "")).lower()
    is_apache = "apache" in stype

    groups = []

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

    if ver_exp:
        if is_apache:
            ver_lines = ["# Hide server version (Apache)", "ServerTokens Prod",
                         "ServerSignature Off"]
        else:
            ver_lines = ["# Hide server version (nginx)", "server_tokens off;"]
        groups.append({
            "sev": "LOW",
            "title": "ซ่อน Version ของ Web Server",
            "lines": ver_lines,
        })

    groups.sort(key=lambda g: SEV_ORDER.get(g["sev"], 9))
    return groups


# ─────────────────────────────────────────────────────────────────
# ชิ้นส่วน HTML
# ─────────────────────────────────────────────────────────────────
def _donut_svg(score: int, color: str) -> str:
    r = 52
    circ = 2 * math.pi * r
    pct = max(0, min(100, int(score))) / 100
    dash = circ * pct
    return (
        '<svg width="124" height="124" viewBox="0 0 124 124" '
        'style="display:block">'
        f'<circle cx="62" cy="62" r="{r}" fill="none" stroke="#e2e8f0" '
        'stroke-width="13"/>'
        f'<circle cx="62" cy="62" r="{r}" fill="none" stroke="{color}" '
        f'stroke-width="13" stroke-linecap="round" '
        f'stroke-dasharray="{dash:.2f} {circ - dash:.2f}" '
        'transform="rotate(-90 62 62)"/>'
        f'<text x="62" y="62" text-anchor="middle" dominant-baseline="central" '
        f'font-size="36" font-weight="700" fill="{color}">{int(score)}</text>'
        '</svg>'
    )


def _section_bar(num: str, title: str) -> str:
    return (
        '<div class="sec-bar">'
        f'<span class="sec-num">{num}</span>{_esc(title, 200)}'
        '</div>'
    )


def _metric_box(label: str, value: str, color: str, fg: str = "#ffffff") -> str:
    return (
        '<div class="metric">'
        f'<div class="metric-val" style="background:{color};color:{fg}">{value}</div>'
        f'<div class="metric-lbl">{_esc(label, 120)}</div>'
        '</div>'
    )


# ─────────────────────────────────────────────────────────────────
# CSS (สไตล์อ่านง่ายอ้างอิงไฟล์รายงานสแกน)  — เก็บแยกเพื่อเลี่ยง brace ปน f-string
# ─────────────────────────────────────────────────────────────────
def _stylesheet() -> str:
    return (
        _fonts_css()
        + """
        *{margin:0;padding:0;box-sizing:border-box}
        @page{size:A4;margin:0}
        html,body{font-family:'Prompt','Segoe UI','Open Sans',sans-serif;color:#1f2937;
            font-size:11px;line-height:1.5;-webkit-print-color-adjust:exact;print-color-adjust:exact}
        .page{width:210mm;height:297mm;background:#ffffff;padding:11mm 12mm 9mm;
            overflow:hidden;position:relative}
        .content{transform-origin:top left}
        a,code{color:#1f2937}
        code{font-family:'Consolas','Courier New','Prompt',monospace;background:#eef2f7;
            padding:0 3px;border-radius:3px;font-size:.92em}

        /* Header banner */
        .banner{background:linear-gradient(120deg,#1e3a5f 0%,#2c4d7d 100%);
            color:#fff;border-radius:6px;padding:14px 18px 0;overflow:hidden;
            border-bottom:3px solid #2563a8}
        .banner h1{font-size:16px;font-weight:700;text-align:center;letter-spacing:.2px}
        .banner .sub{font-size:10px;color:#cbd5e1;text-align:center;margin-top:2px}
        .banner .meta{display:flex;justify-content:space-between;font-size:8.5px;
            color:#94a3b8;background:rgba(15,23,42,.45);margin:12px -18px 0;padding:5px 18px}

        /* Section header bars */
        .sec-bar{background:#1e3a5f;color:#fff;font-weight:700;font-size:11.5px;
            padding:6px 10px;border-radius:4px;margin:11px 0 7px;display:flex;align-items:center}
        .sec-num{display:inline-flex;align-items:center;justify-content:center;
            min-width:17px;height:17px;background:rgba(255,255,255,.22);border-radius:3px;
            font-size:10px;margin-right:8px;padding:0 3px}

        /* §1 Executive summary */
        .exec{display:flex;gap:16px;align-items:center}
        .exec-text{flex:1}
        .exec-text p{margin-bottom:6px}
        .exec-ai{background:#f5f8fc;border-left:3px solid #67ace1;border-radius:4px;
            padding:7px 10px;color:#334155;font-size:10.5px}
        .exec-meta{color:#64748b;font-size:10px;margin-top:6px}
        .donut{width:124px;text-align:center;flex-shrink:0}
        .donut .cap{font-size:10px;color:#64748b;margin-top:2px;font-weight:600}

        /* §2 Dashboard metrics */
        .dash{display:flex;gap:8px}
        .metric{flex:1;text-align:center}
        .metric-val{font-weight:700;font-size:12px;padding:9px 4px;border-radius:4px 4px 0 0}
        .metric-lbl{font-size:9px;color:#475569;text-transform:uppercase;letter-spacing:.3px;
            padding:5px 2px;border:1px solid #ddd;border-top:0;border-radius:0 0 4px 4px}

        /* §3 Checklist table */
        .note{font-size:9.5px;color:#64748b;margin-bottom:5px}
        table.chk{width:100%;border-collapse:collapse;table-layout:fixed}
        table.chk th{background:#f5f5f5;border:1px solid #ddd;padding:6px 7px;font-size:10px;
            font-weight:700;text-align:left;color:#1e3a5f}
        table.chk td{border:1px solid #ddd;padding:6px 7px;font-size:10px;vertical-align:middle;
            overflow-wrap:break-word;word-break:break-word}
        table.chk td.center{text-align:center}
        .chip{display:inline-block;font-weight:700;font-size:9px;padding:3px 7px;
            border-radius:3px;white-space:nowrap}
        .col-res{width:11%}.col-sev{width:11%}.col-topic{width:33%}.col-an{width:45%}
        .topic{font-weight:600;color:#0f172a}

        /* §4 Hardening */
        .hard-bar{color:#fff;font-weight:700;font-size:10.5px;padding:5px 9px;
            border-radius:4px;margin:8px 0 0;display:flex;align-items:center}
        .hard-sev{font-size:8.5px;font-weight:700;background:rgba(0,0,0,.18);
            padding:1px 6px;border-radius:3px;margin-right:8px;letter-spacing:.4px}
        .code{background:#f5f7fa;border:1px solid #e2e8f0;border-top:0;border-radius:0 0 4px 4px;
            font-family:'Consolas','Courier New','Prompt',monospace;font-size:9.5px;line-height:1.65;
            padding:8px 11px;color:#1e293b;white-space:pre-wrap;overflow-wrap:break-word}
        .code .cmt{color:#64748b}
        .hard-note{font-size:10px;color:#475569;margin:2px 0 4px;padding-left:2px}

        /* Footer */
        .foot{border-top:1px solid #e2e8f0;margin-top:11px;padding-top:6px;
            font-size:8.5px;color:#94a3b8;text-align:center}
        .foot-src{margin-top:4px;font-size:9px;color:#334155}
        .foot-src a{color:#2563a8;font-weight:700;text-decoration:none}
        """
    )


# ─────────────────────────────────────────────────────────────────
# Main: build one-page HTML
# ─────────────────────────────────────────────────────────────────
def build_report_html(scan_data: dict, ai_data: dict, server_data: dict,
                      org_name: str = "Your Company") -> str:
    """
    คืน HTML รายงานความปลอดภัย 1 หน้า (สไตล์อ่านง่ายอ้างอิงไฟล์รายงานสแกน)
    โครงสร้าง/หัวข้อ/ข้อมูล คงเดิมจากรายงาน PDF ชุดก่อน:
        Header → §1 บทสรุป + โดนัทคะแนน → §2 แดชบอร์ด → §3 ตารางตรวจสอบ
        → §4 Hardening → Footer
    """
    ai_data     = ai_data or {}
    server_data = server_data or {}

    score  = int(ai_data.get("score", 0) or 0)
    risk   = str(ai_data.get("risk_level", "HIGH")).upper()
    url    = scan_data.get("url", "")
    srv    = server_data
    stype  = str(srv.get("server_type", "Web Server")).upper()
    sver   = str(srv.get("server_version", "") or "")
    http_v = str(srv.get("http_version", "HTTP/1.1") or "HTTP/1.1")

    now_dt   = datetime.now(_ICT)          # Thai local time (UTC+7), server-independent
    month_th = ["", "มกราคม", "กุมภาพันธ์", "มีนาคม", "เมษายน", "พฤษภาคม", "มิถุนายน",
                "กรกฎาคม", "สิงหาคม", "กันยายน", "ตุลาคม", "พฤศจิกายน", "ธันวาคม"]
    date_th  = f"{now_dt.day} {month_th[now_dt.month]} {now_dt.year + 543}"
    # มุมขวาบนของแบนเนอร์: วันที่ก่อนเวลา ไม่มีคำว่า "วันที่/เวลาที่ตรวจสอบ"
    datetime_th = f"{date_th} {now_dt.strftime('%H:%M')} น."

    checklist = _build_checklist(scan_data, server_data, ai_data)
    passed = sum(1 for c in checklist if c["result"] == "PASSED")
    failed = sum(1 for c in checklist if c["result"] == "FAILED")
    risk_c = _risk_color(risk)

    # ชื่อหน่วยงานแบบ deterministic (ไม่เอาจากข้อความ AI ที่อาจมโนชื่อ)
    org_display = _institution_name(scan_data, org_name)

    # บทวิเคราะห์ AI (เรียกด้วยคีย์สำรอง) — ใช้ส่วน "สรุปภาพรวม" เป็นกล่องสีฟ้า
    # ในหัวข้อ 1 วางเหนือบรรทัด "สรุปจาก AI" (ไม่มีป้ายชื่อซ้ำซ้อน แสดงเนื้อหาเลย)
    overview = _section_text(ai_data.get("analysis", ""), "สรุปภาพรวม")
    overview = re.sub(r"(?m)^\s*>.*$", "", overview).strip()      # ตัด blockquote banner
    exec_ai_html = ""
    if overview:
        para = overview.split("\n\n")[0].replace("\n", " ").strip()
        if para:
            exec_ai_html = f'<div class="exec-ai">{_md_inline(para)}</div>'

    # บรรทัด "สรุปจาก AI" จากรายการที่ไม่ผ่าน (เหมือนรายงานเดิม)
    failed_preview = [c for c in checklist if c["result"] == "FAILED"]
    ai_summary_line = ""
    if failed_preview:
        topics = " · ".join(_esc(c["topic"], 80) for c in failed_preview[:3])
        ai_summary_line = (
            f'<p><b>สรุปจาก AI:</b> พบ {len(failed_preview)} รายการที่ต้องแก้ไข — {topics}</p>'
        )

    sec1 = (
        _section_bar("1", "บทสรุปการประเมิน (Executive Summary)")
        + '<div class="exec"><div class="exec-text">'
        + exec_ai_html
        + ai_summary_line
        + f'<div class="exec-meta"><b>หน่วยงาน:</b> {_esc(org_display, 120)} &nbsp;|&nbsp; '
        + f"<b>วันตรวจ:</b> {date_th}</div>"
        + '</div>'
        + f'<div class="donut">{_donut_svg(score, risk_c)}'
        + '<div class="cap">คะแนนความปลอดภัย</div></div>'
        + '</div>'
    )

    # ── §2 แดชบอร์ด — เมตริกเดิม 4 ช่อง ──
    sec2 = (
        _section_bar("2", "สรุปสถานะรายการตรวจสอบความปลอดภัย (Security)")
        + '<div class="dash">'
        + _metric_box("ระดับความเสี่ยงรวม", f"{_risk_th(risk).upper()} RISK", risk_c)
        + _metric_box("ผลการตรวจประเมิน", f"ผ่าน {passed} / ไม่ผ่าน {failed}",
                      _risk_color(risk if failed else "LOW"))
        + _metric_box("เวอร์ชันเซิร์ฟเวอร์", _esc(f"{stype}/{sver or 'N/A'}", 60), C_STEEL)
        + _metric_box("โพรโทคอลเครือข่าย", _esc(http_v, 30), C_NAVY)
        + '</div>'
    )

    # ── §3 ตารางตรวจสอบแบบละเอียด ──
    rows = []
    for it in checklist:
        is_pass = it["result"] == "PASSED"
        sev     = it["sev"]
        sev_bg  = SEV_BG.get(sev, C_STEEL)
        sev_fg  = SEV_FG.get(sev, "#ffffff")
        res_bg  = PASS_BG if is_pass else FAIL_BG
        tint    = PASS_TINT if is_pass else FAIL_TINT
        res_lbl = "ผ่าน" if is_pass else "ไม่ผ่าน"
        rows.append(
            '<tr>'
            f'<td class="center"><span class="chip" style="background:{res_bg};color:#fff">'
            f'{res_lbl}</span></td>'
            f'<td class="center"><span class="chip" style="background:{sev_bg};color:{sev_fg}">'
            f'{_esc(sev, 20)}</span></td>'
            f'<td class="topic" style="background:{tint}">{_esc(it["topic"], 200)}</td>'
            f'<td style="background:{tint}">{_esc(it["analysis"], 400)}</td>'
            '</tr>'
        )
    sec3 = (
        _section_bar("3", "ตารางบันทึกผลการตรวจสอบแบบละเอียด (Detailed Security Checklist)")
        + '<table class="chk"><thead><tr>'
        + '<th class="col-res center">ผลตรวจ</th>'
        + '<th class="col-sev center">ความรุนแรง</th>'
        + '<th class="col-topic">หัวข้อ / ข้อมูลที่ตรวจพบ</th>'
        + '<th class="col-an">บทวิเคราะห์สถานะ (Analysis &amp; Evidence)</th>'
        + '</tr></thead><tbody>'
        + "".join(rows)
        + '</tbody></table>'
    )

    # ── §4 Hardening ──
    sec4_parts = [
        _section_bar("4", "แผนงานปรับแต่งระบบเพื่อความปลอดภัยสูงสุด (Hardening Guidelines)")
    ]
    groups = _build_hardening(scan_data, server_data)
    if not failed:
        sec4_parts.append('<div class="hard-note">ไม่พบรายการที่ต้องแก้ไข '
                          '— ระบบผ่านการตรวจสอบทุกหัวข้อ</div>')
    elif not groups:
        sec4_parts.append(
            '<div class="hard-note">รายการที่ไม่ผ่านต้องแก้ไขที่ระดับใบรับรอง / DNS / '
            'ผู้ให้บริการ ซึ่งไม่มีชุดคำสั่ง config สำเร็จรูป — ดูคำแนะนำเฉพาะรายการในตารางหัวข้อ 3</div>'
        )
    else:
        for g in groups:
            sev   = g["sev"]
            sev_bg = SEV_BG.get(sev, C_STEEL)
            sev_fg = SEV_FG.get(sev, "#ffffff")
            code_lines = []
            for ln in g["lines"]:
                cls = ' class="cmt"' if ln.startswith("#") else ""
                code_lines.append(f'<span{cls}>{_esc(ln, 300)}</span>')
            sec4_parts.append(
                f'<div class="hard-bar" style="background:{sev_bg};color:{sev_fg}">'
                f'<span class="hard-sev">{_esc(sev, 20)}</span>{_esc(g["title"], 160)}</div>'
                + f'<div class="code">{chr(10).join(code_lines)}</div>'
            )
    sec4 = "".join(sec4_parts)

    # ── Header + Footer ──
    banner = (
        '<div class="banner">'
        '<h1>รายงานผลกระบบตรวจสอบความปลอดภัยเว็บไซต์สถานศึกษาด้วย AI</h1>'
        '<div class="sub">Comprehensive Security Audit Report — Project VULNEX</div>'
        f'<div class="meta"><span>Target: {_esc(url, 200)}</span>'
        f'<span>{datetime_th}</span></div>'
        '</div>'
    )
    footer = (
        '<div class="foot">รายงาน Comprehensive Security Audit — Project VULNEX'
        f' &nbsp;|&nbsp; มาตรฐาน Security Baseline 2026 &nbsp;|&nbsp; {_esc(org_display, 120)}'
        ' &nbsp;|&nbsp; หน้า 1 จาก 1'
        '<div class="foot-src">ผลการตรวจสอบนี้จัดทำผ่านเว็บไซต์ '
        '<a href="https://project-vulnex.streamlit.app/">'
        'https://project-vulnex.streamlit.app/</a></div>'
        '</div>'
    )

    body = banner + sec1 + sec2 + sec3 + sec4 + footer

    return (
        '<!DOCTYPE html><html lang="th"><head><meta charset="utf-8">'
        '<title>รายงานความปลอดภัยเว็บไซต์ — Project VULNEX</title>'
        f'<style>{_stylesheet()}</style></head>'
        f'<body><div class="page"><div class="content">{body}</div></div></body></html>'
    )


# ─────────────────────────────────────────────────────────────────
# Self-test — เขียน HTML ออกไฟล์เพื่อเปิดดูในเบราว์เซอร์
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    mock_scan = {
        "url": "https://www.apache-secure-demo.co.th",
        "headers": {"score": 40, "headers_found": {"X-Content-Type-Options": "nosniff"},
                    "headers_missing": ["Content-Security-Policy", "X-Frame-Options",
                                        "Strict-Transport-Security", "Referrer-Policy"]},
        "ssl": {"has_ssl": True, "valid": True, "days_left": 120, "issuer": "DigiCert",
                "warning": ""},
        "dns": {"score": 70, "spf": {"present": True}, "dmarc": {"policy": "none"},
                "error": None},
        "html": {"title": "Demo Site", "external_scripts": [], "insecure_forms": [],
                 "total_links": 10},
    }
    mock_ai = {
        "score": 55, "risk_level": "MEDIUM",
        "analysis": ("## สรุปภาพรวม\nระบบติดตั้งซอฟต์แวร์เวอร์ชันล่าสุดและใช้ HTTP/1.1 ซึ่งปลอดภัย "
                     "จาก DoS บน HTTP/2 แต่ยังต้องปรับปรุงการตั้งค่าเพื่อซ่อนป้ายเวอร์ชัน "
                     "และเสริม Security Headers\n\n## จุดที่ดีแล้ว\n- SSL ใช้งานได้"),
    }
    mock_srv = {
        "server_raw": "Apache/2.4.62", "server_type": "apache", "server_version": "2.4.62",
        "version_exposed": True, "http_version": "HTTP/1.1", "h2_enabled": False,
        "vulnerabilities": [], "dos_risk": False, "dos_detail": "",
    }
    out = build_report_html(mock_scan, mock_ai, mock_srv, "โรงเรียนสาธิตทดสอบ")
    with open("report_preview.html", "w", encoding="utf-8") as fh:
        fh.write(out)
    print(f"wrote report_preview.html ({len(out):,} chars)")
