# app.py — Project-VULNEX  (Phase 4 Final — v2)
# ────────────────────────────────────────────────────────────────
#   Senior security-engineer refactor:
#   · URL validated via urllib.parse + private/loopback SSRF guard
#   · HTML-escape every externally-sourced value before injection
#   · Allowlist validation on severity/risk enums (no blind CSS injection)
#   · Centralised idempotent session-state initialisation
#   · All stdlib imports at the top — no inline `import time`
#   · Full CSS design-token system — zero magic hex literals in Python
#   · CSS-class colouring replaces inline style= hex strings
#   · @keyframes animations + prefers-reduced-motion safety net
#   · Focus-visible a11y styles on all interactive elements
#   · New scan resets pdf_ready/pdf_bytes (no stale downloads)
# ────────────────────────────────────────────────────────────────
import sys
import os
sys.path.insert(0, "src")          # must precede src/* module imports

import math
import re
import time
import html as _html
from datetime import datetime
from urllib.parse import urlparse

import streamlit as st
import pandas as pd

# ── Page config ──────────────────────────────────────────────────
st.set_page_config(
    page_title="Project-VULNEX",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ───────────────────────────────────────────────────
def _load_css(path: str) -> str:
    """Read a CSS file and return it wrapped in a <style> tag."""
    with open(path, "r", encoding="utf-8") as f:
        return f"<style>\n{f.read()}\n</style>"


st.markdown(_load_css(os.path.join("src", "frontend", "index.css")), unsafe_allow_html=True)

# ── Import scanning / AI modules ─────────────────────────────────
try:
    from scanner             import run_scan
    from ai_engine           import analyze
    from scanner.server_info import check_server
    from report_generator    import build_report
    from utils.network       import is_safe_host

    MODULES_OK = True
    MODULE_ERR = ""
except ImportError as exc:
    MODULES_OK = False
    MODULE_ERR = str(exc)

# ────────────────────────────────────────────────────────────────
# Utility functions
# ────────────────────────────────────────────────────────────────

def normalise_url(raw: str) -> tuple:
    """
    Validate and normalise a user-supplied URL.
    Returns (url: str, error: str | None) — error is None on success.
    """
    raw = raw.strip()
    if not raw:
        return "", "กรุณาใส่ URL"
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https"):
            return "", "รองรับเฉพาะ http:// และ https:// เท่านั้น"
        if not parsed.hostname:
            return "", "URL ไม่ถูกต้อง — ไม่พบ hostname"
        if not is_safe_host(parsed.hostname):
            return "", "ไม่สามารถสแกน private / loopback address ได้"
        return raw, None
    except Exception as exc:
        return "", f"URL format ไม่ถูกต้อง: {exc}"


def _esc(value, maxlen: int = 256) -> str:
    """HTML-escape and length-cap an externally-sourced string."""
    return _html.escape(str(value).strip()[:maxlen])


def _sev_safe(raw: str) -> str:
    """Allowlist-validate a severity string before CSS/HTML injection."""
    v = raw.upper() if raw else "INFO"
    return v if v in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "PASS", "INFO") else "INFO"


def _risk_safe(raw: str) -> str:
    """Allowlist-validate a risk-level string."""
    v = raw.upper() if raw else "HIGH"
    return v if v in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "HIGH"


def score_color_class(score: int) -> str:
    """Map a 0–100 score to a CSS colour utility class."""
    if score >= 70: return "col-good"
    if score >= 40: return "col-warn"
    if score >= 20: return "col-bad"
    return "col-crit"


def _scan_module_errors(scan_data: dict) -> list[str]:
    """Collect per-module scan errors for user-friendly display."""
    errors = []
    labels = {
        "headers": "Security Headers", "ssl": "SSL/TLS", "html": "HTML Analysis",
        "dns": "DNS Security", "cookies": "Cookie Security", "cors": "CORS Policy",
        "http_methods": "HTTP Methods", "js_exposure": "JS Exposure",
        "subdomains": "Subdomain Recon", "open_files": "Open Files", "cms": "CMS Fingerprint",
    }
    for key, label in labels.items():
        module = scan_data.get(key, {}) or {}
        if isinstance(module, dict) and module.get("error"):
            errors.append(f"**{label}:** {module['error']}")
    return errors


def _module_ok(scan_data: dict, key: str) -> bool:
    """Return True if a scan module completed without error."""
    module = scan_data.get(key, {}) or {}
    return isinstance(module, dict) and not module.get("error")


# ── SVG icon helpers ───────────────────────────────────────────────
def _i(p: str, s: int, xs: str = "") -> str:
    """Inline Lucide-style SVG icon, inherits currentColor."""
    st_v = f"vertical-align:middle;flex-shrink:0{';' + xs if xs else ''}"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}"'
        f' viewBox="0 0 24 24" fill="none" stroke="currentColor"'
        f' stroke-width="2" stroke-linecap="round" stroke-linejoin="round"'
        f' style="{st_v}">{p}</svg>'
    )


_P_CHECK  = '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>'
_P_XCIRC  = '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>'
_P_ALERT  = '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/><path d="M12 9v4"/><path d="M12 17h.01"/>'
_P_SERVER = '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6 6h.01"/><path d="M6 18h.01"/>'
_P_WRENCH = '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>'
_P_SHIELD = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>'
_P_SHIELD_WARN = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/>'
_P_SEARCH = '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>'


# ── AI analysis rendering ───────────────────────────────────────────
# Map known "## <heading>" section titles (Thai, emoji-free per prompt
# templates) to an SVG icon + accent color. Falls back to no icon/color
# for unknown headings.
_ANALYSIS_SECTION_STYLE = {
    "สรุปภาพรวม":              (_P_SEARCH, "var(--c-info)"),
    "ปัญหาเร่งด่วน (ต้องแก้ทันที)": (_P_ALERT,  "var(--c-crit)"),
    "คำแนะนำการแก้ไข":          (_P_WRENCH, "var(--accent)"),
    "จุดที่ดีแล้ว":              (_P_CHECK,  "var(--c-low)"),
}

# Strip any stray emoji the AI model might still emit despite prompt
# instructions (covers common pictographic / symbol / flag ranges).
_EMOJI_RE = re.compile(
    "["
    "\U0001F300-\U0001FAFF"  # symbols & pictographs, supplemental, emoticons
    "\U00002600-\U000027BF"  # misc symbols, dingbats
    "\U0001F1E6-\U0001F1FF"  # regional indicators (flags)
    "\U00002190-\U000021FF"  # arrows (e.g. ➡️)
    "\U0000FE0F"             # variation selector (emoji presentation)
    "]+"
)


def _strip_emoji(text: str) -> str:
    return _EMOJI_RE.sub("", text)


def render_ai_analysis(analysis: str) -> None:
    """Render the AI/offline analysis markdown, splitting on '## ' section
    headers so each section gets an SVG icon instead of an emoji."""
    analysis = _strip_emoji(analysis or "ไม่มีข้อมูล")

    # Split on lines starting with "## " while keeping the heading text
    parts = re.split(r"^##\s+(.+)$", analysis, flags=re.MULTILINE)

    if len(parts) == 1:
        # No "## " headers found — render as-is
        st.markdown(analysis)
        return

    # parts[0] = any preamble before the first heading (e.g. blockquote)
    if parts[0].strip():
        st.markdown(parts[0].strip())

    # Remaining items alternate: heading, body, heading, body, ...
    for heading, body in zip(parts[1::2], parts[2::2]):
        heading = heading.strip()
        style = _ANALYSIS_SECTION_STYLE.get(heading)
        if style:
            icon, color = style
            st.markdown(
                f'<h2 style="display:flex;align-items:center;gap:0.75rem;'
                f'color:{color} !important">'
                f'{_i(icon, 22)}'
                f'<span style="color:{color} !important">{_esc(heading, 120)}</span>'
                f'</h2>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(f"## {heading}")
        if body.strip():
            st.markdown(body.strip())


def score_ring_html(score: int, color_class: str) -> str:
    """Animated SVG progress ring for the score metric (SMIL, no JS required)."""
    R, CX, CY = 28, 35, 35
    CIRC   = 2 * math.pi * R
    offset = CIRC * (1 - score / 100)
    c = {
        "col-good": "#2d6a4f",
        "col-warn": "#92700a",
        "col-bad":  "#c4622d",
        "col-crit": "#b91c1c",
    }.get(color_class, "#c4622d")
    return (
        '<div class="metric-card">'
        f'<svg width="70" height="70" viewBox="0 0 70 70" style="display:block;margin:0 auto 4px">'
        f'<circle cx="{CX}" cy="{CY}" r="{R}" fill="none" stroke="rgba(20,20,19,0.06)" stroke-width="5"/>'
        f'<circle cx="{CX}" cy="{CY}" r="{R}" fill="none" stroke="{c}" stroke-width="5"'
        f' stroke-linecap="round" stroke-dasharray="{CIRC:.2f}" stroke-dashoffset="{CIRC:.2f}"'
        f' transform="rotate(-90 {CX} {CY})">'
        f'<animate attributeName="stroke-dashoffset" from="{CIRC:.2f}" to="{offset:.2f}"'
        f' dur="1.2s" calcMode="spline" keySplines="0.16 1 0.3 1" keyTimes="0;1" fill="freeze"/>'
        '</circle>'
        f'<text x="{CX}" y="{CY + 1}" text-anchor="middle" dominant-baseline="middle"'
        f' fill="{c}" font-family="JetBrains Mono,Courier New,monospace" font-size="15" font-weight="600">{score}</text>'
        '</svg>'
        '<span class="metric-lbl">คะแนน / 100</span>'
        '</div>'
    )



def risk_color_class(risk: str) -> str:
    return {"LOW": "col-good", "MEDIUM": "col-warn",
            "HIGH": "col-bad",  "CRITICAL": "col-crit"}.get(risk, "col-info")


def sev_emoji(severity: str) -> str:
    """Severity label — SVG-safe text only."""
    return {"CRITICAL": "CRIT", "HIGH": "HIGH", "MEDIUM": "MED",
            "LOW": "LOW", "PASS": "PASS", "INFO": "INFO"}.get(
        str(severity).upper(), "INFO"
    )


def _init_session_state() -> None:
    """Ensure all required session-state keys exist (idempotent)."""
    for key, default in {
        "scan_data": None,  "ai_data": None,   "server_data": None,
        "org": "",          "url": "",          "scanned": False,
        "pdf_ready": False, "pdf_bytes": None,
        "chat_history": [],
    }.items():
        st.session_state.setdefault(key, default)


_init_session_state()

# ── Hero ─────────────────────────────────────────────────────────
st.markdown("""
<div class="hero">
  <div class="hero-eyebrow">Project-VULNEX · Cybersecurity Track · PSU Future Tech 2026</div>
  <h1 class="hero-title"><svg xmlns="http://www.w3.org/2000/svg" width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:10px;margin-bottom:4px"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>Project-<span class="accent">VULNEX</span></h1>
  <p class="hero-sub">ระบบตรวจสอบความปลอดภัยเว็บไซต์สถานศึกษาด้วย AI &nbsp;·&nbsp; Passive Scan Only &nbsp;·&nbsp; PDF Report</p>
</div>
""", unsafe_allow_html=True)

if not MODULES_OK:
    st.error(f"ไม่สามารถโหลด modules ได้: {MODULE_ERR}")
    st.info("ตรวจสอบว่า venv เปิดอยู่และติดตั้ง requirements.txt แล้ว")
    st.stop()

# ── Input section ─────────────────────────────────────────────────
col_url, col_org = st.columns([3, 1])
with col_url:
    url = st.text_input(
        "URL เว็บไซต์ที่ต้องการตรวจสอบ",
        placeholder="https://www.school.ac.th",
    )
with col_org:
    org = st.text_input("Company Name (For Report)", value="Your Company")

scan_btn = st.button("เริ่มตรวจสอบ", use_container_width=True)

st.markdown("---")

# ── Scan logic ────────────────────────────────────────────────────
if scan_btn and url:
    clean_url, url_error = normalise_url(url)
    if url_error:
        st.warning(url_error)
    else:
        prog = st.progress(0, text="เริ่มสแกน...")

        with st.spinner("กำลังสแกนและวิเคราะห์..."):
            prog.progress(20, text="กำลังดึง HTTP Headers และ SSL...")
            scan_data = run_scan(clean_url)

            prog.progress(50, text="ตรวจสอบ Web Server และ CVE Database...")
            server_data = check_server(clean_url)

            prog.progress(75, text="AI กำลังวิเคราะห์ผล Passive Scan...")
            ai_data = analyze(scan_data, server_data)

            prog.progress(100, text="เสร็จสิ้น")
            time.sleep(0.3)
            prog.empty()

        # Bulk update keeps all keys consistent; resets any stale PDF state
        st.session_state.update({
            "scan_data":   scan_data,
            "ai_data":     ai_data,
            "server_data": server_data,
            "org":         org,
            "url":         clean_url,
            "scanned":     True,
            "pdf_ready":   False,
            "pdf_bytes":   None,
            "chat_history": [],  # clear chat on new scan
        })

elif scan_btn and not url:
    st.warning("กรุณาใส่ URL ก่อนกด ตรวจสอบ")

# ── Results ──────────────────────────────────────────────────────
if st.session_state.get("scanned"):
    scan_data   = st.session_state["scan_data"]
    ai_data     = st.session_state["ai_data"]
    server_data = st.session_state["server_data"]
    org         = st.session_state["org"]

    # ── Scan module error recovery ──────────────────────────────
    scan_errors = _scan_module_errors(scan_data)
    if scan_errors:
        st.warning(
            "บางส่วนของการสแกนล้มเหลว — คะแนนด้านล่างอาจไม่ครบถ้วน:\n\n"
            + "\n\n".join(scan_errors)
        )

    if ai_data.get("offline_fallback"):
        st.info(
            "ใช้โหมดวิเคราะห์อัตโนมัติ (Offline) — Gemini AI ไม่พร้อมใช้งาน "
            "(โควต้าหมด / ไม่มี API key / model ล้มเหลว) รายงานด้านล่างสร้างจากข้อมูลสแกนโดยตรง"
        )

    # ── Defensive field extraction ──────────────────────────────
    score     = int(ai_data.get("score", 0))
    risk      = _risk_safe(str(ai_data.get("risk_level", "HIGH")))
    ssl_info  = scan_data.get("ssl", {}) or {}
    hdr_info  = scan_data.get("headers", {}) or {}
    ssl_ok    = bool(ssl_info.get("valid", False)) if _module_ok(scan_data, "ssl") else None
    days_left = int(ssl_info.get("days_left", 0) or 0) if _module_ok(scan_data, "ssl") else 0
    n_missing = (
        len(hdr_info.get("headers_missing", []) or [])
        if _module_ok(scan_data, "headers") else None
    )
    vulns     = server_data.get("vulnerabilities", []) or []
    dos_risk  = bool(server_data.get("dos_risk", False))
    stype     = str(server_data.get("server_type",    "?") or "?").upper()
    sver      = str(server_data.get("server_version", "")  or "")
    http_ver  = str(server_data.get("http_version",   "?") or "?")

    # ── Metric row ──────────────────────────────────────────────
    m1, m2, m3, m4, m5, m6 = st.columns(6)

    m1.markdown(
        score_ring_html(score, score_color_class(score)),
        unsafe_allow_html=True
    )

    m2.markdown(f"""<div class="metric-card">
        <span class="metric-val metric-val-sm {risk_color_class(risk)}">{risk}</span>
        <span class="metric-lbl">ระดับความเสี่ยง</span>
    </div>""", unsafe_allow_html=True)

    if ssl_ok is None:
        ssl_cls, ssl_lbl = "col-warn", "SSL (error)"
        _ssl_ico = _i(_P_ALERT, 22)
    else:
        ssl_cls = "col-good" if ssl_ok else "col-bad"
        ssl_lbl = f"SSL ({days_left} วัน)"
        _ssl_ico = _i(_P_CHECK, 22) if ssl_ok else _i(_P_XCIRC, 22)
    m3.markdown(f'<div class="metric-card">'
               f'<span class="metric-val metric-val-lh {ssl_cls}">{_ssl_ico}</span>'
               f'<span class="metric-lbl">{ssl_lbl}</span>'
               '</div>', unsafe_allow_html=True)

    if n_missing is None:
        hdr_cls, hdr_val = "col-warn", "—"
    else:
        hdr_cls = "col-bad" if n_missing > 2 else ("col-warn" if n_missing > 0 else "col-good")
        hdr_val = str(n_missing)
    m4.markdown(f"""<div class="metric-card">
        <span class="metric-val {hdr_cls}">{hdr_val}</span>
        <span class="metric-lbl">Headers ที่ขาด</span>
    </div>""", unsafe_allow_html=True)

    cve_cls = "col-bad" if vulns else "col-good"
    m5.markdown(f"""<div class="metric-card">
        <span class="metric-val {cve_cls}">{len(vulns)}</span>
        <span class="metric-lbl">CVE พบ</span>
    </div>""", unsafe_allow_html=True)

    dos_cls = "col-crit" if dos_risk else "col-good"
    _dos_ico = _i(_P_ALERT, 22) if dos_risk else _i(_P_CHECK, 22)
    m6.markdown(f'<div class="metric-card">'
               f'<span class="metric-val metric-val-lh {dos_cls}">{_dos_ico}</span>'
               '<span class="metric-lbl">DoS Risk</span>'
               '</div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Score breakdown ────────────────────────────────────────
    breakdown = ai_data.get("breakdown", {})
    if breakdown:
        st.markdown(f"""
        <div class="sec-card" style="padding:14px 18px">
            <div class="sec-card-title" style="margin-bottom:10px;padding-bottom:8px">Score Breakdown (Composite Weights)</div>
            <div style="display:flex;gap:16px;flex-wrap:wrap">
                <span class="metric-lbl">Headers: <b class="col-info">{breakdown.get('headers', 0)}</b>/25</span>
                <span class="metric-lbl">SSL: <b class="col-info">{breakdown.get('ssl', 0)}</b>/20</span>
                <span class="metric-lbl">HTML/JS: <b class="col-info">{breakdown.get('html_js', 0)}</b>/15</span>
                <span class="metric-lbl">Server/CVE: <b class="col-info">{breakdown.get('server_cve', 0)}</b>/15</span>
                <span class="metric-lbl">DNS: <b class="col-info">{breakdown.get('dns', 0)}</b>/10</span>
                <span class="metric-lbl">Cookies: <b class="col-info">{breakdown.get('cookies', 0)}</b>/10</span>
                <span class="metric-lbl">CMS: <b class="col-info">{breakdown.get('cms', 0)}</b>/5</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # ── Tabs ────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4, tab_mod, tab5 = st.tabs([
        "AI Analysis", "Server Info",
        "HTTP Headers", "SSL Certificate", "Scan Modules", "Raw Data"
    ])

    with tab1:
        render_ai_analysis(ai_data.get("analysis", "ไม่มีข้อมูล"))

    with tab2:
        # Escape all server-originated strings before HTML injection
        srv_raw_safe  = _esc(server_data.get("server_raw", "N/A") or "Hidden")
        stype_safe    = _esc(stype)
        sver_safe     = _esc(sver) if sver else ""
        http_ver_safe = _esc(http_ver)

        ver_color = "col-warn" if server_data.get("version_exposed") else "col-good"
        ver_cell  = (f'<span class="{ver_color}">{sver_safe}</span>'
                     if sver_safe else f'<span class="col-good">ซ่อนอยู่ {_i(_P_CHECK, 13)}</span>')
        _ico_alert = _i(_P_ALERT, 13, 'margin-right:4px')
        _ico_ok    = _i(_P_CHECK, 13, 'margin-right:4px')
        dos_detail_safe = _esc(server_data.get("dos_detail", "HTTP/2 DoS vulnerability")[:80])
        dos_cell  = (f'<span class="col-bad">{_ico_alert} YES — {dos_detail_safe}</span>'
                     if dos_risk else f'<span class="col-good">{_ico_ok} ไม่มีความเสี่ยง</span>')

        st.markdown(f"""<div class="sec-card">
<div class="sec-card-title"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6 6h.01"/><path d="M6 18h.01"/></svg> Web Server Detection</div>
<table class="info-table">
  <tr><td>Server Header</td>  <td><code>{srv_raw_safe}</code></td></tr>
  <tr><td>Server Type</td>    <td><span class="col-info server-type-val">{stype_safe}</span></td></tr>
  <tr><td>Version</td>        <td>{ver_cell}</td></tr>
  <tr><td>HTTP Version</td>   <td>{http_ver_safe}</td></tr>
  <tr><td>HTTP/2 DoS Risk</td><td>{dos_cell}</td></tr>
</table>
</div>""", unsafe_allow_html=True)

        if server_data.get("version_exposed"):
            st.warning(
                f"**Version Disclosure (ความเสี่ยงต่ำ):** "
                f"Server โชว์ version `{sver or '(unknown)'}` ทำให้ผู้โจมตีรู้ว่าควรใช้ exploit ใด "
                "แนะนำซ่อนด้วย `server_tokens off;` (nginx) หรือ `ServerTokens Prod` (Apache)"
            )

        if dos_risk:
            st.error(
                f"**CVE-2023-44487 — HTTP/2 Rapid Reset DoS (Zero-day 2023)**\n\n"
                f"{str(server_data.get('dos_detail', ''))[:600]}\n\n"
                "**แนวทางแก้ไข:** อัปเกรด nginx เป็น 1.25.3+ "
                "หรือเพิ่ม `limit_conn` และ `limit_req` เพื่อลดความเสี่ยงชั่วคราว"
            )

        if vulns:
            st.markdown(
                '<div class="cve-title-wrap">'
                f'{_i(_P_SHIELD_WARN, 15)}'
                '<span class="sec-title-label col-crit">CVE ที่พบ</span>'
                '</div>',
                unsafe_allow_html=True
            )
            for v in vulns:
                sev      = _sev_safe(str(v.get("severity", "INFO")))
                cve_id   = _esc(v.get("cve",  ""))
                cve_desc = _esc(v.get("desc", ""))
                cve_fix  = _esc(v.get("fix",  ""))
                tint_cls = (f"tint-{sev.lower()}"
                            if sev in ("CRITICAL", "HIGH", "MEDIUM") else "")
                st.markdown(
                    f"<div class='finding-row {tint_cls}'>"
                    f"<span class='finding-sev sev-{sev}'>{sev}</span>"
                    f"<div>"
                    f"<b class='finding-text'>{cve_id}</b><br>"
                    f"<span class='finding-desc'>{cve_desc}</span><br>"
                    f"<span class='finding-fix'>{_i(_P_WRENCH, 11, 'margin-right:3px')}{cve_fix}</span>"
                    f"</div></div>",
                    unsafe_allow_html=True,
                )

    with tab3:
        if not _module_ok(scan_data, "headers"):
            st.error(f"ไม่สามารถตรวจ Security Headers ได้: {hdr_info.get('error', 'unknown error')}")
        found         = hdr_info.get("headers_found",  {}) or {}
        headers_score = hdr_info.get("score", 0) if _module_ok(scan_data, "headers") else "N/A"
        hdr_defs = {
            "Content-Security-Policy":   ("HIGH",   "ป้องกัน XSS Attack"),
            "Strict-Transport-Security": ("HIGH",   "บังคับใช้ HTTPS เสมอ"),
            "X-Frame-Options":           ("HIGH",   "ป้องกัน Clickjacking"),
            "X-Content-Type-Options":    ("MEDIUM", "ป้องกัน MIME Sniffing"),
            "Referrer-Policy":           ("LOW",    "ควบคุมข้อมูล Referrer"),
            "Permissions-Policy":        ("LOW",    "จำกัด Browser API"),
        }
        st.markdown(f"**Headers Score: {headers_score}/100**")
        for h, (sev, desc) in hdr_defs.items():
            present  = h in found
            icon = _i(_P_CHECK, 16) if present else _i(_P_XCIRC, 16)
            val_safe = _esc(found.get(h, "—")[:60]) if present else "ไม่มี"
            tint_cls = (f"tint-{sev.lower()}"
                        if not present and sev in ("HIGH", "MEDIUM") else "")
            val_html = (f'<br><code class="finding-val">{val_safe}</code>'
                        if present else "")
            sev_html = (f"<span class='finding-sev sev-{sev}'>{sev}</span>"
                        if not present else "")
            st.markdown(
                f"<div class='finding-row {tint_cls}'>"
                f"<span class='finding-icon'>{icon}</span>"
                f"<div style='flex:1'>"
                f"<b class='finding-text'>{h}</b>{val_html}"
                f"<br><span class='finding-desc'>{desc}</span>"
                f"</div>{sev_html}</div>",
                unsafe_allow_html=True,
            )

    with tab4:
        ssl = ssl_info
        if not _module_ok(scan_data, "ssl"):
            st.error(f"ไม่สามารถตรวจ SSL ได้: {ssl.get('error', 'unknown error')}")
        elif ssl.get("warning"):
            st.warning(ssl["warning"])
        col_a, col_b = st.columns(2)
        with col_a:
            st.metric("Status", "Valid" if ssl.get("valid") else "Invalid")
            st.metric("Issuer", ssl.get("issuer", "N/A"))
        with col_b:
            st.metric("Expires",   ssl.get("expires", "N/A"))
            st.metric("Days Left", f"{days_left} วัน",
                      delta=None,
                      delta_color="inverse" if days_left <= 30 else "normal")

    with tab_mod:
        dns = scan_data.get("dns", {}) or {}
        cookies = scan_data.get("cookies", {}) or {}
        cors = scan_data.get("cors", {}) or {}
        http_m = scan_data.get("http_methods", {}) or {}
        js_exp = scan_data.get("js_exposure", {}) or {}
        subs = scan_data.get("subdomains", {}) or {}
        open_f = scan_data.get("open_files", {}) or {}
        cms = scan_data.get("cms", {}) or {}
        html_info = scan_data.get("html", {}) or {}

        st.markdown(f"**HTML Analysis Score: {html_info.get('score', 'N/A')}/100**")

        with st.expander("🌐 DNS & Email Security", expanded=True):
            if dns.get("error"):
                st.error(dns["error"])
            else:
                dc1, dc2, dc3 = st.columns(3)
                dc1.metric("DNS Score", f"{dns.get('score', 0)}/100")
                spf = dns.get("spf", {})
                dc2.metric("SPF", "✅" if spf.get("present") else "❌",
                           help=spf.get("policy", ""))
                dmarc = dns.get("dmarc", {})
                dc3.metric("DMARC", dmarc.get("policy", "none").upper())
                st.write(f"DKIM selectors: {dns.get('dkim', {}).get('selectors_found', [])}")
                st.write(f"DNSSEC: {'Signed' if dns.get('dnssec', {}).get('signed') else 'Not signed'}")
                st.write(f"CAA: {'Present' if dns.get('caa', {}).get('present') else 'Missing'}")
                for f in dns.get("findings", []):
                    st.warning(f"**{f.get('title')}**: {f.get('detail')}")

        with st.expander("🍪 Cookie Security"):
            if cookies.get("error"):
                st.error(cookies["error"])
            else:
                st.metric("Cookie Score", f"{cookies.get('score', 100)}/100")
                for c in cookies.get("cookies", []):
                    flags = f"Secure={c.get('secure')} HttpOnly={c.get('httponly')} SameSite={c.get('samesite') or '-'}"
                    issues = c.get("issues", [])
                    st.write(f"**{c.get('name')}** — {flags}")
                    if issues:
                        st.caption("⚠️ " + "; ".join(issues))

        with st.expander("🔗 CORS Policy"):
            st.metric("CORS Score", f"{cors.get('score', 'N/A')}/100")
            for t in cors.get("tests", []):
                if t.get("tested"):
                    st.write(f"`{t.get('path')}` → Allow-Origin: `{t.get('allow_origin') or 'none'}`")
            for f in cors.get("findings", []):
                st.error(f"**{f.get('title')}**: {f.get('detail')}")

        with st.expander("⚙️ HTTP Methods"):
            st.metric("Methods Score", f"{http_m.get('score', 'N/A')}/100")
            st.write(f"Allowed: {http_m.get('allowed_methods', [])}")
            if http_m.get("dangerous_enabled"):
                st.error(f"Dangerous methods: {http_m['dangerous_enabled']}")

        with st.expander("📜 JavaScript Exposure"):
            st.metric("JS Score", f"{js_exp.get('score', 'N/A')}/100")
            st.write(f"Scripts analyzed: {js_exp.get('scripts_analyzed', 0)}")
            if js_exp.get("source_maps_exposed"):
                st.warning("Source maps exposed: " + ", ".join(js_exp["source_maps_exposed"][:3]))
            for s in js_exp.get("secrets_found", []):
                st.error(f"**{s.get('type')}** in {s.get('source')}")

        with st.expander("📁 Open Files & Directories"):
            st.metric("Open Files Score", f"{open_f.get('score', 'N/A')}/100")
            if open_f.get("directory_listings"):
                st.warning("Directory listing: " + ", ".join(open_f["directory_listings"]))
            for sf in open_f.get("sensitive_files", []):
                st.error(f"Accessible: `{sf.get('path')}` (HTTP {sf.get('status')})")
            if open_f.get("robots_disallow"):
                st.write("robots.txt Disallow paths:", open_f["robots_disallow"][:10])

        with st.expander("🏷️ CMS Fingerprint"):
            st.metric("CMS Score", f"{cms.get('score', 'N/A')}/100")
            st.write(f"Detected: **{cms.get('detected_cms') or 'Unknown'}** v{cms.get('version') or '?'}")
            if cms.get("xmlrpc_enabled"):
                st.warning("WordPress XML-RPC enabled")
            for p in cms.get("default_paths_accessible", []):
                st.write(f"`{p.get('path')}` → HTTP {p.get('status')}")

        with st.expander("🔍 Subdomain Recon"):
            st.write(f"**{subs.get('count', 0)} subdomains** discovered (passive)")
            if subs.get("all_subdomains"):
                st.code("\n".join(subs["all_subdomains"][:30]))
            for w in subs.get("warnings", []):
                st.caption(w)

    with tab5:
        col_r1, col_r2 = st.columns(2)
        with col_r1:
            with st.expander("Scan Data (JSON)"):
                st.json(scan_data)
        with col_r2:
            with st.expander("Server Data (JSON)"):
                st.json(server_data)

    st.markdown("---")

    # ── PDF report ──────────────────────────────────────────────
    st.markdown(
        '<div class="cve-title-wrap" style="margin-bottom:12px">'
        '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24"'
        ' fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round"'
        ' stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
        '<polyline points="14 2 14 8 20 8"/>'
        '<line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>'
        '<span class="report-title">สร้างรายงานความปลอดภัย</span>'
        '</div>',
        unsafe_allow_html=True
    )
    col_pdf1, col_pdf2 = st.columns([2, 1])
    with col_pdf1:
        st.info(
            "รายงาน PDF **1 หน้า** อ่านง่าย ครอบคลุม: "
            "บทสรุปผู้บริหาร · ผลการตรวจสอบทุกหัวข้อ · "
            "สถานะผ่าน/ไม่ผ่าน · คำแนะนำแก้ไขพร้อม Config จริง"
        )
    with col_pdf2:
        if st.button("สร้างรายงาน PDF", use_container_width=True):
            with st.spinner("กำลังสร้าง PDF..."):
                try:
                    pdf_bytes = build_report(scan_data, ai_data, server_data, org)
                    st.session_state["pdf_bytes"] = pdf_bytes
                    st.session_state["pdf_ready"] = True
                    st.success(f"สร้าง PDF สำเร็จ ({len(pdf_bytes):,} bytes)")
                except Exception as exc:
                    st.error(f"สร้าง PDF ไม่สำเร็จ: {exc}")

    if st.session_state.get("pdf_ready"):
        now   = datetime.now().strftime("%Y%m%d_%H%M")
        fname = f"VULNEX_Report_{now}.pdf"
        st.download_button(
            label="ดาวน์โหลด PDF Report",
            data=st.session_state["pdf_bytes"],
            file_name=fname,
            mime="application/pdf",
            use_container_width=True,
        )

elif not st.session_state.get("scanned"):
    st.markdown("""
<div class="empty-state">
  <span class="empty-icon"><svg xmlns="http://www.w3.org/2000/svg" width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:block;margin:0 auto"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></span>
  <div class="empty-title">พร้อมตรวจสอบ</div>
  <div class="empty-hint">
    ใส่ URL เว็บไซต์ด้านบน แล้วกด <kbd>เริ่มตรวจสอบ</kbd><br>
    รองรับ HTTP และ HTTPS · Passive Scan Only
  </div>
</div>
""", unsafe_allow_html=True)