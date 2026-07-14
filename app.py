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
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

# Thailand is fixed UTC+7 (no DST) — used so the PDF filename timestamp matches
# the Thai scan time in the report, regardless of the server's timezone.
_ICT = timezone(timedelta(hours=7))

import streamlit as st

# ── Page config ──────────────────────────────────────────────────
# MUST be the first Streamlit command. NOTE: the st.secrets→env bridge below runs
# AFTER this on purpose — touching st.secrets before set_page_config can raise
# "set_page_config must be the first command", which our try/except would swallow,
# silently leaving the keys unbridged on deploy (→ no AI).
st.set_page_config(
    page_title="Project-VULNEX",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",   # sidebar removed — keep it shut
)

# ── Secrets → env bridge (Streamlit Cloud fix) ───────────────────
# Streamlit Cloud supplies API keys via st.secrets (secrets.toml), NOT a .env file.
# ai_engine reads keys with os.getenv(), so on deploy — where there is no .env —
# GEMINI_KEYS/OPENROUTER would be empty and the app falls to OFFLINE (no AI at all).
# Copy every top-level string secret into os.environ BEFORE ai_engine is imported
# (it's imported lazily much further down), so the key pool is populated on deploy.
# Set when the env var is missing OR empty; try/except → no secrets.toml locally is
# fine (there .env drives everything).
try:
    for _sk, _sv in st.secrets.items():
        if isinstance(_sv, str) and _sv and not (os.environ.get(_sk) or "").strip():
            os.environ[_sk] = _sv
except Exception:
    pass  # no secrets.toml (local dev) — rely on .env / real environment variables

# ── Custom CSS ───────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def _img_data_uri(path: str) -> str:
    """Encode a local image file as a base64 data: URI for inline HTML use.

    Cached: the hero JPG is ~827 KB → ~1.1 MB base64 string. Streamlit reruns
    the whole script on every interaction, so without memoising this the image
    would be re-read and re-encoded on every rerun. The path is static, so one
    encode per server process is enough."""
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    mime = {"jpg": "jpeg", "jpeg": "jpeg", "png": "png",
            "webp": "webp", "gif": "gif"}.get(ext, "jpeg")
    with open(path, "rb") as f:
        b64 = base64.b64encode(f.read()).decode("ascii")
    return f"data:image/{mime};base64,{b64}"


# Inject the base64-embedded Thai @font-face + the main stylesheet. Both live in
# ui_shared so the scan page and the user-manual page can never drift apart
# visually. The sidebar navigation has been removed — the scan page has no
# top-left nav; the manual page carries its own "back" button instead.
from ui_shared import inject_base_styles, manual_anchor_html, render_footer

inject_base_styles()

# ── Authentication gate (MANDATORY) ──────────────────────────────
# Login is required before anything else. require_auth() draws the login/signup
# screen and st.stop()s the script when the visitor is not authenticated, so the
# scanner is unreachable without an account — there is no bypass. When authed it
# renders the account bar (+ logout) and returns the user. supabase_client is the
# server-side data layer using the project SECRET key (never sent to the browser;
# the st.secrets→env bridge above makes SUPABASE_* visible to it on deploy).
from auth import require_auth, get_client_meta
import supabase_client as _db

_auth_user = require_auth()
_auth_uid  = _auth_user.get("id")

# ── Import scanning / AI modules ─────────────────────────────────
# Only is_safe_host (the SSRF guard used by normalise_url) is imported up front:
# it's pure-stdlib and instant. The heavy modules are deferred — scanner pulls in
# httpx / lxml / cryptography / dnspython (~0.4 s) and ai_engine pulls in
# google-generativeai (~0.6 s), neither of which is needed until the user
# actually scans or builds a report. Importing them lazily inside those handlers
# lets the hero + input paint immediately on first load instead of waiting ~1 s
# for the whole stack. Python caches modules, so the cost is paid once, on the
# first scan (where the skeleton is already covering the wait).
try:
    from utils.network import is_safe_host

    MODULES_OK = True
    MODULE_ERR = ""
except ImportError as exc:
    MODULES_OK = False
    MODULE_ERR = str(exc)


@st.cache_resource(show_spinner=False)
def _prepare_pdf_engine() -> bool:
    """
    เตรียมเอนจินสร้างรายงาน (ดาวน์โหลดเบราว์เซอร์ Chromium ของ Playwright)
    ครั้งเดียวต่อเซิร์ฟเวอร์ — รันฝั่งเซิร์ฟเวอร์ ไม่ใช่เครื่องผู้ใช้
    ผู้ใช้ปลายทางจึงไม่ต้องติดตั้งหรือทำอะไรเพิ่ม
    """
    from report_generator import ensure_browser
    ensure_browser()
    return True


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


def _site_slug(url: str) -> str:
    """Short, filename-safe slug for the scanned site, taken from the same URL
    the user entered (the report's Target field). Keeps a leading ``www`` plus
    the main domain label, e.g. ``https://www.technictani.ac.th`` → ``www_technictani``
    (``www.school.ac.th`` → ``www_school``). Returns "" if no host."""
    try:
        host = (urlparse(url).hostname or "").strip().lower()
    except Exception:
        host = ""
    labels = [l for l in host.split(".") if l]
    if not labels:
        return ""
    keep = labels[:2] if labels[0] == "www" and len(labels) > 1 else labels[:1]
    return re.sub(r"[^A-Za-z0-9_]+", "_", "_".join(keep)).strip("_")


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


def _render_module_insight(mod_key: str) -> None:
    """Render the per-module 'AI summary' card at the top of a Scan-Modules dropdown:
    how we scanned (static) + what's wrong & how to fix (AI, rule-based fallback).
    Rendered as Markdown (no raw HTML) so scanned values can't inject markup."""
    ins = (st.session_state.get("module_insights") or {}).get(mod_key)
    if not ins:
        return
    method = ins.get("method", "")
    if method:
        st.markdown(f"**วิธีสแกน:** {method}")
    badge = "AI สรุป" if ins.get("source") == "ai" else "สรุปอัตโนมัติ"
    tone = "🟢" if ins.get("status") == "ok" else "🟠"
    st.markdown(f"**{tone} {badge}**")
    st.markdown(ins.get("summary", ""))
    st.divider()


@st.fragment
def render_pdf_report_section() -> None:
    """Render the 'สร้างรายงานความปลอดภัย' (create PDF) section in isolation.

    Why a fragment: building the PDF blocks for several seconds (Gemini + the
    Playwright/Chromium render). If that runs during a normal full-script rerun,
    Streamlit keeps the previous frame mounted while the new one is computed, and
    the long pause makes that stale frame visible — every card/heading/row looked
    split into a normal copy above and a faded 'ghost' below. @st.fragment scopes
    the button's rerun to THIS section only, so nothing above it is re-rendered
    and there's no page-wide ghost. Inside the fragment the heavy work also runs
    OUTSIDE the st.columns block, so the info-box + button row finishes rendering
    before blocking and never duplicates either.
    """
    scan_data   = st.session_state.get("scan_data") or {}
    ai_data     = st.session_state.get("ai_data") or {}
    server_data = st.session_state.get("server_data") or {}
    org         = st.session_state.get("org", "") or ""

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
    pdf_requested = False
    with col_pdf2:
        if st.button("สร้างรายงาน PDF", use_container_width=True):
            pdf_requested = True

    # งานหนักทำ "นอก" st.columns: ปิดแถวคอลัมน์ให้เสร็จก่อนค่อยบล็อก — กันแถว
    # กล่องข้อมูล+ปุ่มแสดงซ้อนกันสองชุดระหว่างรอ
    if pdf_requested:
        _pdf_t0     = time.time()
        _pdf_req_at = _db._iso()
        _scan_db_id = st.session_state.get("scan_db_id")
        _uid        = (st.session_state.get("auth_user") or {}).get("id")
        try:
            # Lazy import (deferred from module top). ai_engine is already loaded
            # post-scan; the html/report modules are cheap.
            from ai_engine        import generate_report_analysis
            from html_generator   import build_report_html
            from report_generator import html_to_pdf
            # 0) เตรียมเอนจิน (ดาวน์โหลด Chromium บนเซิร์ฟเวอร์ครั้งแรกครั้งเดียว)
            with st.spinner("กำลังเตรียมเอนจินสร้างรายงาน "
                            "(ครั้งแรกของเซิร์ฟเวอร์อาจใช้เวลาสักครู่)..."):
                _prepare_pdf_engine()
            with st.spinner("กำลังเรียก AI (คีย์สำรอง) และสร้างรายงาน..."):
                # 1) เรียก Gemini ด้วยคีย์สำรอง (GEMINI_API_KEY_Backup)
                report_ai = generate_report_analysis(scan_data, server_data, ai_data)
                # 2) ประกอบ HTML รายงาน 1 หน้า
                report_html = build_report_html(
                    scan_data, report_ai, server_data,
                    org.strip(),       # ว่าง → html_generator ดึงชื่อจาก <title>/โดเมนเอง
                )
                # 3) แปลง HTML 1 หน้า → PDF 1 หน้า ด้วย Playwright (Chromium)
                pdf_bytes = html_to_pdf(report_html)
                st.session_state["pdf_bytes"] = pdf_bytes
                st.session_state["pdf_ready"] = True
            if report_ai.get("offline_fallback"):
                st.info(
                    "หมายเหตุ: ใช้บทวิเคราะห์ offline ในรายงาน "
                    "(คีย์สำรองเรียก Gemini ไม่ได้ หรือไม่ได้ตั้งค่า "
                    "GEMINI_API_KEY_Backup)"
                )
            st.success(f"สร้าง PDF สำเร็จ ({len(pdf_bytes):,} bytes)")
            # audit the successful build (best-effort)
            try:
                _pdf_ms = int((time.time() - _pdf_t0) * 1000)
                _db.insert_report_event(
                    scan_id=_scan_db_id, user_id=_uid, status="success",
                    ai_provider="offline" if report_ai.get("offline_fallback") else "ai",
                    ai_offline_fallback=bool(report_ai.get("offline_fallback")),
                    duration_ms=_pdf_ms, page_count=1, file_size_bytes=len(pdf_bytes),
                    requested_at=_pdf_req_at,
                )
                _db.mark_scan_pdf(_scan_db_id, _pdf_ms)
                _db.log_user_event(
                    user_id=_uid, session_id=st.session_state.get("auth_login_event"),
                    event_type="pdf_generated", scan_id=_scan_db_id,
                    detail={"bytes": len(pdf_bytes)}, duration_ms=_pdf_ms,
                    meta=get_client_meta(),
                )
            except Exception:
                pass
        except Exception as exc:
            st.error(f"สร้าง PDF ไม่สำเร็จ: {exc}")
            try:
                _db.insert_report_event(
                    scan_id=_scan_db_id, user_id=_uid, status="error",
                    duration_ms=int((time.time() - _pdf_t0) * 1000),
                    error_type=type(exc).__name__, error_message=str(exc),
                    requested_at=_pdf_req_at,
                )
            except Exception:
                pass

    if st.session_state.get("pdf_ready"):
        now    = datetime.now(_ICT).strftime("%Y%m%d_%H%M")
        slug   = _site_slug(st.session_state.get("url", ""))
        prefix = f"{slug}_" if slug else ""
        fname  = f"{prefix}VULNEX_Report_{now}.pdf"
        st.download_button(
            label="ดาวน์โหลด PDF Report",
            data=st.session_state["pdf_bytes"],
            file_name=fname,
            mime="application/pdf",
            use_container_width=True,
        )


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
        '<div class="metric-card" style="--i:0">'
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



def _scan_skeleton_html(stage: str, pct: int, target: str) -> str:
    """Skeleton loading screen shown live while the scan + AI analysis run.

    Mirrors the eventual results layout (metric row · score breakdown · tabs ·
    panel) with shimmer placeholders, a rotating radar sweep, and a staged
    progress bar. It is rendered into an ``st.empty()`` placeholder *before* the
    blocking scan and cleared once results are ready — Streamlit flushes the
    delta mid-script (the same reason the old progress bar updated live), so the
    shimmer animates in-browser during the synchronous scan. This replaces the
    bare spinner with a structured skeleton (the product-register loading
    pattern). prefers-reduced-motion freezes the shimmer via the global reduce
    rule; the layout still communicates "loading". ``target`` is pre-escaped."""
    cards = "".join(
        f'<div class="skel-card" style="--i:{i}">'
        '<div class="skel skel-ring"></div>'
        '<div class="skel skel-line sm"></div></div>'
        for i in range(6)
    )
    bars = "".join('<div class="skel skel-bar"></div>' for _ in range(7))
    tabs = "".join('<div class="skel skel-tab"></div>' for _ in range(6))
    return (
        '<div class="scan-loading">'
        '<div class="scan-loading-head">'
        '<span class="scan-radar">'
        '<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">'
        '<circle cx="24" cy="24" r="20" stroke="var(--accent-glow)" stroke-width="1.5"/>'
        '<circle cx="24" cy="24" r="12.5" stroke="var(--accent-glow)" stroke-width="1"/>'
        '<circle cx="24" cy="24" r="2.6" fill="var(--accent)"/>'
        '<g class="sweep"><path d="M24 24 L24 4 A20 20 0 0 1 41.3 14 Z" fill="url(#rdr)"/></g>'
        '<defs><linearGradient id="rdr" x1="24" y1="24" x2="40" y2="9" gradientUnits="userSpaceOnUse">'
        '<stop stop-color="var(--accent)" stop-opacity="0.5"/>'
        '<stop offset="1" stop-color="var(--accent)" stop-opacity="0"/>'
        '</linearGradient></defs></svg></span>'
        '<div class="scan-loading-meta">'
        f'<div class="scan-loading-title">กำลังตรวจสอบ <span class="scan-target">{target}</span></div>'
        f'<div class="scan-loading-stage">{stage}</div>'
        '</div>'
        f'<span class="scan-loading-pct">{pct}%</span>'
        '</div>'
        f'<div class="scan-progress"><div class="scan-progress-bar" style="--p:{pct/100:.2f}"></div></div>'
        f'<div class="skel-metrics">{cards}</div>'
        '<div class="skel-breakdown">'
        '<div class="skel skel-line" style="width:32%;height:11px"></div>'
        f'<div class="skel-bars">{bars}</div>'
        '</div>'
        f'<div class="skel-tabs">{tabs}</div>'
        '<div class="skel-panel">'
        '<div class="skel skel-line" style="width:78%"></div>'
        '<div class="skel skel-line" style="width:92%"></div>'
        '<div class="skel skel-line" style="width:64%"></div>'
        '<div class="skel skel-block"></div>'
        '</div>'
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
        "chat_history": [], "module_insights": {},
        "scan_db_id": None,
    }.items():
        st.session_state.setdefault(key, default)


_init_session_state()

# ── Hero ─────────────────────────────────────────────────────────
_hero_img_uri = _img_data_uri(os.path.join("src", "Public", "Hero_Image.jpg"))
st.markdown(f"""
<div class="hero">
  <div class="hero-grid">
    <div class="hero-text">
      <div class="hero-eyebrow">Project-VULNEX · Cybersecurity Track · PSU Future Tech 2026</div>
      <h1 class="hero-title"><svg xmlns="http://www.w3.org/2000/svg" width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:10px;margin-bottom:4px"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>Project-<span class="accent">VULNEX</span></h1>
      <p class="hero-sub">ระบบตรวจสอบความปลอดภัยเว็บไซต์สถานศึกษาด้วย AI &nbsp;·&nbsp; Passive Scan Only &nbsp;·&nbsp; PDF Report</p>
    </div>
    <div class="hero-visual">
      <img src="{_hero_img_uri}" alt="Project-VULNEX banner" />
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

if not MODULES_OK:
    st.error(f"ไม่สามารถโหลด modules ได้: {MODULE_ERR}")
    st.info("ตรวจสอบว่า venv เปิดอยู่และติดตั้ง requirements.txt แล้ว")
    st.stop()

# ── Input section ─────────────────────────────────────────────────
# The institution name is no longer typed in here — the PDF report
# auto-derives it from the site <title>/domain (org="" → html_generator
# fallback). That slot now links to the step-by-step user manual, which opens
# IN PLACE (same tab) — the manual page has its own back button to return.
# Bottom-aligned to share the URL baseline.
col_url, col_manual = st.columns([3, 1], vertical_alignment="bottom")
with col_url:
    url = st.text_input(
        "URL เว็บไซต์ที่ต้องการตรวจสอบ",
        placeholder="https://www.school.ac.th",
    )
with col_manual:
    # The original styled anchor button (.manual-link-btn), restored. It opens
    # the manual in the SAME tab via target="_self" inside manual_anchor_html
    # (Streamlit would otherwise default the link to a new tab).
    st.markdown(
        manual_anchor_html("manual-link-btn", "คู่มือการใช้งาน"),
        unsafe_allow_html=True,
    )

org = ""  # institution name auto-derived in the report (no manual input)

scan_btn = st.button("เริ่มตรวจสอบ", use_container_width=True)

st.markdown("---")

# ── Scan logic ────────────────────────────────────────────────────
if scan_btn and url:
    clean_url, url_error = normalise_url(url)
    if url_error:
        st.warning(url_error)
    else:
        # Skeleton loading screen (replaces the bare spinner). Rendered into a
        # placeholder before the blocking work; Streamlit flushes the delta
        # mid-script, so the shimmer + radar sweep animate in-browser during the
        # synchronous scan. The placeholder is cleared once results are ready.
        loading_ph  = st.empty()
        target_safe = _esc(clean_url, 80)
        loading_ph.markdown(
            _scan_skeleton_html("กำลังเตรียมโมดูลสแกน…", 8, target_safe),
            unsafe_allow_html=True,
        )

        # Lazy import (deferred from module top so the hero paints fast). Paid
        # once, on the first scan — the skeleton above already covers the wait.
        try:
            from scanner             import run_scan
            from scanner.server_info import check_server
            from ai_engine           import analyze
        except ImportError as exc:
            loading_ph.empty()
            st.error(f"ไม่สามารถโหลดโมดูลสแกนได้: {exc}")
            st.info("ตรวจสอบว่า venv เปิดอยู่และติดตั้ง requirements.txt แล้ว")
            st.stop()

        loading_ph.markdown(
            _scan_skeleton_html(
                "กำลังเชื่อมต่อและสแกน Passive (Headers · SSL · DNS · CVE)…",
                18, target_safe),
            unsafe_allow_html=True,
        )

        # run_scan (11 modules) and check_server both spend their time waiting on
        # the network. Run them concurrently so the server/CVE probe overlaps the
        # scan instead of adding its round-trip on top. They stay architecturally
        # separate (check_server is not inside run_scan) — only their waits share.
        _scan_t0    = time.time()
        _started_iso = _db._iso()
        with ThreadPoolExecutor(max_workers=2) as _ex:
            _fut_scan   = _ex.submit(run_scan, clean_url)
            _fut_server = _ex.submit(check_server, clean_url)
            scan_data   = _fut_scan.result()
            server_data = _fut_server.result()

        loading_ph.markdown(
            _scan_skeleton_html("AI กำลังวิเคราะห์ผลการสแกน…", 72, target_safe),
            unsafe_allow_html=True,
        )
        ai_data = analyze(scan_data, server_data)

        # Per-module AI summaries for the Scan Modules dropdowns (one batched, cached
        # call; rule-based fallback inside). Best-effort — never let it break a scan.
        try:
            from module_insight import build_module_insights
            module_insights = build_module_insights(scan_data, server_data)
        except Exception:
            module_insights = {}

        loading_ph.markdown(
            _scan_skeleton_html("เสร็จสิ้น — กำลังแสดงผล", 100, target_safe),
            unsafe_allow_html=True,
        )
        time.sleep(0.25)
        loading_ph.empty()

        _scan_dur_ms  = int((time.time() - _scan_t0) * 1000)
        _finished_iso = _db._iso()

        # Persist the scan for this logged-in user (best-effort — telemetry must
        # never break a scan). Stores the wide columns + full JSONB blobs + per-
        # module rows + CVEs, and an audit user_event. scan_db_id links the later
        # PDF-build event to this scan row.
        _scan_db_id = None
        try:
            _meta = get_client_meta()
            _scan_db_id = _db.insert_scan(
                user_id=_auth_uid, url=clean_url,
                scan_data=scan_data, server_data=server_data, ai_data=ai_data,
                started_at=_started_iso, finished_at=_finished_iso,
                duration_ms=_scan_dur_ms, meta=_meta,
            )
            _db.log_user_event(
                user_id=_auth_uid, session_id=st.session_state.get("auth_login_event"),
                event_type="scan_completed", scan_id=_scan_db_id, target_url=clean_url,
                detail={"score": ai_data.get("score"), "risk": ai_data.get("risk_level"),
                        "cve": len(server_data.get("vulnerabilities", []) or [])},
                duration_ms=_scan_dur_ms, meta=_meta,
            )
        except Exception:
            pass

        # Bulk update keeps all keys consistent; resets any stale PDF state
        st.session_state.update({
            "scan_data":       scan_data,
            "ai_data":         ai_data,
            "server_data":     server_data,
            "org":             org,
            "url":             clean_url,
            "scanned":         True,
            "pdf_ready":       False,
            "pdf_bytes":       None,
            "chat_history":    [],  # clear chat on new scan
            "module_insights": module_insights,
            "scan_db_id":      _scan_db_id,
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

    m2.markdown(f"""<div class="metric-card" style="--i:1">
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
    m3.markdown(f'<div class="metric-card" style="--i:2">'
               f'<span class="metric-val metric-val-lh {ssl_cls}">{_ssl_ico}</span>'
               f'<span class="metric-lbl">{ssl_lbl}</span>'
               '</div>', unsafe_allow_html=True)

    if n_missing is None:
        hdr_cls, hdr_val = "col-warn", "—"
    else:
        hdr_cls = "col-bad" if n_missing > 2 else ("col-warn" if n_missing > 0 else "col-good")
        hdr_val = str(n_missing)
    m4.markdown(f"""<div class="metric-card" style="--i:3">
        <span class="metric-val {hdr_cls}">{hdr_val}</span>
        <span class="metric-lbl">Headers ที่ขาด</span>
    </div>""", unsafe_allow_html=True)

    cve_cls = "col-bad" if vulns else "col-good"
    m5.markdown(f"""<div class="metric-card" style="--i:4">
        <span class="metric-val {cve_cls}">{len(vulns)}</span>
        <span class="metric-lbl">CVE พบ</span>
    </div>""", unsafe_allow_html=True)

    dos_cls = "col-crit" if dos_risk else "col-good"
    _dos_ico = _i(_P_ALERT, 22) if dos_risk else _i(_P_CHECK, 22)
    m6.markdown(f'<div class="metric-card" style="--i:5">'
               f'<span class="metric-val metric-val-lh {dos_cls}">{_dos_ico}</span>'
               '<span class="metric-lbl">DoS Risk</span>'
               '</div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Score breakdown — animated composite-weight meters ──────
    # Each module's earned weighted points are drawn as a fill bar (scaleX =
    # earned / max) that grows on reveal; the fill colour signals how well the
    # module scored (green ≥80% · amber ≥50% · clay below), so the composite is
    # legible at a glance, not just a row of fractions.
    breakdown = ai_data.get("breakdown", {})
    if breakdown:
        # Render only ACTIVE composite components with their effective (renormalized)
        # weights. Suspended modules are omitted from `_weights`, so they no longer
        # appear here at full marks; weights are scaled to still sum to 100.
        _brk_w = breakdown.get("_weights") or {
            "headers": 25, "ssl": 20, "html_js": 15, "server_cve": 15,
            "dns": 10, "cookies": 10, "cms": 5,
        }
        _brk_lbl = {
            "headers": "Headers", "ssl": "SSL", "html_js": "HTML/JS",
            "server_cve": "Server/CVE", "dns": "DNS", "cookies": "Cookies", "cms": "CMS",
        }
        brk_items = []
        idx = 0
        for key in ("headers", "ssl", "html_js", "server_cve", "dns", "cookies", "cms"):
            if key not in _brk_w:          # suspended / absent module — not shown
                continue
            mx    = _brk_w[key]
            label = _brk_lbl[key]
            val   = float(breakdown.get(key, 0) or 0)
            ratio = max(0.0, min(1.0, val / mx)) if mx else 0.0
            cls   = "brk-good" if ratio >= 0.8 else ("brk-warn" if ratio >= 0.5 else "brk-bad")
            disp  = int(round(val)) if abs(val - round(val)) < 0.05 else round(val, 1)
            brk_items.append(
                f'<div class="brk-item {cls}" style="--i:{idx}">'
                f'<div class="brk-row"><span class="brk-label">{label}</span>'
                f'<span class="brk-val"><b>{disp}</b>/{mx}</span></div>'
                f'<div class="brk-track"><div class="brk-fill" style="--r:{ratio:.3f}"></div></div>'
                f'</div>'
            )
            idx += 1
        st.markdown(
            '<div class="sec-card brk-card">'
            '<div class="sec-card-title" style="margin-bottom:14px">Score Breakdown (Composite Weights)</div>'
            f'<div class="brk-grid">{"".join(brk_items)}</div>'
            '</div>',
            unsafe_allow_html=True,
        )

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

        # ── Active scan modules (passive) ───────────────────────
        with st.expander("🌐 DNS & Email Security", expanded=True):
            _render_module_insight("dns")
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
            _render_module_insight("cookies")
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

        with st.expander("📜 JavaScript Exposure"):
            _render_module_insight("js_exposure")
            st.metric("JS Score", f"{js_exp.get('score', 'N/A')}/100")
            st.write(f"Scripts analyzed: {js_exp.get('scripts_analyzed', 0)}")
            if js_exp.get("source_maps_exposed"):
                st.warning("Source maps exposed: " + ", ".join(js_exp["source_maps_exposed"][:3]))
            for s in js_exp.get("secrets_found", []):
                st.error(f"**{s.get('type')}** in {s.get('source')}")

        with st.expander("🔍 Subdomain Recon"):
            _render_module_insight("subdomains")
            st.write(f"**{subs.get('count', 0)} subdomains** discovered (passive)")
            if subs.get("all_subdomains"):
                st.code("\n".join(subs["all_subdomains"][:30]))
            for w in subs.get("warnings", []):
                st.caption(w)

        # These probes are non-passive and are suspended (see scanner._SUSPENDED_MODULES).
        # They render here ONLY if re-enabled; while suspended they appear in the grouped
        # "ระงับชั่วคราว" section below with a plain-language reason instead.
        if not cors.get("suspended"):
            with st.expander("🔗 CORS Policy"):
                st.metric("CORS Score", f"{cors.get('score', 'N/A')}/100")
                for t in cors.get("tests", []):
                    if t.get("tested"):
                        st.write(f"`{t.get('path')}` → Allow-Origin: `{t.get('allow_origin') or 'none'}`")
                for f in cors.get("findings", []):
                    st.error(f"**{f.get('title')}**: {f.get('detail')}")

        if not http_m.get("suspended"):
            with st.expander("⚙️ HTTP Methods"):
                st.metric("Methods Score", f"{http_m.get('score', 'N/A')}/100")
                st.write(f"Allowed: {http_m.get('allowed_methods', [])}")
                if http_m.get("dangerous_enabled"):
                    st.error(f"Dangerous methods: {http_m['dangerous_enabled']}")

        if not open_f.get("suspended"):
            with st.expander("📁 Open Files & Directories"):
                st.metric("Open Files Score", f"{open_f.get('score', 'N/A')}/100")
                if open_f.get("directory_listings"):
                    st.warning("Directory listing: " + ", ".join(open_f["directory_listings"]))
                for sf in open_f.get("sensitive_files", []):
                    st.error(f"Accessible: `{sf.get('path')}` (HTTP {sf.get('status')})")
                if open_f.get("robots_disallow"):
                    st.write("robots.txt Disallow paths:", open_f["robots_disallow"][:10])

        if not cms.get("suspended"):
            with st.expander("🏷️ CMS Fingerprint"):
                st.metric("CMS Score", f"{cms.get('score', 'N/A')}/100")
                st.write(f"Detected: **{cms.get('detected_cms') or 'Unknown'}** v{cms.get('version') or '?'}")
                if cms.get("xmlrpc_enabled"):
                    st.warning("WordPress XML-RPC enabled")
                for p in cms.get("default_paths_accessible", []):
                    st.write(f"`{p.get('path')}` → HTTP {p.get('status')}")

        # ── Temporarily suspended modules (grouped, each with a friendly “why”) ──
        _susp_why = {
            "cors": (
                "🔗 CORS Policy",
                "หัวข้อนี้ต้อง “แกล้ง” ส่งคำขอโดยสวมรอยเป็นเว็บไซต์แปลกหน้า เพื่อทดสอบว่าเซิร์ฟเวอร์เผลอ "
                "เปิดให้เว็บอื่นดึงข้อมูลข้ามไปได้ไหม เท่ากับเป็นการ “ลองยิงทดสอบ” มากกว่าการอ่านข้อมูล "
                "เฉย ๆ เพื่อให้ VULNEX ยังเป็นเครื่องมือแบบ “ดูอย่างเดียว ไม่แตะต้อง” อย่างแท้จริง เราจึง "
                "พักไว้ก่อน แล้วจะพากลับมาในโหมดที่ปลอดภัยและเลือกเปิดใช้เองได้ 🔧",
            ),
            "http_methods": (
                "⚙️ HTTP Methods",
                "การตรวจนี้ต้องลองส่งคำสั่งจริงอย่าง PUT และ DELETE ไปยังเว็บ เพื่อดูว่าเซิร์ฟเวอร์เผลอเปิด "
                "ช่องให้ใครมา “เพิ่มหรือลบ” ข้อมูลได้ไหม ถึงจะทำอย่างระมัดระวัง แต่ก็นับเป็นการ “แตะ” "
                "ระบบจริง ไม่ใช่แค่การดู เราจึงขอพักไว้ก่อนเพื่อความปลอดภัยของเว็บไซต์ที่ถูกตรวจ แล้วจะปรับ "
                "ให้รัดกุมขึ้นในอัปเดตถัดไป ✨",
            ),
            "open_files": (
                "📁 Open Files & Directories",
                "หัวข้อนี้จะ “เดา” ชื่อไฟล์และโฟลเดอร์ที่มักถูกลืมเปิดทิ้งไว้ (เช่นไฟล์ตั้งค่า .env หรือไฟล์สำรอง "
                "ข้อมูล) แล้วไล่ “เคาะประตู” ทีละอันว่าเข้าถึงได้ไหม การไล่เดา–ลองเปิดแบบนี้ออกแนวค้นหา "
                "เชิงรุก มากกว่าการเปิดดูหน้าเว็บตามปกติ เราจึงพักไว้ให้ตรงกับหลักการ Passive แล้วจะพากลับมา "
                "แบบปลอดภัยยิ่งขึ้น 🔒",
            ),
            "cms": (
                "🏷️ CMS Fingerprint",
                "ส่วนที่เดาว่าเว็บใช้ระบบอะไร (เช่น WordPress) จากหน้าเว็บทำได้แบบดู ๆ ก็จริง แต่โมดูลนี้ยัง "
                "แอบ “ลองเรียก” ไฟล์ระบบอย่าง xmlrpc.php และเคาะหน้า /wp-admin/ เพิ่มด้วย ซึ่งเลยเส้น "
                "“ดูอย่างเดียว” ไปนิดหนึ่ง เราจึงพักทั้งหัวข้อไว้ก่อนเพื่อคงความเป็น Passive ให้ครบถ้วน แล้วค่อย "
                "เปิดเฉพาะส่วนที่ปลอดภัยในภายหลัง 🧩",
            ),
        }
        _susp_now = [
            (k, m) for k, m in
            (("cors", cors), ("http_methods", http_m), ("open_files", open_f), ("cms", cms))
            if m.get("suspended")
        ]
        if _susp_now:
            st.markdown("---")
            st.markdown("#### ⏸ โมดูลที่ระงับชั่วคราว (Temporarily Suspended)")
            st.caption(
                "โมดูลกลุ่มนี้จำเป็นต้อง “ลองแตะ” หรือ “ลองเดา” กับเว็บไซต์เป้าหมาย ซึ่งเกินขอบเขตการสแกน "
                "แบบ Passive (ดูอย่างเดียว ไม่รบกวนระบบ) ของ VULNEX จึงพักไว้ชั่วคราว — กดเปิดแต่ละหัวข้อ "
                "เพื่อดูเหตุผลแบบเข้าใจง่าย แล้วเราจะพากลับมาในเวอร์ชันที่ปลอดภัยและเลือกเปิดใช้ได้เอง"
            )
            for _key, _mod in _susp_now:
                _label, _why = _susp_why[_key]
                with st.expander(_label):
                    st.info("**ระงับชั่วคราว — รอการอัปเดตในอนาคต**")
                    st.markdown(_why)

    with tab5:
        col_r1, col_r2 = st.columns(2)
        with col_r1:
            with st.expander("Scan Data (JSON)"):
                st.json(scan_data)
        with col_r2:
            with st.expander("Server Data (JSON)"):
                st.json(server_data)

    st.markdown("---")

    # ── PDF report — isolated @st.fragment so the multi-second build reruns
    #    only this section and can't ghost/duplicate the rest of the page ──
    render_pdf_report_section()

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

# Site footer — credibility references (renders on every state)
render_footer()