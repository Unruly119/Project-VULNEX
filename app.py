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

import time
import ipaddress
import html as _html
from datetime import datetime
from urllib.parse import urlparse

import streamlit as st

# ── Page config ──────────────────────────────────────────────────
st.set_page_config(
    page_title="Project-VULNEX",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Custom CSS ───────────────────────────────────────────────────
st.markdown("""
<style>
/* ════════════════════════════════════════════════════════════════
   PROJECT-VULNEX  ·  Design Token System
   ════════════════════════════════════════════════════════════════ */
@import url('https://fonts.googleapis.com/css2?family=Noto+Sans+Thai:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    --bg:        #0d1117;
    --surface-1: #161b22;
    --surface-2: #21262d;
    --border:    #30363d;
    --border-hi: #484f58;

    --cyan:      #22d3ee;
    --cyan-dark: #06b6d4;
    --cyan-dim:  rgba(34, 211, 238, 0.10);
    --cyan-glow: rgba(34, 211, 238, 0.22);

    --c-crit:     #fca5a5;
    --c-crit-bg:  rgba(127, 29, 29, 0.22);
    --c-crit-bdr: rgba(153, 27, 27, 0.65);
    --c-high:     #f87171;
    --c-high-bg:  rgba(248, 113, 113, 0.09);
    --c-high-bdr: rgba(248, 113, 113, 0.38);
    --c-med:      #fbbf24;
    --c-med-bg:   rgba(251, 191, 36, 0.08);
    --c-med-bdr:  rgba(251, 191, 36, 0.36);
    --c-low:      #4ade80;
    --c-low-bg:   rgba(74, 222, 128, 0.07);
    --c-low-bdr:  rgba(74, 222, 128, 0.33);

    --text:   #e6edf3;
    --muted:  #8b949e;
    --subtle: #484f58;

    --font-ui:   'Noto Sans Thai', system-ui, sans-serif;
    --font-mono: 'JetBrains Mono', 'Fira Code', monospace;

    --r-sm: 4px;
    --r-md: 8px;
    --r-lg: 12px;

    --ease: cubic-bezier(0.25, 1, 0.5, 1);
    --t-fast: 120ms;
    --t-base: 220ms;
    --t-slow: 380ms;
}

@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
        animation-duration:  0.01ms !important;
        transition-duration: 0.01ms !important;
    }
}

@keyframes fade-up {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
}
@keyframes dot-breathe {
    0%, 100% { opacity: 0.04; }
    50%       { opacity: 0.09; }
}
@keyframes crit-pulse {
    0%   { box-shadow: 0 0 0 0   rgba(220, 38, 38, 0.40); }
    70%  { box-shadow: 0 0 0 7px rgba(220, 38, 38, 0.00); }
    100% { box-shadow: 0 0 0 0   rgba(220, 38, 38, 0.00); }
}

html, body, [class*="css"] { font-family: var(--font-ui) !important; }
#MainMenu, footer, header   { visibility: hidden; }
.stDeployButton             { display: none; }
.stApp                      { background: var(--bg); }
.block-container            { padding-top: 1.5rem !important; max-width: 1140px; }

/* ── Hero ─────────────────────────────────────────────────────── */
.hero-wrap {
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: var(--r-lg);
    padding: 28px 32px 24px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
}
.hero-wrap::before {
    content: '';
    position: absolute;
    inset: 0;
    background-image:
        radial-gradient(circle at 76% 50%, rgba(34,211,238,.07) 0%, transparent 52%),
        radial-gradient(var(--border) 1px, transparent 1px);
    background-size: 100% 100%, 22px 22px;
    animation: dot-breathe 5s ease-in-out infinite;
    pointer-events: none;
}
.hero-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: var(--cyan-dim);
    border: 1px solid rgba(34,211,238,.20);
    color: var(--cyan);
    font-family: var(--font-mono);
    font-size: 10px;
    padding: 3px 10px;
    border-radius: var(--r-sm);
    letter-spacing: .07em;
    margin-bottom: 10px;
    position: relative;
}
.hero-badge::before { content: '▶'; font-size: 7px; opacity: .55; }
.hero-title {
    font-size: 30px;
    font-weight: 700;
    color: var(--text);
    margin: 0 0 5px;
    letter-spacing: -.015em;
    text-wrap: balance;
    position: relative;
}
.hero-title span { color: var(--cyan); text-shadow: 0 0 28px rgba(34,211,238,.20); }
.hero-sub { font-size: 13px; color: var(--muted); margin: 0; position: relative; }

/* ── Metric cards ─────────────────────────────────────────────── */
.metric-card {
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    padding: 15px 12px;
    text-align: center;
    animation: fade-up var(--t-slow) var(--ease) both;
    transition: border-color var(--t-base) var(--ease),
                transform     var(--t-base) var(--ease);
}
.metric-card:hover { border-color: var(--border-hi); transform: translateY(-2px); }
.metric-val {
    font-family: var(--font-mono);
    font-size: 26px;
    font-weight: 600;
    display: block;
    margin-bottom: 4px;
    line-height: 1;
}
.metric-lbl { font-size: 11px; color: var(--muted); }

/* Colour utility classes — no more inline hex in Python */
.col-good { color: var(--c-low);  }
.col-warn { color: var(--c-med);  }
.col-bad  { color: var(--c-high); }
.col-crit { color: var(--c-crit); }
.col-info { color: var(--cyan);   }

/* ── Risk badge ───────────────────────────────────────────────── */
.risk-badge { display: inline-block; padding: 4px 12px; border-radius: var(--r-sm); font-family: var(--font-mono); font-size: 12px; font-weight: 700; letter-spacing: .05em; }
.risk-LOW      { background: var(--c-low-bg);  border: 1px solid var(--c-low-bdr);  color: var(--c-low);  }
.risk-MEDIUM   { background: var(--c-med-bg);  border: 1px solid var(--c-med-bdr);  color: var(--c-med);  }
.risk-HIGH     { background: var(--c-high-bg); border: 1px solid var(--c-high-bdr); color: var(--c-high); }
.risk-CRITICAL { background: var(--c-crit-bg); border: 1px solid var(--c-crit-bdr); color: var(--c-crit); animation: crit-pulse 2s ease-out infinite; }

/* ── Severity badge ───────────────────────────────────────────── */
.finding-sev { font-family: var(--font-mono); font-size: 10px; padding: 2px 8px; border-radius: var(--r-sm); flex-shrink: 0; margin-top: 2px; letter-spacing: .04em; }
.sev-CRITICAL { background: var(--c-crit-bg); border: 1px solid var(--c-crit-bdr); color: var(--c-crit); }
.sev-HIGH     { background: var(--c-high-bg); border: 1px solid var(--c-high-bdr); color: var(--c-high); }
.sev-MEDIUM   { background: var(--c-med-bg);  border: 1px solid var(--c-med-bdr);  color: var(--c-med);  }
.sev-LOW      { background: var(--c-low-bg);  border: 1px solid var(--c-low-bdr);  color: var(--c-low);  }
.sev-PASS     { background: var(--c-low-bg);  border: 1px solid var(--c-low-bdr);  color: var(--c-low);  }

/* ── Finding rows — severity via background tint + full border ── */
.finding-row {
    display: flex; gap: 12px; align-items: flex-start;
    padding: 10px 14px;
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    margin-bottom: 7px;
    transition: background var(--t-fast);
}
.finding-row:hover         { background: var(--surface-2); }
.finding-row.tint-critical { background: var(--c-crit-bg); border-color: var(--c-crit-bdr); }
.finding-row.tint-high     { background: var(--c-high-bg); border-color: var(--c-high-bdr); }
.finding-row.tint-medium   { background: var(--c-med-bg);  border-color: var(--c-med-bdr);  }

/* ── Section card ─────────────────────────────────────────────── */
.sec-card { background: var(--surface-1); border: 1px solid var(--border); border-radius: var(--r-lg); padding: 20px 22px; margin-bottom: 16px; }
.sec-card-title {
    font-size: 13px; font-weight: 600; color: var(--cyan);
    font-family: var(--font-mono);
    margin-bottom: 14px; padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 8px;
}

/* ── Server info table ────────────────────────────────────────── */
.info-table              { width: 100%; border-collapse: collapse; font-size: 13px; }
.info-table tr + tr td   { border-top: 1px solid var(--border); }
.info-table td           { padding: 9px 8px; vertical-align: middle; }
.info-table td:first-child { color: var(--muted); width: 42%; }
.info-table td:last-child  { color: var(--text); }

/* ── Mono tag ─────────────────────────────────────────────────── */
.mono-tag { font-family: var(--font-mono); font-size: 11px; color: #79c0ff; background: rgba(121,192,255,.08); padding: 2px 7px; border-radius: var(--r-sm); }

/* ── Empty state ──────────────────────────────────────────────── */
.empty-state { text-align: center; padding: 60px 24px; color: var(--muted); animation: fade-up var(--t-slow) var(--ease); }
.empty-icon  { font-size: 52px; display: block; margin-bottom: 16px; }
.empty-title { font-size: 16px; font-weight: 600; color: var(--text); margin-bottom: 8px; }
.empty-hint  { font-size: 13px; line-height: 1.8; }
.empty-hint kbd { display: inline-block; background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--r-sm); padding: 1px 7px; font-family: var(--font-mono); font-size: 11px; color: var(--cyan); }

/* ── Streamlit overrides ──────────────────────────────────────── */
div.stButton > button {
    background: var(--cyan) !important; color: #000 !important;
    font-weight: 700 !important; border: none !important;
    border-radius: var(--r-md) !important; padding: 10px 0 !important;
    font-family: var(--font-ui) !important; font-size: 15px !important;
    transition: background var(--t-base) var(--ease),
                transform   var(--t-base) var(--ease),
                box-shadow  var(--t-base) var(--ease) !important;
}
div.stButton > button:hover {
    background: var(--cyan-dark) !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 22px var(--cyan-glow) !important;
}
div.stButton > button:focus-visible {
    outline: 2px solid var(--cyan) !important; outline-offset: 2px !important;
}

div[data-testid="stDownloadButton"] > button {
    background: #1f6feb !important; color: #fff !important;
    font-weight: 700 !important; border: none !important;
    border-radius: var(--r-md) !important;
    transition: background var(--t-base) !important;
}
div[data-testid="stDownloadButton"] > button:hover { background: #388bfd !important; }

div[data-baseweb="input"] > div {
    background: var(--surface-1) !important;
    border-color: var(--border) !important;
    border-radius: var(--r-md) !important;
    transition: border-color var(--t-fast) !important;
}
div[data-baseweb="input"] > div:focus-within {
    border-color: var(--cyan) !important;
    box-shadow: 0 0 0 1px var(--cyan) !important;
}

.stProgress > div > div { background: var(--cyan) !important; }

.stTabs [role="tablist"]        { border-bottom-color: var(--border) !important; }
.stTabs [role="tab"]            { color: var(--muted) !important; font-family: var(--font-ui); font-size: 14px; transition: color var(--t-fast) !important; }
.stTabs [aria-selected="true"]  { color: var(--cyan) !important; border-bottom-color: var(--cyan) !important; }
.stTabs [role="tab"]:hover      { color: var(--text) !important; }

.streamlit-expanderHeader { background: var(--surface-1) !important; border-radius: var(--r-md) !important; border-color: var(--border) !important; }

hr { border-color: var(--border) !important; }
</style>
""", unsafe_allow_html=True)

# ── Import scanning / AI modules ─────────────────────────────────
try:
    from scanner             import run_scan
    from ai_engine           import analyze
    from scanner.server_info import check_server
    from report_generator    import build_report
    MODULES_OK = True
    MODULE_ERR = ""
except ImportError as exc:
    MODULES_OK = False
    MODULE_ERR = str(exc)

# ────────────────────────────────────────────────────────────────
# Utility functions
# ────────────────────────────────────────────────────────────────

def _is_safe_host(hostname: str) -> bool:
    """
    Reject private / loopback / link-local IP addresses (SSRF mitigation).
    Domain names always pass — only numeric IP literals are checked.
    """
    try:
        addr = ipaddress.ip_address(hostname)
        return not (addr.is_loopback or addr.is_private or addr.is_link_local)
    except ValueError:
        return True                     # hostname is a domain name — allow


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
        if not _is_safe_host(parsed.hostname):
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
    return "col-bad"


def risk_color_class(risk: str) -> str:
    return {"LOW": "col-good", "MEDIUM": "col-warn",
            "HIGH": "col-bad",  "CRITICAL": "col-crit"}.get(risk, "col-info")


def sev_emoji(severity: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🟢",      "PASS": "✅", "INFO":  "🔵"}.get(
        str(severity).upper(), "⚪"
    )


def _init_session_state() -> None:
    """Ensure all required session-state keys exist (idempotent)."""
    for key, default in {
        "scan_data": None,  "ai_data": None,   "server_data": None,
        "org": "",          "url": "",          "scanned": False,
        "pdf_ready": False, "pdf_bytes": None,
    }.items():
        st.session_state.setdefault(key, default)


_init_session_state()

# ── Hero ─────────────────────────────────────────────────────────
st.markdown("""
<div class="hero-wrap">
  <div class="hero-badge">PROJECT-VULNEX · CYBERSECURITY TRACK · PSU FUTURE TECH 2026</div>
  <h1 class="hero-title">🛡️ Project-<span>VULNEX</span></h1>
  <p class="hero-sub">ระบบตรวจสอบความปลอดภัยเว็บไซต์สถานศึกษาด้วย AI &nbsp;·&nbsp; Passive Scan Only &nbsp;·&nbsp; ISO/IEC 27001 Report</p>
</div>
""", unsafe_allow_html=True)

if not MODULES_OK:
    st.error(f"❌ ไม่สามารถโหลด modules ได้: {MODULE_ERR}")
    st.info("ตรวจสอบว่า venv เปิดอยู่และติดตั้ง requirements.txt แล้ว")
    st.stop()

# ── Input section ─────────────────────────────────────────────────
col_url, col_org = st.columns([3, 1])
with col_url:
    url = st.text_input(
        "🌐 URL เว็บไซต์ที่ต้องการตรวจสอบ",
        placeholder="https://www.school.ac.th",
    )
with col_org:
    org = st.text_input("🏫 ชื่อองค์กร (สำหรับ Report)", value="วิทยาลัยเทคนิคปัตตานี")

scan_btn = st.button("🔍 เริ่มตรวจสอบ", use_container_width=True)

st.markdown("---")

# ── Scan logic ────────────────────────────────────────────────────
if scan_btn and url:
    clean_url, url_error = normalise_url(url)
    if url_error:
        st.warning(f"⚠️ {url_error}")
    else:
        prog = st.progress(0, text="⚡ เริ่มสแกน...")

        with st.spinner(""):
            prog.progress(20, text="📡 ดึง HTTP Headers และ SSL Certificate...")
            scan_data = run_scan(clean_url)

            prog.progress(50, text="🖥️ ตรวจสอบ Web Server และ CVE Database...")
            server_data = check_server(clean_url)

            prog.progress(75, text="🤖 AI กำลังวิเคราะห์ผล Passive Scan...")
            ai_data = analyze(scan_data)

            prog.progress(100, text="✅ เสร็จสิ้น")
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
        })

elif scan_btn and not url:
    st.warning("⚠️ กรุณาใส่ URL ก่อนกด ตรวจสอบ")

# ── Results ──────────────────────────────────────────────────────
if st.session_state.get("scanned"):
    scan_data   = st.session_state["scan_data"]
    ai_data     = st.session_state["ai_data"]
    server_data = st.session_state["server_data"]
    org         = st.session_state["org"]

    # ── Defensive field extraction ──────────────────────────────
    score     = int(ai_data.get("score", 0))
    risk      = _risk_safe(str(ai_data.get("risk_level", "HIGH")))
    ssl_info  = scan_data.get("ssl", {}) or {}
    ssl_ok    = bool(ssl_info.get("valid", False))
    days_left = int(ssl_info.get("days_left", 0) or 0)
    n_missing = len(scan_data.get("headers", {}).get("headers_missing", []) or [])
    vulns     = server_data.get("vulnerabilities", []) or []
    dos_risk  = bool(server_data.get("dos_risk", False))
    stype     = str(server_data.get("server_type",    "?") or "?").upper()
    sver      = str(server_data.get("server_version", "")  or "")
    http_ver  = str(server_data.get("http_version",   "?") or "?")

    # ── Metric row ──────────────────────────────────────────────
    m1, m2, m3, m4, m5, m6 = st.columns(6)

    m1.markdown(f"""<div class="metric-card">
        <span class="metric-val {score_color_class(score)}">{score}</span>
        <span class="metric-lbl">คะแนน / 100</span>
    </div>""", unsafe_allow_html=True)

    m2.markdown(f"""<div class="metric-card">
        <span class="metric-val {risk_color_class(risk)}" style="font-size:17px">{risk}</span>
        <span class="metric-lbl">ระดับความเสี่ยง</span>
    </div>""", unsafe_allow_html=True)

    ssl_cls = "col-good" if ssl_ok else "col-bad"
    m3.markdown(f"""<div class="metric-card">
        <span class="metric-val {ssl_cls}" style="font-size:22px">{'✅' if ssl_ok else '❌'}</span>
        <span class="metric-lbl">SSL ({days_left} วัน)</span>
    </div>""", unsafe_allow_html=True)

    hdr_cls = "col-bad" if n_missing > 2 else ("col-warn" if n_missing > 0 else "col-good")
    m4.markdown(f"""<div class="metric-card">
        <span class="metric-val {hdr_cls}">{n_missing}</span>
        <span class="metric-lbl">Headers ที่ขาด</span>
    </div>""", unsafe_allow_html=True)

    cve_cls = "col-bad" if vulns else "col-good"
    m5.markdown(f"""<div class="metric-card">
        <span class="metric-val {cve_cls}">{len(vulns)}</span>
        <span class="metric-lbl">CVE พบ</span>
    </div>""", unsafe_allow_html=True)

    dos_cls = "col-crit" if dos_risk else "col-good"
    m6.markdown(f"""<div class="metric-card">
        <span class="metric-val {dos_cls}" style="font-size:22px">{'🚨' if dos_risk else '✅'}</span>
        <span class="metric-lbl">DoS Risk</span>
    </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Tabs ────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🤖 AI Analysis", "🖥️ Server Info", "📋 Headers", "🔒 SSL", "🔬 Raw Data"
    ])

    with tab1:
        st.markdown(ai_data.get("analysis", "ไม่มีข้อมูล"))

    with tab2:
        # Escape all server-originated strings before HTML injection
        srv_raw_safe  = _esc(server_data.get("server_raw", "N/A") or "Hidden")
        stype_safe    = _esc(stype)
        sver_safe     = _esc(sver) if sver else ""
        http_ver_safe = _esc(http_ver)

        ver_color = "col-warn" if server_data.get("version_exposed") else "col-good"
        ver_cell  = (f'<span class="{ver_color}">{sver_safe}</span>'
                     if sver_safe else '<span class="col-good">ซ่อนอยู่ ✅</span>')
        dos_cell  = ('<span class="col-bad">🚨 YES — CVE-2023-44487</span>'
                     if dos_risk else '<span class="col-good">✅ ไม่มีความเสี่ยง</span>')

        st.markdown(f"""<div class="sec-card">
<div class="sec-card-title">🖥️ Web Server Detection</div>
<table class="info-table">
  <tr><td>Server Header</td>  <td><code>{srv_raw_safe}</code></td></tr>
  <tr><td>Server Type</td>    <td><span class="col-info" style="font-weight:600">{stype_safe}</span></td></tr>
  <tr><td>Version</td>        <td>{ver_cell}</td></tr>
  <tr><td>HTTP Version</td>   <td>{http_ver_safe}</td></tr>
  <tr><td>HTTP/2 DoS Risk</td><td>{dos_cell}</td></tr>
</table>
</div>""", unsafe_allow_html=True)

        if server_data.get("version_exposed"):
            st.warning(
                f"⚠️ **Version Disclosure (ความเสี่ยงต่ำ):** "
                f"Server โชว์ version `{sver or '(unknown)'}` ทำให้ผู้โจมตีรู้ว่าควรใช้ exploit ใด "
                "แนะนำซ่อนด้วย `server_tokens off;` (nginx) หรือ `ServerTokens Prod` (Apache)"
            )

        if dos_risk:
            st.error(
                f"🚨 **CVE-2023-44487 — HTTP/2 Rapid Reset DoS (Zero-day 2023)**\n\n"
                f"{str(server_data.get('dos_detail', ''))[:600]}\n\n"
                "**แนวทางแก้ไข:** อัปเกรด nginx เป็น 1.25.3+ "
                "หรือเพิ่ม `limit_conn` และ `limit_req` เพื่อลดความเสี่ยงชั่วคราว"
            )

        if vulns:
            st.markdown("#### 🔴 CVE ที่พบ")
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
                    f"<b style='color:var(--text)'>{cve_id}</b><br>"
                    f"<span style='color:var(--muted);font-size:12px'>{cve_desc}</span><br>"
                    f"<span style='color:var(--cyan);font-size:12px'>🔧 {cve_fix}</span>"
                    f"</div></div>",
                    unsafe_allow_html=True,
                )

    with tab3:
        found         = scan_data.get("headers", {}).get("headers_found",  {}) or {}
        headers_score = scan_data.get("headers", {}).get("score", 0)
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
            icon     = "✅" if present else "❌"
            val_safe = _esc(found.get(h, "—")[:60]) if present else "ไม่มี"
            tint_cls = (f"tint-{sev.lower()}"
                        if not present and sev in ("HIGH", "MEDIUM") else "")
            val_html = (f'<br><code style="font-size:11px;color:#79c0ff">{val_safe}</code>'
                        if present else "")
            sev_html = (f"<span class='finding-sev sev-{sev}'>{sev}</span>"
                        if not present else "")
            st.markdown(
                f"<div class='finding-row {tint_cls}'>"
                f"<span style='font-size:18px;flex-shrink:0'>{icon}</span>"
                f"<div style='flex:1'>"
                f"<b style='color:var(--text)'>{h}</b>{val_html}"
                f"<br><span style='font-size:12px;color:var(--muted)'>{desc}</span>"
                f"</div>{sev_html}</div>",
                unsafe_allow_html=True,
            )

    with tab4:
        ssl = scan_data.get("ssl", {}) or {}
        if ssl.get("warning"):
            st.warning(ssl["warning"])
        col_a, col_b = st.columns(2)
        with col_a:
            st.metric("Status", "✅ Valid" if ssl.get("valid") else "❌ Invalid")
            st.metric("Issuer", ssl.get("issuer", "N/A"))
        with col_b:
            st.metric("Expires",   ssl.get("expires", "N/A"))
            st.metric("Days Left", f"{days_left} วัน",
                      delta=None,
                      delta_color="inverse" if days_left <= 30 else "normal")

    with tab5:
        col_r1, col_r2 = st.columns(2)
        with col_r1:
            with st.expander("📊 Scan Data (JSON)"):
                st.json(scan_data)
        with col_r2:
            with st.expander("🖥️ Server Data (JSON)"):
                st.json(server_data)

    st.markdown("---")

    # ── PDF report ──────────────────────────────────────────────
    st.markdown("### 📄 สร้างรายงาน ISO/IEC 27001")
    col_pdf1, col_pdf2 = st.columns([2, 1])
    with col_pdf1:
        st.info(
            "รายงาน PDF มาตรฐาน **ISO/IEC 27001:2022** ครอบคลุม: "
            "Executive Summary · Technical Findings · CVE Report · "
            "SSL Analysis · AI Analysis · Remediation Plan · Appendix"
        )
    with col_pdf2:
        if st.button("🔧 สร้าง PDF Report", use_container_width=True):
            with st.spinner("กำลังสร้าง PDF..."):
                try:
                    pdf_bytes = build_report(scan_data, ai_data, server_data, org)
                    st.session_state["pdf_bytes"] = pdf_bytes
                    st.session_state["pdf_ready"] = True
                    st.success(f"✅ สร้าง PDF สำเร็จ ({len(pdf_bytes):,} bytes)")
                except Exception as exc:
                    st.error(f"❌ สร้าง PDF ไม่สำเร็จ: {exc}")

    if st.session_state.get("pdf_ready"):
        now   = datetime.now().strftime("%Y%m%d_%H%M")
        fname = f"VULNEX_Report_{now}.pdf"
        st.download_button(
            label="⬇️ ดาวน์โหลด PDF Report",
            data=st.session_state["pdf_bytes"],
            file_name=fname,
            mime="application/pdf",
            use_container_width=True,
        )

elif not st.session_state.get("scanned"):
    st.markdown("""
<div class="empty-state">
  <span class="empty-icon">🛡️</span>
  <div class="empty-title">พร้อมตรวจสอบ</div>
  <div class="empty-hint">
    ใส่ URL เว็บไซต์ด้านบน แล้วกด <kbd>เริ่มตรวจสอบ</kbd><br>
    รองรับ HTTP และ HTTPS · Passive Scan Only
  </div>
</div>
""", unsafe_allow_html=True)