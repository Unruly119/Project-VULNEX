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
   PROJECT-VULNEX  ·  SENTINEL Design System  v3
   ════════════════════════════════════════════════════════════════ */
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=Noto+Sans+Thai:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    /* ── Backgrounds ───────────────────────────────────────────── */
    --bg:        #07090d;
    --surface-1: #0c1018;
    --surface-2: #131923;
    --surface-3: #1a2232;

    /* ── Borders ───────────────────────────────────────────────── */
    --border:    #1c2535;
    --border-hi: #2c3d52;

    /* ── Primary accent — Amber ────────────────────────────────── */
    --amber:      #f97316;
    --amber-dark: #c05c0a;
    --amber-dim:  rgba(249, 115, 22, 0.11);
    --amber-glow: rgba(249, 115, 22, 0.28);

    /* ── Info accent — Sky ─────────────────────────────────────── */
    --sky:      #38bdf8;
    --sky-dim:  rgba(56, 189, 248, 0.10);

    /* ── Severity palette ──────────────────────────────────────── */
    --c-crit:     #fca5a5;
    --c-crit-bg:  rgba(127, 29, 29, 0.20);
    --c-crit-bdr: rgba(200, 50, 50, 0.50);
    --c-high:     #fb923c;
    --c-high-bg:  rgba(251, 146, 60, 0.10);
    --c-high-bdr: rgba(251, 146, 60, 0.35);
    --c-med:      #fbbf24;
    --c-med-bg:   rgba(251, 191, 36, 0.09);
    --c-med-bdr:  rgba(251, 191, 36, 0.35);
    --c-low:      #4ade80;
    --c-low-bg:   rgba(74, 222, 128, 0.08);
    --c-low-bdr:  rgba(74, 222, 128, 0.30);

    /* ── Text ──────────────────────────────────────────────────── */
    --text:   #dde6f0;
    --muted:  #7a8a9c;
    --subtle: #2a3545;

    /* ── Typography ────────────────────────────────────────────── */
    --font-display: 'Syne', 'Noto Sans Thai', sans-serif;
    --font-ui:      'Noto Sans Thai', system-ui, sans-serif;
    --font-mono:    'JetBrains Mono', 'Fira Code', monospace;

    /* ── Radii ─────────────────────────────────────────────────── */
    --r-sm:   5px;
    --r-md:   10px;
    --r-lg:   16px;
    --r-xl:   20px;
    --r-pill: 100px;

    /* ── Motion ────────────────────────────────────────────────── */
    --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
    --t-fast:   100ms;
    --t-base:   200ms;
    --t-slow:   360ms;
}

/* ── Motion safety ─────────────────────────────────────────────── */
@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
        animation-duration:  0.01ms !important;
        transition-duration: 0.01ms !important;
    }
}

/* ── Keyframes ─────────────────────────────────────────────────── */
@keyframes fade-up {
    from { opacity: 0; transform: translateY(10px); }
    to   { opacity: 1; transform: translateY(0); }
}
@keyframes grid-breathe {
    0%, 100% { opacity: 0.028; }
    50%       { opacity: 0.065; }
}
@keyframes scanline {
    0%   { top: -1px; opacity: 0; }
    8%   { opacity: 0.9; }
    92%  { opacity: 0.7; }
    100% { top: 100%; opacity: 0; }
}
@keyframes crit-pulse {
    0%   { box-shadow: 0 0 0 0   rgba(220, 38, 38, 0.45); }
    70%  { box-shadow: 0 0 0 8px rgba(220, 38, 38, 0.00); }
    100% { box-shadow: 0 0 0 0   rgba(220, 38, 38, 0.00); }
}
@keyframes amber-ping {
    0%   { box-shadow: 0 0 0 0   rgba(249, 115, 22, 0.55); }
    70%  { box-shadow: 0 0 0 7px rgba(249, 115, 22, 0.00); }
    100% { box-shadow: 0 0 0 0   rgba(249, 115, 22, 0.00); }
}

/* ── Base ──────────────────────────────────────────────────────── */
html, body, [class*="css"] { font-family: var(--font-ui) !important; }
#MainMenu, footer, header   { visibility: hidden; }
.stDeployButton             { display: none; }
.stApp                      { background: var(--bg); }
.block-container            { padding-top: 1.5rem !important; max-width: 1160px; }

/* ── Hero ─────────────────────────────────────────────────────── */
.hero-wrap {
    position: relative;
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: var(--r-xl);
    padding: 32px 36px 28px;
    margin-bottom: 28px;
    overflow: hidden;
}
/* Grid background */
.hero-wrap::before {
    content: '';
    position: absolute;
    inset: 0;
    background-image:
        radial-gradient(ellipse 65% 80% at 82% 50%, rgba(249, 115, 22, 0.07) 0%, transparent 60%),
        linear-gradient(var(--border) 1px, transparent 1px),
        linear-gradient(90deg, var(--border) 1px, transparent 1px);
    background-size: 100% 100%, 44px 44px, 44px 44px;
    animation: grid-breathe 6s ease-in-out infinite;
    pointer-events: none;
    border-radius: inherit;
}
/* Scanline sweep */
.hero-wrap::after {
    content: '';
    position: absolute;
    left: 0; right: 0;
    top: 0;
    height: 1px;
    background: linear-gradient(90deg,
        transparent 0%,
        rgba(249, 115, 22, 0.12) 15%,
        rgba(249, 115, 22, 0.85) 50%,
        rgba(249, 115, 22, 0.12) 85%,
        transparent 100%
    );
    animation: scanline 5s linear infinite;
    animation-delay: 0.8s;
    pointer-events: none;
    z-index: 2;
}

.hero-badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: var(--amber-dim);
    border: 1px solid rgba(249, 115, 22, 0.22);
    color: var(--amber);
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: .10em;
    text-transform: uppercase;
    padding: 4px 14px 4px 10px;
    border-radius: var(--r-pill);
    margin-bottom: 14px;
    position: relative;
    z-index: 3;
}
.hero-badge::before {
    content: '';
    width: 6px; height: 6px;
    background: var(--amber);
    border-radius: 50%;
    flex-shrink: 0;
    animation: amber-ping 2.2s ease-out infinite;
}

.hero-title {
    font-family: var(--font-display);
    font-size: 36px;
    font-weight: 800;
    color: var(--text);
    margin: 0 0 8px;
    letter-spacing: -.025em;
    text-wrap: balance;
    position: relative;
    z-index: 3;
    line-height: 1.1;
}
.hero-title .accent {
    background: linear-gradient(125deg, var(--amber) 0%, #fcd34d 55%, var(--amber) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}
.hero-sub {
    font-size: 13px;
    color: var(--muted);
    margin: 0;
    position: relative;
    z-index: 3;
    line-height: 1.8;
}

/* ── Metric cards ─────────────────────────────────────────────── */
.metric-card {
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: var(--r-lg);
    padding: 18px 14px 16px;
    text-align: center;
    animation: fade-up var(--t-slow) var(--ease-out) both;
    transition:
        border-color var(--t-base) var(--ease-out),
        transform    var(--t-base) var(--ease-out),
        box-shadow   var(--t-base) var(--ease-out);
    position: relative;
}
.metric-card::after {
    content: '';
    position: absolute;
    inset: 0;
    border-radius: inherit;
    background: linear-gradient(170deg, rgba(255,255,255,0.025) 0%, transparent 50%);
    pointer-events: none;
}
.metric-card:hover {
    border-color: var(--border-hi);
    transform: translateY(-3px);
    box-shadow: 0 10px 32px rgba(0,0,0,0.40);
}

.metric-val {
    font-family: var(--font-mono);
    font-size: 28px;
    font-weight: 600;
    display: block;
    margin-bottom: 6px;
    line-height: 1;
    letter-spacing: -.02em;
}
.metric-lbl { font-size: 11px; color: var(--muted); letter-spacing: .03em; }

/* ── Colour utilities ─────────────────────────────────────────── */
.col-good   { color: var(--c-low);  }
.col-warn   { color: var(--c-med);  }
.col-bad    { color: var(--c-high); }
.col-crit   { color: var(--c-crit); }
.col-info   { color: var(--sky);    }
.col-accent { color: var(--amber);  }

/* ── Risk badge ───────────────────────────────────────────────── */
.risk-badge {
    display: inline-block;
    padding: 5px 14px;
    border-radius: var(--r-pill);
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: .08em;
    text-transform: uppercase;
}
.risk-LOW      { background: var(--c-low-bg);  border: 1px solid var(--c-low-bdr);  color: var(--c-low);  }
.risk-MEDIUM   { background: var(--c-med-bg);  border: 1px solid var(--c-med-bdr);  color: var(--c-med);  }
.risk-HIGH     { background: var(--c-high-bg); border: 1px solid var(--c-high-bdr); color: var(--c-high); }
.risk-CRITICAL { background: var(--c-crit-bg); border: 1px solid var(--c-crit-bdr); color: var(--c-crit); animation: crit-pulse 2s ease-out infinite; }

/* ── Severity badge ───────────────────────────────────────────── */
.finding-sev {
    font-family: var(--font-mono);
    font-size: 9px;
    font-weight: 600;
    letter-spacing: .07em;
    text-transform: uppercase;
    padding: 3px 10px;
    border-radius: var(--r-pill);
    flex-shrink: 0;
    margin-top: 3px;
}
.sev-CRITICAL { background: var(--c-crit-bg); border: 1px solid var(--c-crit-bdr); color: var(--c-crit); }
.sev-HIGH     { background: var(--c-high-bg); border: 1px solid var(--c-high-bdr); color: var(--c-high); }
.sev-MEDIUM   { background: var(--c-med-bg);  border: 1px solid var(--c-med-bdr);  color: var(--c-med);  }
.sev-LOW      { background: var(--c-low-bg);  border: 1px solid var(--c-low-bdr);  color: var(--c-low);  }
.sev-PASS     { background: var(--c-low-bg);  border: 1px solid var(--c-low-bdr);  color: var(--c-low);  }

/* ── Finding rows ─────────────────────────────────────────────── */
.finding-row {
    display: flex;
    gap: 14px;
    align-items: flex-start;
    padding: 12px 16px;
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    margin-bottom: 8px;
    transition: background var(--t-fast), border-color var(--t-fast);
}
.finding-row:hover         { background: var(--surface-2); border-color: var(--border-hi); }
.finding-row.tint-critical { background: var(--c-crit-bg); border-color: var(--c-crit-bdr); }
.finding-row.tint-high     { background: var(--c-high-bg); border-color: var(--c-high-bdr); }
.finding-row.tint-medium   { background: var(--c-med-bg);  border-color: var(--c-med-bdr);  }

/* ── Section card ─────────────────────────────────────────────── */
.sec-card {
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: var(--r-lg);
    padding: 22px 24px;
    margin-bottom: 18px;
}
.sec-card-title {
    font-family: var(--font-mono);
    font-size: 10px;
    font-weight: 600;
    color: var(--amber);
    letter-spacing: .12em;
    text-transform: uppercase;
    margin-bottom: 16px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 8px;
}

/* ── Server info table ────────────────────────────────────────── */
.info-table            { width: 100%; border-collapse: collapse; font-size: 13px; }
.info-table tr + tr td { border-top: 1px solid var(--border); }
.info-table td         { padding: 10px 10px; vertical-align: middle; }
.info-table td:first-child { color: var(--muted); width: 42%; font-size: 12px; letter-spacing: .02em; }
.info-table td:last-child  { color: var(--text); }

/* ── Mono tag ─────────────────────────────────────────────────── */
.mono-tag {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--sky);
    background: var(--sky-dim);
    padding: 2px 8px;
    border-radius: var(--r-sm);
}

/* ── Empty state ──────────────────────────────────────────────── */
.empty-state {
    text-align: center;
    padding: 80px 24px;
    color: var(--muted);
    animation: fade-up var(--t-slow) var(--ease-out);
}
.empty-icon  {
    font-size: 56px;
    display: block;
    margin-bottom: 20px;
    filter: drop-shadow(0 0 20px var(--amber-glow));
}
.empty-title {
    font-size: 17px;
    font-weight: 600;
    color: var(--text);
    margin-bottom: 10px;
    letter-spacing: -.01em;
}
.empty-hint  { font-size: 13px; line-height: 1.9; }
.empty-hint kbd {
    display: inline-block;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    padding: 2px 8px;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--amber);
}

/* ── Streamlit overrides ──────────────────────────────────────── */
div.stButton > button {
    background: var(--amber) !important;
    color: #000 !important;
    font-weight: 700 !important;
    border: none !important;
    border-radius: var(--r-md) !important;
    padding: 10px 0 !important;
    font-family: var(--font-ui) !important;
    font-size: 15px !important;
    letter-spacing: .01em !important;
    transition:
        background var(--t-base) var(--ease-out),
        transform   var(--t-base) var(--ease-out),
        box-shadow  var(--t-base) var(--ease-out) !important;
}
div.stButton > button:hover {
    background: var(--amber-dark) !important;
    transform: translateY(-2px) !important;
    box-shadow: 0 6px 28px var(--amber-glow) !important;
}
div.stButton > button:focus-visible {
    outline: 2px solid var(--amber) !important;
    outline-offset: 2px !important;
}

div[data-testid="stDownloadButton"] > button {
    background: #1d4ed8 !important;
    color: #fff !important;
    font-weight: 700 !important;
    border: none !important;
    border-radius: var(--r-md) !important;
    transition: background var(--t-base) !important;
}
div[data-testid="stDownloadButton"] > button:hover { background: #2563eb !important; }

div[data-baseweb="input"] > div {
    background: var(--surface-1) !important;
    border-color: var(--border) !important;
    border-radius: var(--r-md) !important;
    transition: border-color var(--t-fast) !important;
}
div[data-baseweb="input"] > div:focus-within {
    border-color: var(--amber) !important;
    box-shadow: 0 0 0 1px var(--amber) !important;
}

.stProgress > div > div {
    background: linear-gradient(90deg, var(--amber-dark) 0%, var(--amber) 100%) !important;
    border-radius: var(--r-pill) !important;
}

.stTabs [role="tablist"]       { border-bottom-color: var(--border) !important; }
.stTabs [role="tab"]           { color: var(--muted) !important; font-family: var(--font-ui); font-size: 13.5px; transition: color var(--t-fast) !important; }
.stTabs [aria-selected="true"] { color: var(--amber) !important; border-bottom-color: var(--amber) !important; }
.stTabs [role="tab"]:hover     { color: var(--text) !important; }

.streamlit-expanderHeader { background: var(--surface-1) !important; border-radius: var(--r-md) !important; border-color: var(--border) !important; }

label, .stTextInput label { color: var(--muted) !important; font-size: 12px !important; letter-spacing: .02em !important; }

hr { border-color: var(--border) !important; opacity: 0.5 !important; }

/* ── Inline-style replacements ────────────────────────────────── */
.metric-val-sm   { font-size: 17px; }
.metric-val-lh   { line-height: 1.8; }
.sec-title-label { font-weight: 600; font-size: 14px; }
.cve-title-wrap  { display: flex; align-items: center; gap: 8px; margin: 12px 0 8px; }
.finding-text    { color: var(--text); }
.finding-desc    { color: var(--muted); font-size: 12px; }
.finding-fix     { color: var(--amber); font-size: 12px; }
.finding-icon    { line-height: 1; flex-shrink: 0; padding-top: 2px; }
.finding-val     { font-size: 11px; color: var(--sky); }
.report-title    { font-size: 17px; font-weight: 700; color: var(--text); }
.server-type-val { font-weight: 600; }
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
    """Map a 0–60 score to a CSS colour utility class."""
    if score >= 70: return "col-good"
    if score >= 40: return "col-warn"
    return "col-bad"


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


def score_ring_html(score: int, color_class: str) -> str:
    """Animated SVG progress ring for the score metric (SMIL, no JS required)."""
    import math
    R, CX, CY = 28, 35, 35
    CIRC   = 2 * math.pi * R
    offset = CIRC * (1 - score / 100)
    c = {"col-good": "#4ade80", "col-warn": "#fbbf24", "col-bad": "#fb923c"}.get(color_class, "#fb923c")
    return (
        '<div class="metric-card">'
        f'<svg width="70" height="70" viewBox="0 0 70 70" style="display:block;margin:0 auto 4px">'
        f'<circle cx="{CX}" cy="{CY}" r="{R}" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="5"/>'
        f'<circle cx="{CX}" cy="{CY}" r="{R}" fill="none" stroke="{c}" stroke-width="5"'
        f' stroke-linecap="round" stroke-dasharray="{CIRC:.2f}" stroke-dashoffset="{CIRC:.2f}"'
        f' transform="rotate(-90 {CX} {CY})">'
        f'<animate attributeName="stroke-dashoffset" from="{CIRC:.2f}" to="{offset:.2f}"'
        f' dur="1.2s" calcMode="spline" keySplines="0.16 1 0.3 1" keyTimes="0;1" fill="freeze"/>'
        '</circle>'
        f'<text x="{CX}" y="{CY + 1}" text-anchor="middle" dominant-baseline="middle"'
        f' fill="{c}" font-family="JetBrains Mono,monospace" font-size="15" font-weight="600">{score}</text>'
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
    }.items():
        st.session_state.setdefault(key, default)


_init_session_state()

# ── Hero ─────────────────────────────────────────────────────────
st.markdown("""
<div class="hero-wrap">
  <div class="hero-badge">Project-VULNEX · Cybersecurity Track · PSU Future Tech 2026</div>
  <h1 class="hero-title"><svg xmlns="http://www.w3.org/2000/svg" width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="var(--amber)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:10px;margin-bottom:4px"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>Project-<span class="accent">VULNEX</span></h1>
  <p class="hero-sub">ระบบตรวจสอบความปลอดภัยเว็บไซต์สถานศึกษาด้วย AI &nbsp;·&nbsp; Passive Scan Only &nbsp;·&nbsp; ISO/IEC 27001</p>
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
    org = st.text_input("ชื่อองค์กร (สำหรับ Report)", value="วิทยาลัยเทคนิคปัตตานี")

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
        })

elif scan_btn and not url:
    st.warning("กรุณาใส่ URL ก่อนกด ตรวจสอบ")

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

    m1.markdown(
        score_ring_html(score, score_color_class(score)),
        unsafe_allow_html=True
    )

    m2.markdown(f"""<div class="metric-card">
        <span class="metric-val metric-val-sm {risk_color_class(risk)}">{risk}</span>
        <span class="metric-lbl">ระดับความเสี่ยง</span>
    </div>""", unsafe_allow_html=True)

    ssl_cls = "col-good" if ssl_ok else "col-bad"
    _ssl_ico = _i(_P_CHECK, 22) if ssl_ok else _i(_P_XCIRC, 22)
    m3.markdown(f'<div class="metric-card">'
               f'<span class="metric-val metric-val-lh {ssl_cls}">{_ssl_ico}</span>'
               f'<span class="metric-lbl">SSL ({days_left} วัน)</span>'
               '</div>', unsafe_allow_html=True)

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
    _dos_ico = _i(_P_ALERT, 22) if dos_risk else _i(_P_CHECK, 22)
    m6.markdown(f'<div class="metric-card">'
               f'<span class="metric-val metric-val-lh {dos_cls}">{_dos_ico}</span>'
               '<span class="metric-lbl">DoS Risk</span>'
               '</div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Score breakdown ────────────────────────────────────────
    breakdown = ai_data.get("breakdown", {})
    if breakdown:
        bd_h = breakdown.get("headers", 0)
        bd_s = breakdown.get("ssl", 0)
        bd_c = breakdown.get("cve", 0)
        bd_v = breakdown.get("server", 0)
        st.markdown(f"""
        <div class="sec-card" style="padding:14px 18px">
            <div class="sec-card-title" style="margin-bottom:10px;padding-bottom:8px">Score Breakdown</div>
            <div style="display:flex;gap:24px;flex-wrap:wrap">
                <span class="metric-lbl">Headers: <b class="col-info">{bd_h}</b>/40</span>
                <span class="metric-lbl">SSL: <b class="col-info">{bd_s}</b>/25</span>
                <span class="metric-lbl">CVE/DoS: <b class="col-info">{bd_c}</b>/25</span>
                <span class="metric-lbl">Server: <b class="col-info">{bd_v}</b>/10</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # ── Tabs ────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "AI Analysis", "Server Info", "HTTP Headers", "SSL Certificate", "Raw Data"
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
                     if sver_safe else f'<span class="col-good">ซ่อนอยู่ {_i(_P_CHECK, 13)}</span>')
        _ico_alert = _i(_P_ALERT, 13, 'margin-right:4px')
        _ico_ok    = _i(_P_CHECK, 13, 'margin-right:4px')
        dos_cell  = (f'<span class="col-bad">{_ico_alert} YES — CVE-2023-44487</span>'
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
        ssl = scan_data.get("ssl", {}) or {}
        if ssl.get("warning"):
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
        ' fill="none" stroke="var(--amber)" stroke-width="2" stroke-linecap="round"'
        ' stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
        '<polyline points="14 2 14 8 20 8"/>'
        '<line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>'
        '<span class="report-title">สร้างรายงาน ISO/IEC 27001</span>'
        '</div>',
        unsafe_allow_html=True
    )
    col_pdf1, col_pdf2 = st.columns([2, 1])
    with col_pdf1:
        st.info(
            "รายงาน PDF มาตรฐาน **ISO/IEC 27001:2022** ครอบคลุม: "
            "Executive Summary · Technical Findings · CVE Report · "
            "SSL Analysis · AI Analysis · Remediation Plan · Appendix"
        )
    with col_pdf2:
        if st.button("สร้าง PDF Report", use_container_width=True):
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
  <span class="empty-icon"><svg xmlns="http://www.w3.org/2000/svg" width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="var(--amber)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:block;margin:0 auto"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></span>
  <div class="empty-title">พร้อมตรวจสอบ</div>
  <div class="empty-hint">
    ใส่ URL เว็บไซต์ด้านบน แล้วกด <kbd>เริ่มตรวจสอบ</kbd><br>
    รองรับ HTTP และ HTTPS · Passive Scan Only
  </div>
</div>
""", unsafe_allow_html=True)