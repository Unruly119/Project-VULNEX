# ui_shared.py — Shared UI scaffolding for every VULNEX page
# ────────────────────────────────────────────────────────────────
#   One place that owns the things every page needs to look identical:
#     · inject_base_styles()  — base64 Thai @font-face + index.css
#     · render_sidebar_nav()  — branded two-item side navigation
#   Both app.py (the scan page) and pages/*.py import from here so the
#   parchment/terracotta design system, fonts, and nav never drift apart.
#
#   Paths are resolved relative to the repo root (Streamlit keeps the CWD
#   at the main script's directory for every page), matching how app.py
#   has always loaded src/frontend/index.css.
# ────────────────────────────────────────────────────────────────
import base64
import os

import streamlit as st

# Exact unicode-range Google Fonts uses for the Prompt "thai" subset:
# core Thai block + the combining marks / dotted-circle it ships with.
_THAI_UNICODE_RANGE = "U+02D7, U+0303, U+0331, U+0E01-0E5B, U+200C-200D, U+25CC"

_FONT_DIR = os.path.join("src", "Font", "google_font")
_CSS_PATH = os.path.join("src", "frontend", "index.css")

_FONT_WEIGHTS = {
    400: "Prompt-Regular-thai.woff2",
    500: "Prompt-Medium-thai.woff2",
    600: "Prompt-SemiBold-thai.woff2",
    700: "Prompt-Bold-thai.woff2",
}


def _thai_font_css() -> str:
    """Build @font-face blocks for the Prompt Thai webfont with each woff2
    file base64-embedded as a data: URI.

    Embedding is required because this stylesheet is injected inline via
    st.markdown — a relative url('../font/...') would resolve against the
    Streamlit page origin (which does not serve src/), so the fonts would
    never load. unicode-range restricts Prompt to Thai codepoints only, so
    English / Latin text keeps using AnthropicSans / AnthropicSerif.
    """
    blocks = []
    for weight, fname in _FONT_WEIGHTS.items():
        with open(os.path.join(_FONT_DIR, fname), "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
        blocks.append(
            "@font-face{font-family:'Prompt';font-style:normal;"
            f"font-weight:{weight};font-display:swap;"
            f"src:url(data:font/woff2;base64,{b64}) format('woff2');"
            f"unicode-range:{_THAI_UNICODE_RANGE};}}"
        )
    return "\n".join(blocks)


def _load_css(path: str) -> str:
    """Read a CSS file and return it wrapped in a <style> tag."""
    with open(path, "r", encoding="utf-8") as f:
        return f"<style>\n{f.read()}\n</style>"


def inject_base_styles() -> None:
    """Inject the base64-embedded Thai @font-face first, then the main
    stylesheet — the exact order app.py has always used."""
    st.markdown(
        f"<style>\n{_thai_font_css()}\n</style>", unsafe_allow_html=True
    )
    st.markdown(_load_css(_CSS_PATH), unsafe_allow_html=True)


# ── Branded side navigation ──────────────────────────────────────
# Streamlit's auto-generated page list (`[data-testid="stSidebarNav"]`) is
# hidden in index.css; this renders an intentional two-item nav in its
# place. st.page_link auto-highlights whichever page is currently active,
# so no manual "active" bookkeeping is needed.
_NAV_ITEMS = (
    ("app.py", "หน้าตรวจสอบ", ":material/security:"),
    ("pages/user_manual.py", "คู่มือการใช้งาน", ":material/menu_book:"),
)


def render_sidebar_nav() -> None:
    """Render the shared branded sidebar navigation on any page."""
    with st.sidebar:
        st.markdown(
            '<div class="side-nav-brand">'
            '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18"'
            ' viewBox="0 0 24 24" fill="none" stroke="var(--accent)"'
            ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
            '<path d="m9 12 2 2 4-4"/></svg>'
            '<span>Project-<b>VULNEX</b></span></div>',
            unsafe_allow_html=True,
        )
        for target, label, icon in _NAV_ITEMS:
            st.page_link(target, label=label, icon=icon)
