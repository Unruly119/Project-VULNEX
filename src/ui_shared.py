# ui_shared.py — Shared UI scaffolding for every VULNEX page
# ────────────────────────────────────────────────────────────────
#   One place that owns the things every page needs to look identical:
#     · inject_base_styles()  — base64 Thai @font-face + index.css
#     · render_footer()       — shared product footer
#   Both app.py (the scan page) and pages/*.py import from here so the
#   parchment/terracotta design system and fonts never drift apart.
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


@st.cache_data(show_spinner=False)
def _base_styles_html() -> str:
    """Build the Thai @font-face block + main stylesheet once and memoise it.

    The font woff2 files (~52 KB) and index.css (~46 KB) are static assets, so
    the base64 encoding and file reads only need to happen once per server
    process. Without this, Streamlit re-reads and re-encodes every asset on
    every rerun (i.e. every widget interaction) — pure wasted work. The font
    @font-face goes first, then the stylesheet, matching the order app.py has
    always used.
    """
    return f"<style>\n{_thai_font_css()}\n</style>\n{_load_css(_CSS_PATH)}"


def inject_base_styles() -> None:
    """Inject the base64-embedded Thai @font-face + the main stylesheet
    (built once and cached — see _base_styles_html)."""
    st.markdown(_base_styles_html(), unsafe_allow_html=True)


# Small "opens in a new tab" arrow — appended to external reference links in
# the footer (those, and only those, still open in a NEW browser tab).
_EXT_SVG = (
    '<svg class="ext-ico" xmlns="http://www.w3.org/2000/svg" width="13" height="13"'
    ' viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M15 3h6v6"/><path d="M10 14 21 3"/>'
    '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>'
)

# URL slug of pages/user_manual.py (filename without extension). Manual links
# point here WITHOUT target="_blank" so the manual opens IN PLACE (same tab) via
# Streamlit's multi-page routing — the manual page carries its own back button.
MANUAL_URL = "user_manual"


# ── Site footer ──────────────────────────────────────────────────
# A quiet two-column product footer (Linear / Vercel restraint): a brand block
# on the left (mark · wordmark · one line · two CTAs) beside a single "อ้างอิง"
# column listing the public standards VULNEX is modelled on. One warm panel, a
# hairline rule, then a low-key copyright row. No team list, no marketing
# paragraph, no balancing filler — every element earns its place.
_FOOTER_SHIELD_LG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"'
    ' viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
    '<path d="m9 12 2 2 4-4"/></svg>'
)

# The external standards each VULNEX module is benchmarked against. Every link
# goes somewhere real; nothing is decorative.
_FOOTER_REFS = (
    ("SecurityHeaders", "https://securityheaders.com/"),
    ("SSL Labs", "https://www.ssllabs.com/ssltest/"),
)

# The development team — rendered as a numbered roster column in the footer.
_FOOTER_TEAM = ("Dev01", "Dev02", "Dev03", "Dev04")


def render_footer() -> None:
    """Render the site footer: a two-column product footer — brand block + CTAs
    on the left, the 'อ้างอิง' standards column on the right, then a copyright
    row. All references open in a new tab."""
    refs = "".join(
        f'<a class="ft-link" href="{url}" target="_blank" rel="noopener noreferrer">'
        f'<span>{label}</span>{_EXT_SVG}</a>'
        for label, url in _FOOTER_REFS
    )
    team = "".join(
        f'<li class="ft-team-item">'
        f'<span class="ft-team-num">{i}.</span><span>{name}</span></li>'
        for i, name in enumerate(_FOOTER_TEAM, start=1)
    )
    st.markdown(
        '<footer class="site-footer"><div class="site-footer-inner">'
        '<div class="site-footer-top">'
        # ── primary column: brand + one line + CTAs ──
        '<div class="ft-primary">'
        f'<span class="ft-mark">{_FOOTER_SHIELD_LG}</span>'
        '<div class="ft-name">Project-<b>VULNEX</b></div>'
        '<p class="ft-tagline">ระบบตรวจสอบความปลอดภัยเว็บไซต์แบบ Passive</p>'
        '<div class="ft-cta">'
        '<a class="ft-btn ft-btn-primary" href="./">เริ่มตรวจสอบ</a>'
        f'<a class="ft-btn ft-btn-ghost" href="{MANUAL_URL}">คู่มือ</a>'
        '</div>'
        '</div>'
        # ── secondary column: development team ──
        '<nav class="ft-team" aria-labelledby="ft-team-head">'
        '<h2 id="ft-team-head" class="ft-refs-head">Development Team (Name)</h2>'
        f'<ol class="ft-team-list">{team}</ol>'
        '</nav>'
        # ── tertiary column: references ──
        '<nav class="ft-refs" aria-labelledby="ft-refs-head">'
        '<h2 id="ft-refs-head" class="ft-refs-head">อ้างอิง</h2>'
        f'{refs}'
        '</nav>'
        '</div>'
        # ── baseline ──
        '<div class="site-footer-base">'
        '<span>© 2026 Project-VULNEX</span>'
        '<span>PSU Future Tech · Cybersecurity Track</span>'
        '</div>'
        '</div></footer>',
        unsafe_allow_html=True,
    )
