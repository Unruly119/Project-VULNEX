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
# place. We deliberately AVOID st.page_link here: on some Streamlit
# versions (e.g. Streamlit Community Cloud) its internal page lookup reads a
# `url_pathname` key that isn't present in every page record, raising a
# KeyError. st.switch_page only touches `script_path` / `page_script_hash`,
# so it navigates reliably everywhere — the active page is rendered as a
# non-clickable "current" indicator instead of a button.
_SHIELD_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="17" height="17"'
    ' viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
    '<path d="m9 12 2 2 4-4"/></svg>'
)
_BOOK_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="17" height="17"'
    ' viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/>'
    '<path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>'
)

# Small "opens in a new tab" arrow appended to manual links.
_EXT_SVG = (
    '<svg class="ext-ico" xmlns="http://www.w3.org/2000/svg" width="13" height="13"'
    ' viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M15 3h6v6"/><path d="M10 14 21 3"/>'
    '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>'
)

# URL slug of pages/user_manual.py (filename without extension). Manual links
# point here with target="_blank" so the manual pops into a NEW browser tab
# and the scan page — including any scan results on it — is never replaced.
MANUAL_URL = "user_manual"


def manual_anchor_html(css_class: str, label: str) -> str:
    """Return an <a> that opens the user manual in a new browser tab, styled
    by `css_class`. Centralised so the scan page's manual button and the
    sidebar nav share one piece of markup."""
    return (
        f'<a class="{css_class}" href="{MANUAL_URL}" target="_blank"'
        ' rel="noopener noreferrer" title="เปิดคู่มือการใช้งานในแท็บใหม่">'
        f'{_BOOK_SVG}<span>{label}</span>{_EXT_SVG}</a>'
    )


def render_sidebar_nav(active: str = "scan") -> None:
    """Render the shared branded sidebar navigation.

    `active` is the key of the current page ("scan" or "manual"); that item
    is shown as a highlighted current-page indicator. The scan link uses
    same-tab st.switch_page (it is the primary "home"); the manual link opens
    in a new tab so it never replaces the scan page.
    """
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

        # Scan page — same-tab navigation
        if active == "scan":
            st.markdown(
                f'<div class="side-nav-current">{_SHIELD_SVG}'
                '<span>หน้าตรวจสอบ</span></div>',
                unsafe_allow_html=True,
            )
        elif st.button(
            ":material/security: หน้าตรวจสอบ",
            key="sidenav_scan",
            use_container_width=True,
        ):
            st.switch_page("app.py")

        # Manual page — pops out into a new tab
        if active == "manual":
            st.markdown(
                f'<div class="side-nav-current">{_BOOK_SVG}'
                '<span>คู่มือการใช้งาน</span></div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                manual_anchor_html("side-nav-link", "คู่มือการใช้งาน"),
                unsafe_allow_html=True,
            )


# ── Site footer ──────────────────────────────────────────────────
# The standards VULNEX's own modules are modelled on — surfaced as a black
# footer bar so users can see the credible, public references behind the
# scan. Each entry maps to a VULNEX module: headers → SecurityHeaders,
# SSL → SSL Labs, server/exposure → Shodan. Links open in a new tab.
_BADGE_CHECK_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18"'
    ' viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78'
    ' 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1'
    '-4.78-4.77 4 4 0 0 1 0-6.76Z"/><path d="m9 12 2 2 4-4"/></svg>'
)

_FOOTER_SHIELD_LG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22"'
    ' viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
    '<path d="m9 12 2 2 4-4"/></svg>'
)

_FOOTER_REFS = (
    ("SecurityHeaders", "https://securityheaders.com/",
     "มาตรฐาน HTTP Security Headers"),
    ("SSL Labs · SSL Server Test", "https://www.ssllabs.com/ssltest/",
     "ตรวจใบรับรองและโปรโตคอล TLS"),
    ("Shodan", "https://www.shodan.io/",
     "ฐานข้อมูลการเปิดเผยบริการบนอินเทอร์เน็ต"),
)


def render_footer() -> None:
    """Render the shared black footer: a compact VULNEX brand block beside a
    divided list of the public standards the scan is modelled on."""
    refs = "".join(
        f'<a class="footer-ref" href="{url}" target="_blank"'
        ' rel="noopener noreferrer">'
        f'<span class="footer-ref-name">{name}</span>'
        f'<span class="footer-ref-sub">{desc}</span>{_EXT_SVG}</a>'
        for name, url, desc in _FOOTER_REFS
    )
    st.markdown(
        '<footer class="site-footer"><div class="site-footer-inner">'
        '<div class="site-footer-top">'
        # ── brand block ──
        f'<div class="footer-brand"><span class="footer-brand-ico">'
        f'{_FOOTER_SHIELD_LG}</span><div>'
        '<div class="footer-brand-name">Project-<b>VULNEX</b></div>'
        '<p class="footer-brand-tag">ระบบตรวจสอบความปลอดภัยเว็บไซต์สถานศึกษา '
        'แบบ Passive เพื่อความถูกต้องและน่าเชื่อถือของผลการตรวจสอบ</p>'
        '</div></div>'
        # ── reference list ──
        '<div class="footer-refs">'
        f'<div class="footer-refs-label">{_BADGE_CHECK_SVG}'
        '<span>อ้างอิงมาตรฐานจากแหล่งที่เชื่อถือได้ระดับสากล</span></div>'
        f'{refs}</div>'
        '</div>'
        # ── baseline ──
        '<div class="site-footer-base">'
        '<span>© 2026 Project-VULNEX</span>'
        '<span>PSU Future Tech 2026 · Cybersecurity Track</span>'
        '</div>'
        '</div></footer>',
        unsafe_allow_html=True,
    )
