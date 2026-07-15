# auth.py — Project-VULNEX authentication (scan-first, auth-on-action)
# ────────────────────────────────────────────────────────────────
#   Workflow: the scan page is public. The login wall is raised at the SCAN
#   ACTION — an unauthenticated visitor who enters a URL and presses scan is sent
#   to the sign-in screen (which remembers the URL), and the scan runs itself once
#   they're in. Signed-in visitors scan with no interruption. The manual is public.
#
#   Public API used by app.py / pages:
#     init()               → (controller, user|None)   cookie→session bootstrap
#     is_authed()          → bool
#     current_user()       → dict|None
#     render_top_bar(c,u)  → right-aligned account / sign-in control
#     request_login(url)   → raise the wall, remember the pending scan URL, rerun
#     render_auth_screen(c)→ the split-plate sign-in/sign-up screen
#     scroll_top()         → reset the stMain scroll container (wall/scan starts)
#     get_client_meta()    → request metadata for logging
#
#   The auth screen is a two-panel "instrument plate": a dark ink brand panel
#   (serif statement + a passive-scan console readout framed by reticle corners,
#   showing the pending target host) beside the form on the warm surface. All
#   panel HTML is static/authored except the host, which is HTML-escaped.
#
#   Session model unchanged: session_state is truth within a run; a Secure,
#   SameSite cookie holding only a random token persists across sessions (the DB
#   stores its SHA-256). All DB work lives in supabase_client.
# ────────────────────────────────────────────────────────────────
from __future__ import annotations

import os
import re
import html as _html
from datetime import datetime, timezone, timedelta

import streamlit as st
from streamlit_cookies_controller import CookieController

import supabase_client as db
from privacy_policy import open_policy_dialog, POLICY_VERSION

COOKIE_NAME = "vulnex_session"
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_SHIELD = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
           'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">'
           '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
           '<path d="m9 12 2 2 4-4"/></svg>')


# ── request / client metadata ────────────────────────────────────
def _headers() -> dict:
    try:
        h = st.context.headers
        return {str(k).lower(): v for k, v in dict(h).items()} if h else {}
    except Exception:
        return {}


def _parse_ua(ua: str) -> dict:
    ua_l = (ua or "").lower()
    if "tablet" in ua_l or "ipad" in ua_l:
        device = "tablet"
    elif "mobi" in ua_l or "android" in ua_l or "iphone" in ua_l:
        device = "mobile"
    else:
        device = "desktop"
    browser, ver = "unknown", None
    for name, pat in (
        ("Edge", r"edg(?:e|a|ios)?/([\d.]+)"),
        ("Opera", r"opr/([\d.]+)"),
        ("Samsung", r"samsungbrowser/([\d.]+)"),
        ("Chrome", r"chrome/([\d.]+)"),
        ("Firefox", r"firefox/([\d.]+)"),
        ("Safari", r"version/([\d.]+).*safari"),
    ):
        m = re.search(pat, ua_l)
        if m:
            browser, ver = name, m.group(1)
            break
    os_name, os_ver = "unknown", None
    if "windows nt" in ua_l:
        os_name = "Windows"; m = re.search(r"windows nt ([\d.]+)", ua_l); os_ver = m.group(1) if m else None
    elif "android" in ua_l:
        os_name = "Android"; m = re.search(r"android ([\d.]+)", ua_l); os_ver = m.group(1) if m else None
    elif "iphone os" in ua_l or "cpu os" in ua_l:
        os_name = "iOS"; m = re.search(r"os ([\d_]+)", ua_l); os_ver = m.group(1).replace("_", ".") if m else None
    elif "mac os x" in ua_l:
        os_name = "macOS"; m = re.search(r"mac os x ([\d_]+)", ua_l); os_ver = m.group(1).replace("_", ".") if m else None
    elif "linux" in ua_l:
        os_name = "Linux"
    return {"device_type": device, "browser": browser, "browser_version": ver,
            "os_name": os_name, "os_version": os_ver}


def get_client_meta() -> dict:
    h = _headers()
    xff = h.get("x-forwarded-for", "") or ""
    client_ip = xff.split(",")[0].strip() if xff else None
    ua = h.get("user-agent", "") or ""
    meta = {"client_ip": client_ip, "forwarded_for": xff or None, "user_agent": ua}
    meta.update(_parse_ua(ua))
    return meta


# ── cookie helpers ───────────────────────────────────────────────
def get_controller() -> CookieController:
    return CookieController(key="vulnex_cookies")


def _cookie_secure() -> bool:
    return (os.environ.get("VULNEX_COOKIE_SECURE", "1").strip() != "0")


def _set_cookie(controller: CookieController, token: str) -> None:
    try:
        controller.set(
            COOKIE_NAME, token,
            expires=datetime.now(timezone.utc) + timedelta(days=db._SESSION_DAYS),
            max_age=db._SESSION_DAYS * 24 * 3600,
            secure=_cookie_secure(), same_site="strict", path="/",
        )
    except Exception:
        pass


def _clear_cookie(controller: CookieController) -> None:
    try:
        controller.remove(COOKIE_NAME, path="/")
    except Exception:
        pass


# ── session lifecycle ────────────────────────────────────────────
def _establish_session(controller: CookieController, user: dict, event: str) -> None:
    meta = get_client_meta()
    token, _ = db.create_session(user["id"], client_ip=meta.get("client_ip"),
                                 user_agent=meta.get("user_agent"))
    if token:
        _set_cookie(controller, token)
        st.session_state["auth_token"] = token
    st.session_state["auth_user"] = user
    sid = db.log_login_event(user["id"], None, meta)
    st.session_state["auth_login_event"] = sid
    db.log_user_event(user_id=user["id"], session_id=None, event_type=event, meta=meta)


def logout(controller: CookieController) -> None:
    token = st.session_state.get("auth_token")
    if token:
        db.revoke_session(token)
    db.mark_logout(st.session_state.get("auth_login_event"))
    user = st.session_state.get("auth_user") or {}
    if user.get("id"):
        db.log_user_event(user_id=user["id"], session_id=None,
                          event_type="logout", meta=get_client_meta())
    _clear_cookie(controller)
    for k in ("auth_user", "auth_token", "auth_login_event", "show_auth",
              "pending_scan_url"):
        st.session_state.pop(k, None)
    st.rerun()


def current_user() -> dict | None:
    return st.session_state.get("auth_user")


def is_authed() -> bool:
    return st.session_state.get("auth_user") is not None


# ── bootstrap + gate helpers ─────────────────────────────────────
def init() -> tuple[CookieController, dict | None]:
    """Cookie→session bootstrap (no gating). Returns (controller, user|None)."""
    controller = get_controller()
    if not st.session_state.get("auth_user") and db.is_configured():
        try:
            token = controller.get(COOKIE_NAME)
        except Exception:
            token = None
        if token:
            u = db.get_session_user(token)
            if u:
                st.session_state["auth_user"] = u
                st.session_state["auth_token"] = token
                db.log_user_event(user_id=u["id"], session_id=u.get("_session_id"),
                                  event_type="session_resume", meta=get_client_meta())
            else:
                _clear_cookie(controller)
    return controller, st.session_state.get("auth_user")


def request_login(pending_url: str | None = None) -> None:
    """Raise the sign-in wall; remember the URL the visitor tried to scan.
    Always opens on the login view — a freshly raised wall shouldn't inherit a
    stale signup view from an earlier visit."""
    if pending_url:
        st.session_state["pending_scan_url"] = pending_url
    st.session_state["show_auth"] = True
    st.session_state["auth_view"] = "login"
    st.session_state["auth_scroll_pending"] = True   # one-shot scroll reset
    st.rerun()


def scroll_top() -> None:
    """Reset the scroll position of Streamlit's main container.

    Streamlit preserves scroll across reruns, so when the auth wall replaces the
    scan page (or a pending scan starts after login) the visitor would land at
    whatever offset they were at. The zero-height component runs a static script
    in the same-origin component iframe — no user input touches it.
    """
    import streamlit.components.v1 as components
    components.html(
        "<script>"
        "const m = window.parent.document.querySelector('section.stMain');"
        "if (m) { m.scrollTo({top: 0, left: 0, behavior: 'instant'}); }"
        "</script>",
        height=0,
    )


def _cancel_auth() -> None:
    st.session_state["show_auth"] = False
    st.session_state.pop("pending_scan_url", None)
    st.rerun()


# ── UI: top bar ──────────────────────────────────────────────────
def render_top_bar(controller: CookieController, user: dict | None) -> None:
    with st.container(key="auth-topbar"):
        left, right = st.columns([1, 0.34], vertical_alignment="center")
        with left:
            if user:
                email = _html.escape(str(user.get("gmail", "")))
                st.markdown(
                    f'<div class="auth-whoami"><span class="auth-dot"></span>'
                    f'<span class="auth-whoami-txt">{email}</span></div>',
                    unsafe_allow_html=True)
        with right:
            if user:
                if st.button("ออกจากระบบ", key="logout_btn", use_container_width=True):
                    logout(controller)
            else:
                if st.button("เข้าสู่ระบบ", key="signin_top", use_container_width=True):
                    request_login(None)


# ── UI: the auth screen — the "instrument plate" ─────────────────
#   One bordered plate, two panels. Left: dark ink brand panel (serif statement,
#   reticle-framed passive-scan console, the three vows). Right: the form on the
#   warm surface — underline tabs, inputs, one dark CTA. No floating card, no
#   decorative glow; structure comes from the plate itself.
def render_auth_screen(controller: CookieController) -> None:
    # One-shot: scroll to the top only when the wall is first raised — not on
    # every rerun inside it (a checkbox tick must not fling mobile users up).
    if st.session_state.pop("auth_scroll_pending", False):
        scroll_top()
    pending = st.session_state.get("pending_scan_url")
    view = st.session_state.setdefault("auth_view", "login")

    with st.container(key="vulnex-auth"):
        with st.container(key="auth-back"):
            if st.button("← กลับไปหน้าสแกน", key="auth_back"):
                _cancel_auth()

        if not db.is_configured():
            st.error("ระบบสมาชิกยังไม่พร้อมใช้งาน — ผู้ดูแลระบบต้องตั้งค่าฐานข้อมูลก่อน")
            return

        with st.container(key="auth-plate"):
            left, right = st.columns([1.08, 1], gap="small")
            with left:
                st.markdown(_gate_panel_html(pending), unsafe_allow_html=True)
            with right:
                with st.container(key="auth-form-side"):
                    _tabs(view)
                    if view == "login":
                        _login_form(controller)
                    else:
                        _signup_form(controller)


def _gate_panel_html(pending: str | None) -> str:
    """The dark brand panel. Static/authored HTML — only the host is dynamic,
    and it is HTML-escaped before interpolation."""
    if pending:
        target = _html.escape(_pretty_host(pending))
        status = "รอเข้าสู่ระบบ"
    else:
        target = "ยังไม่ได้เลือกเว็บไซต์"
        status = "พร้อมเมื่อเข้าสู่ระบบ"
    return f'''
<div class="gate-panel">
  <div class="gate-brand">{_SHIELD}<span class="gate-word">Project-<em>VULNEX</em></span></div>
  <h2 class="gate-statement">เห็นความเสี่ยง<br>ก่อนผู้ไม่หวังดี</h2>
  <p class="gate-sub">สแกนแบบพาสซีฟ อ่านอย่างเดียว — ปลอดภัยต่อเว็บไซต์ของคุณเสมอ</p>
  <div class="gate-console">
    <i class="gc-c gc-tl"></i><i class="gc-c gc-tr"></i>
    <i class="gc-c gc-bl"></i><i class="gc-c gc-br"></i>
    <span class="gc-sweep"></span>
    <div class="gc-row"><span class="gc-k">เป้าหมาย</span><span class="gc-host">{target}</span></div>
    <div class="gc-row"><span class="gc-k">โหมด</span><span class="gc-v">Passive · อ่านอย่างเดียว</span></div>
    <div class="gc-row"><span class="gc-k">สถานะ</span><span class="gc-v"><i class="gc-dot"></i>{status}</span></div>
  </div>
  <div class="gate-vows">ไม่เจาะระบบ<span>·</span>ไม่เดารหัสผ่าน<span>·</span>ไม่แก้ไขข้อมูล</div>
</div>'''


def _tabs(view: str) -> None:
    with st.container(key="auth-tabs"):
        c1, c2 = st.columns(2, gap="small")
        with c1:
            if st.button("เข้าสู่ระบบ", key="tab_login", use_container_width=True,
                         type=("primary" if view == "login" else "secondary")):
                st.session_state["auth_view"] = "login"; st.rerun()
        with c2:
            if st.button("สมัครสมาชิก", key="tab_signup", use_container_width=True,
                         type=("primary" if view == "signup" else "secondary")):
                st.session_state["auth_view"] = "signup"; st.rerun()


def _finish(controller: CookieController, user: dict, event: str) -> None:
    _establish_session(controller, user, event)
    st.session_state["show_auth"] = False          # pending_scan_url stays → auto-scan
    st.rerun()


def _login_form(controller: CookieController) -> None:
    # st.form so Enter in either field submits — the fast path for returning users.
    with st.form(key="auth_login_form", border=False):
        st.text_input("อีเมล", key="li_email", placeholder="you@school.ac.th")
        st.text_input("รหัสผ่าน", key="li_pw", type="password", placeholder="••••••••")
        submitted = st.form_submit_button("เข้าสู่ระบบ", use_container_width=True,
                                          type="primary")
    if submitted:
        email = (st.session_state.get("li_email") or "").strip()
        pw = st.session_state.get("li_pw") or ""
        if not email or not pw:
            st.warning("กรุณากรอกอีเมลและรหัสผ่าน"); return
        with st.spinner("กำลังเข้าสู่ระบบ…"):
            user, err = db.authenticate(email, pw)
        if err:
            st.error(err); return
        _finish(controller, user, "login")
    _switch_hint("ยังไม่มีบัญชี?", "สมัครสมาชิกฟรี", "signup", "to_signup")


def _signup_form(controller: CookieController) -> None:
    # Not an st.form: the policy dialog opener is a regular button, which
    # Streamlit forbids inside forms.
    st.text_input("อีเมล", key="su_email", placeholder="you@school.ac.th")
    st.text_input("รหัสผ่าน", key="su_pw", type="password",
                  placeholder="อย่างน้อย 8 ตัวอักษร")
    st.text_input("ยืนยันรหัสผ่าน", key="su_pw2", type="password", placeholder="••••••••")

    agree = st.checkbox("ฉันได้อ่านและยอมรับนโยบายความเป็นส่วนตัว", key="su_agree")
    with st.container(key="auth-policy"):
        if st.button("อ่านนโยบายฉบับเต็ม", key="su_read_policy"):
            open_policy_dialog()

    if st.button("สร้างบัญชี", key="su_submit", use_container_width=True, type="primary"):
        email = (st.session_state.get("su_email") or "").strip().lower()
        pw = st.session_state.get("su_pw") or ""
        pw2 = st.session_state.get("su_pw2") or ""
        if not _EMAIL_RE.match(email):
            st.warning("รูปแบบอีเมลไม่ถูกต้อง"); return
        if len(pw) < 8:
            st.warning("รหัสผ่านต้องยาวอย่างน้อย 8 ตัวอักษร"); return
        if pw != pw2:
            st.warning("รหัสผ่านทั้งสองช่องไม่ตรงกัน"); return
        if not agree:
            st.warning("กรุณายอมรับนโยบายความเป็นส่วนตัวก่อนสร้างบัญชี"); return
        with st.spinner("กำลังสร้างบัญชี…"):
            user, err = db.create_user(email, pw, POLICY_VERSION)
        if err:
            st.error(err); return
        _finish(controller, user, "signup")
    _switch_hint("มีบัญชีอยู่แล้ว?", "เข้าสู่ระบบ", "login", "to_login")


def _switch_hint(lead: str, action: str, target_view: str, key: str) -> None:
    with st.container(key=f"auth-switch-{key}"):
        st.markdown(f'<div class="auth-switch-lead">{lead}</div>',
                    unsafe_allow_html=True)
        if st.button(action, key=f"switch_{key}"):
            st.session_state["auth_view"] = target_view
            st.rerun()


def _pretty_host(url: str) -> str:
    from urllib.parse import urlparse
    try:
        h = (urlparse(url).hostname or url).strip()
        return h or url
    except Exception:
        return url
