# auth.py — Project-VULNEX login gate (Streamlit)
# ────────────────────────────────────────────────────────────────
#   The scan page and the manual page both call require_auth() FIRST. If the
#   visitor is not authenticated, the login/signup screen renders and the script
#   stops — so there is no way to reach the scanner without logging in (no bypass).
#
#   Session model:
#     · Truth-of-record within a running Streamlit session = st.session_state
#       (server-side, per-session, un-forgeable by the client).
#     · Persistence across tabs / refresh / server restart = a Secure, SameSite
#       cookie holding ONLY a 256-bit random token. The DB stores its SHA-256.
#     · On a fresh session we bootstrap from the cookie (validate → load user).
#
#   Every DB call is in supabase_client; this file is UI + glue only.
# ────────────────────────────────────────────────────────────────
from __future__ import annotations

import os
import re
from datetime import datetime, timezone, timedelta

import streamlit as st
from streamlit_cookies_controller import CookieController

import supabase_client as db
from privacy_policy import open_policy_dialog, POLICY_VERSION

COOKIE_NAME = "vulnex_session"
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ── request / client metadata ────────────────────────────────────
def _headers() -> dict:
    try:
        h = st.context.headers
        return {str(k).lower(): v for k, v in dict(h).items()} if h else {}
    except Exception:
        return {}


def _parse_ua(ua: str) -> dict:
    ua_l = (ua or "").lower()
    # device
    if "tablet" in ua_l or "ipad" in ua_l:
        device = "tablet"
    elif "mobi" in ua_l or "android" in ua_l or "iphone" in ua_l:
        device = "mobile"
    else:
        device = "desktop"
    # browser (order matters — Edge/Opera/Chrome share tokens)
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
    # os
    os_name, os_ver = "unknown", None
    if "windows nt" in ua_l:
        os_name = "Windows"
        m = re.search(r"windows nt ([\d.]+)", ua_l); os_ver = m.group(1) if m else None
    elif "android" in ua_l:
        os_name = "Android"
        m = re.search(r"android ([\d.]+)", ua_l); os_ver = m.group(1) if m else None
    elif "iphone os" in ua_l or "cpu os" in ua_l:
        os_name = "iOS"
        m = re.search(r"os ([\d_]+)", ua_l); os_ver = m.group(1).replace("_", ".") if m else None
    elif "mac os x" in ua_l:
        os_name = "macOS"
        m = re.search(r"mac os x ([\d_]+)", ua_l); os_ver = m.group(1).replace("_", ".") if m else None
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
def _cookie_secure() -> bool:
    # Secure cookies require HTTPS. Streamlit Cloud is HTTPS → keep True. For
    # local http testing set VULNEX_COOKIE_SECURE=0.
    return (os.environ.get("VULNEX_COOKIE_SECURE", "1").strip() != "0")


def _set_cookie(controller: CookieController, token: str) -> None:
    try:
        controller.set(
            COOKIE_NAME, token,
            expires=datetime.now(timezone.utc) + timedelta(days=db._SESSION_DAYS),
            max_age=db._SESSION_DAYS * 24 * 3600,
            secure=_cookie_secure(),
            same_site="strict",
            path="/",
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
    """Create a DB session, set the cookie, populate session_state, log it."""
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
    for k in ("auth_user", "auth_token", "auth_login_event"):
        st.session_state.pop(k, None)
    st.rerun()


def current_user() -> dict | None:
    return st.session_state.get("auth_user")


# ── the gate ─────────────────────────────────────────────────────
def require_auth() -> dict:
    """Return the authenticated user, or render login + st.stop()."""
    controller = CookieController(key="vulnex_cookies")
    st.session_state["_auth_controller_present"] = True

    user = st.session_state.get("auth_user")
    if user:
        _render_account_bar(controller, user)
        return user

    if not db.is_configured():
        _render_not_ready()
        st.stop()

    # bootstrap from cookie
    token = None
    try:
        token = controller.get(COOKIE_NAME)
    except Exception:
        token = None

    if not token and not st.session_state.get("_cookie_probed"):
        # first paint: give the cookie component one frame to hydrate so returning
        # users don't see a login flash before the cookie is read.
        st.session_state["_cookie_probed"] = True
        _render_boot_loader()
        st.stop()

    if token:
        u = db.get_session_user(token)
        if u:
            st.session_state["auth_user"] = u
            st.session_state["auth_token"] = token
            db.log_user_event(user_id=u["id"], session_id=u.get("_session_id"),
                              event_type="session_resume", meta=get_client_meta())
            _render_account_bar(controller, u)
            return u
        _clear_cookie(controller)   # stale / revoked cookie

    _render_login_page(controller)
    st.stop()


# ── UI pieces ────────────────────────────────────────────────────
def _render_boot_loader() -> None:
    st.markdown(
        '<div style="text-align:center;padding:4rem 1rem;color:var(--muted,#6b6b6b)">'
        '<div style="font-size:1.05rem">กำลังตรวจสอบการเข้าสู่ระบบ…</div></div>',
        unsafe_allow_html=True,
    )


def _render_not_ready() -> None:
    st.error("ระบบสมาชิกยังไม่พร้อมใช้งาน — ยังไม่ได้ตั้งค่าการเชื่อมต่อฐานข้อมูล")
    st.info("ผู้ดูแลระบบต้องตั้งค่า SUPABASE_URL และ SUPABASE_SERVICE_KEY ใน st.secrets ก่อน")


def _render_account_bar(controller: CookieController, user: dict) -> None:
    email = user.get("gmail", "")
    c1, c2 = st.columns([5, 1], vertical_alignment="center")
    with c1:
        st.markdown(
            f'<div style="font-size:0.85rem;color:var(--muted,#6b6b6b);padding-top:6px">'
            f'เข้าสู่ระบบในชื่อ <b>{email}</b></div>',
            unsafe_allow_html=True,
        )
    with c2:
        if st.button("ออกจากระบบ", key="logout_btn", use_container_width=True):
            logout(controller)


def _render_login_page(controller: CookieController) -> None:
    st.markdown(
        '<div style="text-align:center;margin:1.5rem 0 0.5rem">'
        '<h1 style="margin-bottom:0.25rem"><span style="color:var(--accent,#c4622d)">VULNEX</span></h1>'
        '<p style="color:var(--muted,#6b6b6b);margin-top:0">'
        'ระบบตรวจสอบความปลอดภัยเว็บไซต์สถานศึกษา — กรุณาเข้าสู่ระบบเพื่อใช้งาน</p></div>',
        unsafe_allow_html=True,
    )
    _c1, _c2, _c3 = st.columns([1, 2, 1])
    with _c2:
        tab_login, tab_signup = st.tabs(["เข้าสู่ระบบ", "สมัครสมาชิก"])
        with tab_login:
            _login_form(controller)
        with tab_signup:
            _signup_form(controller)


def _login_form(controller: CookieController) -> None:
    st.text_input("อีเมล", key="li_email", placeholder="you@example.com")
    st.text_input("รหัสผ่าน", key="li_pw", type="password")
    if st.button("เข้าสู่ระบบ", key="li_submit", use_container_width=True, type="primary"):
        email = (st.session_state.get("li_email") or "").strip()
        pw = st.session_state.get("li_pw") or ""
        if not email or not pw:
            st.warning("กรุณากรอกอีเมลและรหัสผ่าน")
            return
        with st.spinner("กำลังเข้าสู่ระบบ…"):
            user, err = db.authenticate(email, pw)
        if err:
            st.error(err)
            return
        _establish_session(controller, user, event="login")
        st.rerun()


def _signup_form(controller: CookieController) -> None:
    st.text_input("อีเมล", key="su_email", placeholder="you@example.com")
    st.text_input("รหัสผ่าน (อย่างน้อย 8 ตัวอักษร)", key="su_pw", type="password")
    st.text_input("ยืนยันรหัสผ่าน", key="su_pw2", type="password")

    ca, cb = st.columns([3, 2], vertical_alignment="center")
    with ca:
        agree = st.checkbox("ฉันได้อ่านและยอมรับนโยบายความเป็นส่วนตัว", key="su_agree")
    with cb:
        if st.button("อ่านนโยบาย (PDPA)", key="su_read_policy", use_container_width=True):
            open_policy_dialog()

    if st.button("สมัครสมาชิก", key="su_submit", use_container_width=True, type="primary"):
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
            st.warning("กรุณาอ่านและยอมรับนโยบายความเป็นส่วนตัวก่อนสมัคร"); return
        with st.spinner("กำลังสมัครสมาชิก…"):
            user, err = db.create_user(email, pw, POLICY_VERSION)
        if err:
            st.error(err); return
        st.success("สมัครสมาชิกสำเร็จ — กำลังเข้าสู่ระบบ…")
        _establish_session(controller, user, event="signup")
        st.rerun()
