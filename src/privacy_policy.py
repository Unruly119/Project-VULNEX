# privacy_policy.py — Privacy notice for Project-VULNEX (Thai, Apple-style voice)
# ────────────────────────────────────────────────────────────────
#   Shown at signup and openable any time from the auth screen. Consent is
#   required to create an account; the modal (st.dialog) keeps the signup form
#   filled while it's read. The copy is principle-led and reassuring rather than
#   a clinical enumeration — calm, plain, and honest.
#
#   All copy is static (no user input), so no escaping is needed here.
# ────────────────────────────────────────────────────────────────
import streamlit as st

# Bump this (and supabase_client.PRIVACY_VERSION) together on a material change.
POLICY_VERSION = "2026-07-14"

# The short line under the "read policy" affordance and at signup.
POLICY_TAGLINE = "ข้อมูลของคุณเป็นของคุณ เราเก็บเท่าที่จำเป็นและดูแลมันอย่างดีที่สุด"

POLICY_MD = """
เราออกแบบ VULNEX ด้วยความเชื่อง่าย ๆ ข้อเดียว — **ความเป็นส่วนตัวของคุณมาก่อน**
เราเก็บข้อมูลเท่าที่จำเป็นต่อการให้บริการจริง ๆ และดูแลมันอย่างดีที่สุด
ข้อมูลของคุณเป็นของคุณ ไม่ใช่สินค้าที่เรานำไปขาย

### สิ่งที่เราเก็บ และเพราะอะไร
- **บัญชีของคุณ** — อีเมลที่ใช้เข้าสู่ระบบ และรหัสผ่านที่ถูกเข้ารหัสแบบทางเดียว
  จนแม้แต่เราเองก็อ่านไม่ได้
- **ประวัติการตรวจสอบ** — เว็บไซต์ที่คุณสแกนและผลลัพธ์ เก็บไว้ให้คุณย้อนกลับมาดูได้
- **ข้อมูลการใช้งานพื้นฐาน** — เท่าที่ระบบต้องใช้เพื่อรักษาความปลอดภัยของบัญชี
  และพัฒนาเครื่องมือให้ดีขึ้น ไม่มากไปกว่านั้น

### สิ่งที่เราไม่ทำ
เราไม่ขายข้อมูลของคุณ ไม่แลกเปลี่ยนเพื่อการโฆษณา และไม่เก็บรหัสผ่านเป็นข้อความธรรมดา
การสแกนของเราเป็นแบบ **อ่านอย่างเดียว** — มองดูเว็บไซต์เหมือนผู้เข้าชมทั่วไป
ไม่แตะต้อง ไม่เปลี่ยนแปลง และไม่รบกวนระบบของเป้าหมาย

### คุณคือคนควบคุม
คุณขอดู แก้ไข หรือลบข้อมูลของคุณเมื่อไรก็ได้ และถอนความยินยอมได้ทุกเมื่อ
เพียงติดต่อทีมงาน เราจะดำเนินการให้ตามสิทธิ์ของคุณภายใต้
พระราชบัญญัติคุ้มครองข้อมูลส่วนบุคคล (PDPA)

_เมื่อกดยอมรับ ถือว่าคุณเข้าใจและยินยอมตามแนวทางนี้ — ขอบคุณที่ไว้วางใจให้เราดูแล_
"""


def render_policy_body() -> None:
    st.markdown(POLICY_MD)


# Default (small) dialog width as the base; index.css widens it to a 620px
# reading measure — "large" spans ~90ch of Thai text, too long to read.
@st.dialog("ความเป็นส่วนตัวของคุณ")
def open_policy_dialog() -> None:
    """Read-only policy modal. Closing it keeps the signup form intact."""
    with st.container(key="pdpa-body"):
        st.markdown(
            '<div class="pdpa-lede">'
            'ใช้เวลาสักครู่ทำความเข้าใจว่าเราดูแลข้อมูลของคุณอย่างไร'
            '</div>',
            unsafe_allow_html=True)
        render_policy_body()
        if st.button("เข้าใจแล้ว", use_container_width=True, key="privacy_close_btn"):
            st.rerun()
