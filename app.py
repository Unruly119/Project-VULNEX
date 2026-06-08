# app.py — หน้าแรกของ PTC AI Web Shield
import streamlit as st

# ตั้งค่าหน้า
st.set_page_config(
    page_title="PTC AI Web Shield",
    page_icon="🛡️",
    layout="wide"
)

# Header
st.title("🛡️ PTC AI Web Shield")
st.subheader("ระบบตรวจสอบความปลอดภัยเว็บไซต์ด้วย AI")
st.divider()

# รับ URL จากผู้ใช้
url = st.text_input(
    "🌐 ใส่ URL ที่ต้องการตรวจสอบ:",
    placeholder="https://example.com"
)

if st.button("🔍 ตรวจสอบ", type="primary"):
    if url:
        st.success(f"✅ รับ URL: {url} — พร้อมเชื่อม AI!")
    else:
        st.warning("⚠️ กรุณาใส่ URL ก่อน")