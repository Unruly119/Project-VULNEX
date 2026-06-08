# app.py — Streamlit UI หลัก (Phase 3 complete)
import sys, streamlit as st
sys.path.insert(0, "src")
from scanner   import run_scan
from ai_engine import analyze

# ── ตั้งค่าหน้า ───────────────────────────────
st.set_page_config(
    page_title="PTC AI Web Shield",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ PTC AI Web Shield")
st.caption("ระบบตรวจสอบความปลอดภัยเว็บไซต์สถานศึกษา — powered by Gemini AI")
st.divider()

# ── Input URL ────────────────────────────────
url = st.text_input(
    "🌐 URL เว็บไซต์ที่ต้องการตรวจสอบ",
    placeholder="เช่น https://www.school.ac.th"
)

scan_btn = st.button("🔍 เริ่มตรวจสอบ", type="primary", use_container_width=True)

# ── Logic หลัก ───────────────────────────────
if scan_btn and url:
    with st.spinner("⏳ กำลังสแกน..."):     
        scan_data = run_scan(url)
    with st.spinner("🤖 AI กำลังวิเคราะห์..."):
        ai_data = analyze(scan_data)

    # ── แสดง Metrics row ─────────────────────
    c1, c2, c3, c4 = st.columns(4)  
    c1.metric("📊 คะแนน",
              f"{ai_data['score']}/100")
    c2.metric("⚠️ ระดับความเสี่ยง",
              ai_data["risk_level"])
    c3.metric("🔒 SSL",
              "✅ ปลอดภัย" if scan_data["ssl"]["valid"] else "❌ มีปัญหา")
    c4.metric("📋 Headers ที่ขาด",
              f"{len(scan_data['headers']['headers_missing'])} ตัว")

    st.divider()

    # ── แสดงผล AI Analysis ───────────────────
    st.subheader("🤖 ผลวิเคราะห์จาก AI")
    st.markdown(ai_data["analysis"])  

    # ── แสดง Raw Data (ซ่อนอยู่) ────────────
    with st.expander("🔬 ดูข้อมูล Raw (สำหรับนักเทคนิค)"):  
        st.json(scan_data)

elif scan_btn and not url:
    st.warning("⚠️ กรุณาใส่ URL ก่อน")