# pages/user_manual.py — VULNEX user manual (Thai, non-expert audience)
# ────────────────────────────────────────────────────────────────
#   A step-by-step walkthrough of the scan page. Every on-screen control
#   is shown as a faithful replica (faux field / button / tab strip) next
#   to a plain-Thai explanation and a concrete example, then summarised in
#   a button-reference grid. All copy is static and authored here, so no
#   HTML escaping is required (there is no user input on this page).
#
#   Shares the exact design system with app.py via ui_shared: same Thai
#   webfont, same index.css tokens, same branded sidebar nav.
# ────────────────────────────────────────────────────────────────
import sys

sys.path.insert(0, "src")          # must precede src/* module imports

import streamlit as st

st.set_page_config(
    page_title="คู่มือการใช้งาน · Project-VULNEX",
    page_icon="📖",
    layout="wide",
    initial_sidebar_state="collapsed",   # sidebar removed — keep it shut
)

from ui_shared import inject_base_styles, render_footer

inject_base_styles()

# ── Top-left back button ─────────────────────────────────────────
# The sidebar nav is gone; this is the only way back to the scan page from
# here. Same-tab st.switch_page replaces the manual with the scan page in
# place (no new browser tab).
_back_col, _ = st.columns([1, 5])
with _back_col:
    if st.button(
        ":material/arrow_back: กลับ",
        key="manual_back_top",
        use_container_width=True,
    ):
        st.switch_page("app.py")


# ── Inline icon helpers (lucide-style, matching app.py's icon language) ──
def _icon(paths: str, size: int = 18) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}"'
        ' viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
        f' stroke-linecap="round" stroke-linejoin="round">{paths}</svg>'
    )


I_LINK    = '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>'
I_BOOK    = '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>'
I_SEARCH  = '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>'
I_TABS    = '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M9 21V9"/>'
I_FILE    = '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>'
I_DOWNLOAD = '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>'
I_INFO    = '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>'
I_MONITOR = '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>'
I_BOOKOPEN = I_BOOK


# ── Hero ─────────────────────────────────────────────────────────
st.markdown(f"""
<div class="manual-hero">
  <div class="manual-hero-eyebrow">คู่มือการใช้งาน · Project-VULNEX</div>
  <h1 class="manual-hero-title">เริ่มตรวจสอบเว็บไซต์ของคุณ ใน 5 ขั้นตอน</h1>
  <p class="manual-hero-sub">
    คู่มือนี้พาคุณดูทุกปุ่มและทุกส่วนของหน้าตรวจสอบ พร้อมตัวอย่างจริงว่ากดแล้วเกิดอะไรขึ้น
    ออกแบบมาเพื่อครูและเจ้าหน้าที่ไอทีของสถานศึกษา — ไม่ต้องมีความรู้ด้านความปลอดภัยมาก่อน
  </p>
</div>
""", unsafe_allow_html=True)

# ── Lead / what this tool does ───────────────────────────────────
st.markdown(f"""
<div class="manual-lead">
  <p>
    <strong>VULNEX</strong> คือเครื่องมือ <strong>ตรวจสอบความปลอดภัยแบบไม่รุกล้ำ (Passive Scan)</strong>
    สำหรับเว็บไซต์สถานศึกษา ระบบจะส่งเพียงคำขออ่านข้อมูลทั่วไปเหมือนการเปิดเว็บปกติ
    <strong>ไม่มีการเจาะระบบ ไม่มีการเดารหัสผ่าน และไม่แก้ไขข้อมูลใด ๆ</strong>
    เมื่อตรวจเสร็จ คุณจะได้คะแนนความปลอดภัย 0–100 บทวิเคราะห์ภาษาไทยจาก AI
    และรายงาน PDF หนึ่งหน้าที่ดาวน์โหลดได้ทันที
  </p>
</div>
""", unsafe_allow_html=True)

# ── Section: step-by-step ────────────────────────────────────────
st.markdown('<h2 class="manual-h2">ทำตามทีละขั้นตอน</h2>', unsafe_allow_html=True)

# Step 1 — enter URL
st.markdown(f"""
<div class="manual-step">
  <div class="manual-step-num">1</div>
  <div class="manual-step-body">
    <div class="manual-step-title">ใส่ URL ของเว็บไซต์ที่ต้องการตรวจสอบ</div>
    <p class="manual-step-desc">
      พิมพ์ที่อยู่เว็บไซต์ลงในช่องด้านบนสุดของหน้าตรวจสอบ ใส่เพียงชื่อโดเมนก็พอ
      เช่น <code>www.school.ac.th</code> ระบบจะเติม <code>https://</code> ให้อัตโนมัติ
      รองรับทั้ง HTTP และ HTTPS
    </p>
    <div class="manual-preview">
      <div class="manual-preview-cap">{_icon(I_MONITOR, 14)} ตัวอย่างบนหน้าจอ</div>
      <div class="faux-field-label">URL เว็บไซต์ที่ต้องการตรวจสอบ</div>
      <div class="faux-input">https://www.school.ac.th<span class="caret"></span></div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# Step 2 — start scan
st.markdown(f"""
<div class="manual-step">
  <div class="manual-step-num">2</div>
  <div class="manual-step-body">
    <div class="manual-step-title">กดปุ่ม “เริ่มตรวจสอบ”</div>
    <p class="manual-step-desc">
      กดปุ่มสีเข้มใต้ช่อง URL ระบบจะเริ่มสแกน 12 ด้านความปลอดภัยพร้อมกัน
      (Headers, SSL, DNS, Cookies, CORS, CMS และอื่น ๆ) แล้วให้ AI วิเคราะห์ผล
      ระหว่างนี้จะมีแถบความคืบหน้าบอกสถานะ ใช้เวลาประมาณไม่กี่วินาทีถึงราวหนึ่งนาที
    </p>
    <div class="manual-preview">
      <div class="manual-preview-cap">{_icon(I_MONITOR, 14)} ตัวอย่างบนหน้าจอ</div>
      <div class="faux-btn-row">
        <span class="faux-btn is-primary">เริ่มตรวจสอบ</span>
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# Step 3 — read the score
st.markdown(f"""
<div class="manual-step">
  <div class="manual-step-num">3</div>
  <div class="manual-step-body">
    <div class="manual-step-title">อ่านคะแนนและระดับความเสี่ยง</div>
    <p class="manual-step-desc">
      เมื่อสแกนเสร็จ แถวสรุปด้านบนจะแสดง <strong>วงแหวนคะแนน 0–100</strong>
      ยิ่งคะแนนสูงยิ่งปลอดภัย ถัดมาคือ <strong>ระดับความเสี่ยง</strong> สถานะใบรับรอง SSL
      จำนวน Header ที่ขาด จำนวนช่องโหว่ (CVE) และความเสี่ยงถูกโจมตีให้ล่ม (DoS)
    </p>
    <p class="manual-step-desc">
      ระดับความเสี่ยงมี 4 ระดับ — สีช่วยให้เห็นความรุนแรงได้ทันที โดยไม่ต้องตีความตัวเลข:
    </p>
    <div class="manual-preview">
      <div class="manual-preview-cap">{_icon(I_MONITOR, 14)} ตัวอย่างบนหน้าจอ</div>
      <div class="faux-btn-row">
        <span class="faux-btn" style="background:var(--c-low-bg);color:var(--c-low);border-color:var(--c-low-bdr)">LOW · ความเสี่ยงต่ำ</span>
        <span class="faux-btn" style="background:var(--c-med-bg);color:var(--c-med);border-color:var(--c-med-bdr)">MEDIUM · ปานกลาง</span>
        <span class="faux-btn" style="background:var(--c-high-bg);color:var(--c-high);border-color:var(--c-high-bdr)">HIGH · สูง</span>
        <span class="faux-btn" style="background:var(--c-crit-bg);color:var(--c-crit);border-color:var(--c-crit-bdr)">CRITICAL · วิกฤต</span>
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# Step 4 — explore tabs
st.markdown(f"""
<div class="manual-step">
  <div class="manual-step-num">4</div>
  <div class="manual-step-body">
    <div class="manual-step-title">เจาะลึกผลแต่ละด้านในแท็บ</div>
    <p class="manual-step-desc">
      ใต้แถวสรุปมี 6 แท็บ คลิกเพื่อดูรายละเอียดทีละด้าน เริ่มที่
      <strong>AI Analysis</strong> ซึ่งสรุปเป็นภาษาไทยว่าอะไรเร่งด่วนและควรแก้อย่างไร
      หากยังไม่ได้ตั้งค่าคีย์ AI ระบบจะใช้บทวิเคราะห์แบบออฟไลน์ให้แทนโดยอัตโนมัติ
    </p>
    <div class="manual-preview">
      <div class="manual-preview-cap">{_icon(I_MONITOR, 14)} ตัวอย่างบนหน้าจอ</div>
      <div class="faux-tabs">
        <span class="faux-tab is-active">AI Analysis</span>
        <span class="faux-tab">Server Info</span>
        <span class="faux-tab">HTTP Headers</span>
        <span class="faux-tab">SSL Certificate</span>
        <span class="faux-tab">Scan Modules</span>
        <span class="faux-tab">Raw Data</span>
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# Step 5 — generate & download PDF
st.markdown(f"""
<div class="manual-step">
  <div class="manual-step-num">5</div>
  <div class="manual-step-body">
    <div class="manual-step-title">สร้างและดาวน์โหลดรายงาน PDF</div>
    <p class="manual-step-desc">
      เลื่อนลงล่างสุดแล้วกด <strong>“สร้างรายงาน PDF”</strong> ระบบจะประกอบรายงานหนึ่งหน้า
      ที่อ่านง่าย ครอบคลุมบทสรุป ผลทุกหัวข้อ สถานะผ่าน/ไม่ผ่าน และคำแนะนำแก้ไขพร้อม
      ตัวอย่างการตั้งค่าจริง เมื่อสร้างเสร็จจะมีปุ่ม <strong>“ดาวน์โหลด PDF Report”</strong> ให้บันทึกไฟล์
      ชื่อสถานศึกษาในรายงานจะถูกดึงมาจากชื่อหรือโดเมนของเว็บไซต์ให้อัตโนมัติ
    </p>
    <div class="manual-preview">
      <div class="manual-preview-cap">{_icon(I_MONITOR, 14)} ตัวอย่างบนหน้าจอ</div>
      <div class="faux-btn-row">
        <span class="faux-btn is-primary">สร้างรายงาน PDF</span>
        <span class="faux-btn is-accent">{_icon(I_DOWNLOAD, 16)} ดาวน์โหลด PDF Report</span>
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Tip callout ──────────────────────────────────────────────────
st.markdown(f"""
<div class="manual-tip">
  {_icon(I_INFO, 20)}
  <p>
    <strong>ไม่ต้องเข้าสู่ระบบ และไม่ต้องกรอกชื่อสถานศึกษาเอง</strong> —
    เพียงใส่ URL แล้วกดตรวจสอบ ระบบจะจัดการที่เหลือให้ทั้งหมด
    การสแกนเป็นแบบไม่รุกล้ำ จึงปลอดภัยต่อเว็บไซต์เป้าหมายเสมอ
  </p>
</div>
""", unsafe_allow_html=True)

# ── Section: every control explained ─────────────────────────────
st.markdown('<h2 class="manual-h2">ปุ่มและส่วนควบคุมทั้งหมด</h2>', unsafe_allow_html=True)

_REFS = [
    (I_LINK, "ช่องใส่ URL",
     "ช่องพิมพ์ที่อยู่เว็บไซต์ที่ต้องการตรวจสอบ ใส่ชื่อโดเมนก็พอ",
     "อยู่บนสุดของหน้าตรวจสอบ"),
    (I_BOOK, "ปุ่ม “คู่มือการใช้งาน”",
     "เปิดหน้าคู่มือนี้ — ดูวิธีใช้และคำอธิบายปุ่มต่าง ๆ ได้ทุกเมื่อ",
     "อยู่ทางขวาของช่อง URL"),
    (I_SEARCH, "ปุ่ม “เริ่มตรวจสอบ”",
     "เริ่มสแกน 12 ด้านความปลอดภัยพร้อมกัน แล้วให้ AI วิเคราะห์ผล",
     "อยู่ใต้ช่อง URL"),
    (I_TABS, "แท็บผลการตรวจสอบ",
     "6 แท็บแยกดูรายละเอียด: AI Analysis, Server Info, HTTP Headers, SSL, Scan Modules, Raw Data",
     "ปรากฏหลังสแกนเสร็จ"),
    (I_FILE, "ปุ่ม “สร้างรายงาน PDF”",
     "ประกอบรายงานความปลอดภัยหนึ่งหน้าพร้อมคำแนะนำแก้ไข",
     "อยู่ล่างสุดของหน้าผลลัพธ์"),
    (I_DOWNLOAD, "ปุ่ม “ดาวน์โหลด PDF Report”",
     "บันทึกไฟล์รายงาน PDF ลงเครื่องของคุณ",
     "ปรากฏหลังสร้างรายงานเสร็จ"),
]

_cards = "".join(
    f"""
  <div class="btn-ref">
    <div class="btn-ref-head">
      <span class="btn-ref-chip">{_icon(icon, 17)}</span>
      <span class="btn-ref-name">{name}</span>
    </div>
    <div class="btn-ref-desc">{desc}<span class="where">{_icon(I_MONITOR, 11)} {where}</span></div>
  </div>"""
    for icon, name, desc, where in _REFS
)
st.markdown(f'<div class="btn-ref-grid">{_cards}</div>', unsafe_allow_html=True)

# ── Foot CTA — back to the scan page ─────────────────────────────
st.markdown("""
<div class="manual-foot">
  <div class="manual-foot-title">พร้อมตรวจสอบเว็บไซต์ของคุณแล้วหรือยัง?</div>
  <div class="manual-foot-sub">กลับไปที่หน้าตรวจสอบ ใส่ URL แล้วเริ่มได้ทันที</div>
</div>
""", unsafe_allow_html=True)

_c1, _c2, _c3 = st.columns([1, 2, 1])
with _c2:
    if st.button(
        ":material/security: กลับไปหน้าตรวจสอบ",
        key="back_to_scan_btn",
        use_container_width=True,
        type="primary",
    ):
        st.switch_page("app.py")

# Site footer — credibility references
render_footer()
