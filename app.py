# app.py — PTC AI Web Shield  (Phase 4 Final)
# ────────────────────────────────────────────────────────────────
import sys, os
sys.path.insert(0, "src")

import streamlit as st
from datetime import datetime

# ── Page config ──────────────────────────────────────────────────
st.set_page_config(
    page_title="PTC AI Web Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Custom CSS ───────────────────────────────────────────────────
st.markdown("""
<style>
/* Import fonts */
@import url('https://fonts.googleapis.com/css2?family=Noto+Sans+Thai:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Noto Sans Thai', sans-serif !important;
}

/* Dark theme variables */
:root {
    --bg:    #0d1117;
    --s1:    #161b22;
    --s2:    #21262d;
    --cyan:  #22d3ee;
    --lime:  #4ade80;
    --amber: #fbbf24;
    --rose:  #f87171;
    --text:  #e6edf3;
    --muted: #8b949e;
}

/* Hide Streamlit chrome */
#MainMenu, footer, header { visibility: hidden; }
.stDeployButton { display: none; }

/* App background */
.stApp { background: var(--bg); }
.block-container { padding-top: 1.5rem !important; max-width: 1100px; }

/* Hero header */
.hero-wrap {
    background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0d1117 100%);
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 28px 32px 24px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
}
.hero-wrap::before {
    content: '';
    position: absolute;
    top: -50%;  right: -10%;
    width: 300px; height: 300px;
    background: radial-gradient(circle, rgba(34,211,238,.08) 0%, transparent 70%);
    pointer-events: none;
}
.hero-title {
    font-family: 'Noto Sans Thai', sans-serif;
    font-size: 28px; font-weight: 700;
    color: #e6edf3; margin: 0 0 4px 0;
}
.hero-title span { color: #22d3ee; }
.hero-sub {
    font-size: 14px; color: #8b949e;
    margin: 0; font-weight: 300;
}
.hero-badge {
    display: inline-block;
    background: rgba(34,211,238,.1);
    border: 1px solid rgba(34,211,238,.2);
    color: #22d3ee;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px; padding: 3px 10px;
    border-radius: 3px; letter-spacing: .08em;
    margin-bottom: 10px;
}

/* Metric cards */
.metric-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px 18px;
    text-align: center;
}
.metric-val {
    font-family: 'JetBrains Mono', monospace;
    font-size: 28px; font-weight: 600;
    display: block; margin-bottom: 4px;
}
.metric-lbl { font-size: 11px; color: #8b949e; }

/* Risk badge */
.risk-HIGH    { background: rgba(248,113,113,.12); border: 1px solid rgba(248,113,113,.3); color: #f87171; padding: 6px 16px; border-radius: 4px; font-weight: 700; font-size: 13px; }
.risk-CRITICAL{ background: rgba(127,29,29,.2);    border: 1px solid #7f1d1d; color: #fca5a5; padding: 6px 16px; border-radius: 4px; font-weight: 700; font-size: 13px; }
.risk-MEDIUM  { background: rgba(251,191,36,.1);   border: 1px solid rgba(251,191,36,.3); color: #fbbf24; padding: 6px 16px; border-radius: 4px; font-weight: 700; font-size: 13px; }
.risk-LOW     { background: rgba(74,222,128,.1);   border: 1px solid rgba(74,222,128,.3); color: #4ade80; padding: 6px 16px; border-radius: 4px; font-weight: 700; font-size: 13px; }

/* Findings table */
.finding-row {
    display: flex; gap: 12px; align-items: flex-start;
    padding: 10px 14px;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    margin-bottom: 8px;
}
.finding-sev { font-family: 'JetBrains Mono', monospace; font-size: 10px; padding: 2px 8px; border-radius: 3px; flex-shrink: 0; margin-top: 2px; }
.sev-CRITICAL { background: rgba(127,29,29,.3); color: #fca5a5; border: 1px solid #7f1d1d; }
.sev-HIGH     { background: rgba(248,113,113,.1); color: #f87171; border: 1px solid rgba(248,113,113,.3); }
.sev-MEDIUM   { background: rgba(251,191,36,.1); color: #fbbf24; border: 1px solid rgba(251,191,36,.3); }
.sev-LOW      { background: rgba(74,222,128,.1); color: #4ade80; border: 1px solid rgba(74,222,128,.2); }
.sev-PASS     { background: rgba(74,222,128,.1); color: #4ade80; border: 1px solid rgba(74,222,128,.2); }

/* Section card */
.sec-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 20px 22px;
    margin-bottom: 16px;
}
.sec-card-title {
    font-size: 13px; font-weight: 700; color: #22d3ee;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: .05em; text-transform: uppercase;
    margin-bottom: 14px;
    display: flex; align-items: center; gap: 8px;
}

/* Code mono */
.mono-tag {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px; color: #79c0ff;
    background: rgba(121,192,255,.08);
    padding: 2px 7px; border-radius: 3px;
}

/* Override streamlit button */
div.stButton > button {
    background: #22d3ee !important;
    color: #000 !important;
    font-weight: 700 !important;
    border: none !important;
    border-radius: 7px !important;
    padding: 10px 0 !important;
    font-family: 'Noto Sans Thai', sans-serif !important;
    font-size: 15px !important;
    transition: all .2s !important;
}
div.stButton > button:hover {
    background: #06b6d4 !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 20px rgba(34,211,238,.3) !important;
}

/* Download button */
div[data-testid="stDownloadButton"] > button {
    background: #1f6feb !important;
    color: white !important;
    font-weight: 700 !important;
    border: none !important;
    border-radius: 7px !important;
}
div[data-testid="stDownloadButton"] > button:hover {
    background: #388bfd !important;
}

/* Input */
div[data-baseweb="input"] > div {
    background: #161b22 !important;
    border-color: #30363d !important;
    border-radius: 7px !important;
}

/* Progress */
.stProgress > div > div { background: #22d3ee !important; }

/* Tabs */
.stTabs [role="tab"] { color: #8b949e !important; font-family: 'Noto Sans Thai', sans-serif; }
.stTabs [aria-selected="true"] { color: #22d3ee !important; border-bottom-color: #22d3ee !important; }

/* Expander */
.streamlit-expanderHeader { background: #161b22 !important; border-radius: 6px !important; }
</style>
""", unsafe_allow_html=True)

# ── Import modules ────────────────────────────────────────────────
try:
    from scanner        import run_scan
    from ai_engine      import analyze
    from scanner.server_info import check_server
    from report_generator    import build_report
    MODULES_OK = True
except ImportError as e:
    MODULES_OK = False
    MODULE_ERR = str(e)

# ── Helper functions ──────────────────────────────────────────────
def score_color(s):
    if s >= 70: return "#4ade80"
    if s >= 40: return "#fbbf24"
    return "#f87171"

def sev_emoji(s):
    return {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","PASS":"✅","INFO":"🔵"}.get(s,"⚪")

# ── HERO ──────────────────────────────────────────────────────────
st.markdown("""
<div class="hero-wrap">
  <div class="hero-badge">PTC AI WEB SHIELD · CYBERSECURITY TRACK · PSU FUTURE TECH 2026</div>
  <h1 class="hero-title">🛡️ PTC AI <span>Web Shield</span></h1>
  <p class="hero-sub">ระบบตรวจสอบความปลอดภัยเว็บไซต์สถานศึกษาด้วย AI · Passive Scan Only · ISO/IEC 27001 Report</p>
</div>
""", unsafe_allow_html=True)

if not MODULES_OK:
    st.error(f"❌ ไม่สามารถโหลด modules ได้: {MODULE_ERR}")
    st.info("ตรวจสอบว่า venv เปิดอยู่และติดตั้ง requirements.txt แล้ว")
    st.stop()

# ── INPUT SECTION ─────────────────────────────────────────────────
col_url, col_org = st.columns([3, 1])
with col_url:
    url = st.text_input(
        "🌐 URL เว็บไซต์ที่ต้องการตรวจสอบ",
        placeholder="https://www.school.ac.th",
        label_visibility="visible",
    )
with col_org:
    org = st.text_input("🏫 ชื่อองค์กร (สำหรับ Report)", value="วิทยาลัยเทคนิคปัตตานี")

scan_btn = st.button("🔍 เริ่มตรวจสอบ", use_container_width=True)

st.markdown("---")

# ── SCAN LOGIC ────────────────────────────────────────────────────
if scan_btn and url:
    if not url.startswith("http"):
        url = "https://" + url

    # Progress bar
    prog = st.progress(0, text="⚡ เริ่มสแกน...")

    with st.spinner(""):
        prog.progress(20, text="📡 กำลังดึง HTTP Headers...")
        scan_data = run_scan(url)

        prog.progress(50, text="🖥️ กำลังตรวจสอบ Web Server...")
        server_data = check_server(url)

        prog.progress(75, text="🤖 AI กำลังวิเคราะห์...")
        ai_data = analyze(scan_data)

        prog.progress(100, text="✅ เสร็จสิ้น!")
        import time; time.sleep(0.3)
        prog.empty()

    # ── บันทึกใน session state ──────────────────────────────────
    st.session_state["scan_data"]   = scan_data
    st.session_state["ai_data"]     = ai_data
    st.session_state["server_data"] = server_data
    st.session_state["org"]         = org
    st.session_state["url"]         = url
    st.session_state["scanned"]     = True

elif scan_btn and not url:
    st.warning("⚠️ กรุณาใส่ URL ก่อนกด ตรวจสอบ")

# ── RESULTS ──────────────────────────────────────────────────────
if st.session_state.get("scanned"):
    scan_data   = st.session_state["scan_data"]
    ai_data     = st.session_state["ai_data"]
    server_data = st.session_state["server_data"]
    org         = st.session_state["org"]

    score     = ai_data.get("score", 0)
    risk      = ai_data.get("risk_level", "HIGH")
    ssl_ok    = scan_data.get("ssl",{}).get("valid", False)
    days_left = scan_data.get("ssl",{}).get("days_left", 0)
    n_missing = len(scan_data.get("headers",{}).get("headers_missing",[]))
    vulns     = server_data.get("vulnerabilities",[])
    dos_risk  = server_data.get("dos_risk", False)
    stype     = server_data.get("server_type","?").upper()
    sver      = server_data.get("server_version","?")
    http_ver  = server_data.get("http_version","?")

    # ── METRIC ROW ──────────────────────────────────────────────
    sc = score_color(score)
    m1, m2, m3, m4, m5, m6 = st.columns(6)

    m1.markdown(f"""<div class="metric-card">
        <span class="metric-val" style="color:{sc}">{score}</span>
        <span class="metric-lbl">คะแนน/100</span></div>""", unsafe_allow_html=True)

    risk_color = {"HIGH":"#f87171","CRITICAL":"#fca5a5","MEDIUM":"#fbbf24","LOW":"#4ade80"}.get(risk,"#8b949e")
    m2.markdown(f"""<div class="metric-card">
        <span class="metric-val" style="color:{risk_color}; font-size:18px">{risk}</span>
        <span class="metric-lbl">ระดับความเสี่ยง</span></div>""", unsafe_allow_html=True)

    ssl_c = "#4ade80" if ssl_ok else "#f87171"
    m3.markdown(f"""<div class="metric-card">
        <span class="metric-val" style="color:{ssl_c}; font-size:20px">{'✅' if ssl_ok else '❌'}</span>
        <span class="metric-lbl">SSL ({days_left} วัน)</span></div>""", unsafe_allow_html=True)

    hdr_c = "#f87171" if n_missing > 2 else ("#fbbf24" if n_missing > 0 else "#4ade80")
    m4.markdown(f"""<div class="metric-card">
        <span class="metric-val" style="color:{hdr_c}">{n_missing}</span>
        <span class="metric-lbl">Headers ที่ขาด</span></div>""", unsafe_allow_html=True)

    cve_c = "#f87171" if vulns else "#4ade80"
    m5.markdown(f"""<div class="metric-card">
        <span class="metric-val" style="color:{cve_c}">{len(vulns)}</span>
        <span class="metric-lbl">CVE พบ</span></div>""", unsafe_allow_html=True)

    dos_c = "#fca5a5" if dos_risk else "#4ade80"
    m6.markdown(f"""<div class="metric-card">
        <span class="metric-val" style="color:{dos_c}; font-size:20px">{'🚨' if dos_risk else '✅'}</span>
        <span class="metric-lbl">DoS Risk</span></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── TABS ────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🤖 AI Analysis", "🖥️ Server Info", "📋 Headers", "🔒 SSL", "🔬 Raw Data"
    ])

    with tab1:
        st.markdown(ai_data.get("analysis","ไม่มีข้อมูล"))

    with tab2:
        st.markdown(f"""<div class="sec-card">
<div class="sec-card-title">🖥️ WEB SERVER DETECTION</div>
<table style="width:100%;border-collapse:collapse;font-size:13px">
<tr style="border-bottom:1px solid #30363d">
  <td style="padding:8px;color:#8b949e;width:40%">Server Header</td>
  <td style="padding:8px;color:#e6edf3"><code>{server_data.get('server_raw','N/A') or 'Hidden'}</code></td>
</tr>
<tr style="border-bottom:1px solid #30363d">
  <td style="padding:8px;color:#8b949e">Server Type</td>
  <td style="padding:8px;color:#22d3ee;font-weight:600">{stype}</td>
</tr>
<tr style="border-bottom:1px solid #30363d">
  <td style="padding:8px;color:#8b949e">Version</td>
  <td style="padding:8px;color:{'#fbbf24' if server_data.get('version_exposed') else '#4ade80'}">{sver or 'ซ่อนอยู่ ✅'}</td>
</tr>
<tr style="border-bottom:1px solid #30363d">
  <td style="padding:8px;color:#8b949e">HTTP Version</td>
  <td style="padding:8px;color:#e6edf3">{http_ver}</td>
</tr>
<tr>
  <td style="padding:8px;color:#8b949e">HTTP/2 DoS Risk</td>
  <td style="padding:8px;color:{'#f87171' if dos_risk else '#4ade80'}">{'🚨 YES — CVE-2023-44487' if dos_risk else '✅ ไม่มีความเสี่ยง'}</td>
</tr>
</table>
</div>""", unsafe_allow_html=True)

        if server_data.get("version_exposed"):
            st.warning(
                "⚠️ **Version Disclosure (ความเสี่ยงต่ำ):** "
                f"Server โชว์ version `{sver}` ทำให้ผู้โจมตีรู้ว่าควรใช้ exploit ใด "
                "แนะนำซ่อนด้วย `server_tokens off;` (nginx) หรือ `ServerTokens Prod` (Apache)"
            )

        if dos_risk:
            st.error(
                f"🚨 **CVE-2023-44487 — HTTP/2 Rapid Reset DoS (Zero-day 2023)**\n\n"
                f"{server_data.get('dos_detail','')}\n\n"
                "**แนวทางแก้ไข:** อัปเกรด nginx เป็น 1.25.3+ "
                "หรือเพิ่ม `limit_conn` และ `limit_req` เพื่อลดความเสี่ยงชั่วคราว"
            )

        if vulns:
            st.markdown("#### 🔴 CVE ที่พบ")
            for v in vulns:
                sev = v.get("severity","INFO")
                st.markdown(
                    f"<div class='finding-row'>"
                    f"<span class='finding-sev sev-{sev}'>{sev}</span>"
                    f"<div><b style='color:#e6edf3'>{v.get('cve','')}</b><br>"
                    f"<span style='color:#8b949e;font-size:12px'>{v.get('desc','')}</span><br>"
                    f"<span style='color:#22d3ee;font-size:12px'>🔧 {v.get('fix','')}</span></div>"
                    f"</div>",
                    unsafe_allow_html=True
                )

    with tab3:
        found   = scan_data.get("headers",{}).get("headers_found",{})
        missing = scan_data.get("headers",{}).get("headers_missing",[])
        hdr_defs = {
            "Content-Security-Policy":   ("HIGH",    "ป้องกัน XSS Attack"),
            "Strict-Transport-Security": ("HIGH",    "บังคับใช้ HTTPS เสมอ"),
            "X-Frame-Options":           ("HIGH",    "ป้องกัน Clickjacking"),
            "X-Content-Type-Options":    ("MEDIUM",  "ป้องกัน MIME Sniffing"),
            "Referrer-Policy":           ("LOW",     "ควบคุมข้อมูล Referrer"),
            "Permissions-Policy":        ("LOW",     "จำกัด Browser API"),
        }
        st.markdown(f"**Headers Score: {scan_data.get('headers',{}).get('score',0)}/100**")
        for h, (sev, desc) in hdr_defs.items():
            present = h in found
            icon = "✅" if present else "❌"
            val  = found.get(h, "—")[:60] if present else "ไม่มี"
            clr  = "#4ade80" if present else "#f87171"
            st.markdown(
                f"<div class='finding-row'>"
                f"<span style='font-size:18px;flex-shrink:0'>{icon}</span>"
                f"<div style='flex:1'><b style='color:#e6edf3'>{h}</b>"
                f"{'<br><code style=\"font-size:11px;color:#79c0ff\">'+val+'</code>' if present else ''}"
                f"<br><span style='font-size:12px;color:#8b949e'>{desc}</span></div>"
                f"{'<span class=\"finding-sev sev-'+sev+'\">'+sev+'</span>' if not present else ''}"
                f"</div>",
                unsafe_allow_html=True
            )

    with tab4:
        ssl = scan_data.get("ssl",{})
        if ssl.get("warning"):
            st.warning(ssl["warning"])
        col_a, col_b = st.columns(2)
        with col_a:
            st.metric("Status",    "✅ Valid" if ssl.get("valid") else "❌ Invalid")
            st.metric("Issuer",    ssl.get("issuer","N/A"))
        with col_b:
            st.metric("Expires",   ssl.get("expires","N/A"))
            st.metric("Days Left", f"{ssl.get('days_left',0)} วัน",
                      delta=None,
                      delta_color="inverse" if ssl.get("days_left",0) <= 30 else "normal")

    with tab5:
        col_r1, col_r2 = st.columns(2)
        with col_r1:
            with st.expander("📊 Scan Data (JSON)"):
                st.json(scan_data)
        with col_r2:
            with st.expander("🖥️ Server Data (JSON)"):
                st.json(server_data)

    st.markdown("---")

    # ── PDF REPORT ──────────────────────────────────────────────
    st.markdown("### 📄 สร้างรายงาน ISO/IEC 27001")
    col_pdf1, col_pdf2 = st.columns([2, 1])
    with col_pdf1:
        st.info(
            "รายงาน PDF มาตรฐาน **ISO/IEC 27001:2022** ครอบคลุม: "
            "Executive Summary · Technical Findings · CVE Report · "
            "SSL Analysis · AI Analysis · Remediation Plan · Appendix"
        )
    with col_pdf2:
        if st.button("🔧 สร้าง PDF Report", use_container_width=True):
            with st.spinner("กำลังสร้าง PDF..."):
                try:
                    pdf_bytes = build_report(scan_data, ai_data, server_data, org)
                    st.session_state["pdf_bytes"] = pdf_bytes
                    st.session_state["pdf_ready"] = True
                    st.success(f"✅ สร้าง PDF สำเร็จ ({len(pdf_bytes):,} bytes)")
                except Exception as e:
                    st.error(f"❌ สร้าง PDF ไม่สำเร็จ: {e}")

    if st.session_state.get("pdf_ready"):
        now = datetime.now().strftime("%Y%m%d_%H%M")
        fname = f"PTC_WebShield_Report_{now}.pdf"
        st.download_button(
            label="⬇️ ดาวน์โหลด PDF Report",
            data=st.session_state["pdf_bytes"],
            file_name=fname,
            mime="application/pdf",
            use_container_width=True,
        )

elif not st.session_state.get("scanned"):
    st.markdown("""
<div style="text-align:center;padding:48px;color:#8b949e">
  <div style="font-size:48px;margin-bottom:16px">🛡️</div>
  <div style="font-size:16px;margin-bottom:8px;color:#e6edf3">พร้อมตรวจสอบ</div>
  <div style="font-size:13px">ใส่ URL เว็บไซต์ด้านบนแล้วกด <b>เริ่มตรวจสอบ</b></div>
</div>
""", unsafe_allow_html=True)