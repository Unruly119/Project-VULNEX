# Project-VULNEX

ระบบตรวจสอบความปลอดภัยเว็บไซต์สถานศึกษาด้วย AI — **Passive Scan Only**

สแกนเว็บไซต์แบบอ่านอย่างเดียว (ไม่โจมตี ไม่เขียนข้อมูล) ให้คะแนน 0–100
วิเคราะห์เป็นภาษาไทยด้วย AI แล้วสร้างรายงาน PDF 1 หน้าสำหรับผู้ดูแลระบบและครู

## Quick Start

```bash
# 1. Clone and enter project
cd Project-VULNEX

# 2. Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1     # Windows (PowerShell)
# source venv/bin/activate      # Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install the PDF engine's browser (once per machine)
#    The app also does this automatically on the first report build.
python -m playwright install chromium

# 5. Configure API keys
cp .env.example .env
# Edit .env and set GEMINI_API_KEY

# 6. Run the app
streamlit run app.py
```

Open http://localhost:8501 in your browser.

> ไม่มี API key ก็ใช้งานได้ — ระบบจะสลับไปใช้บทวิเคราะห์แบบ **offline (rule-based)** ให้อัตโนมัติ

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GEMINI_API_KEY` | Yes* | — | Google Gemini API key (คีย์หลัก) |
| `GEMINI_API_KEY_Backup` | No | — | คีย์สำรอง — ใช้ก่อนตอนสร้างรายงาน PDF เพื่อไม่แย่งโควต้าหน้าจอ |
| `GEMINI_API_KEY_2` … `_8` | No | — | คีย์เสริมในพูล (กระจายโหลด / หลบ quota อัตโนมัติ) |
| `OPENROUTER_API_KEY` | No | — | ผู้ให้บริการสำรองชั้นถัดจาก Gemini |
| `GEMINI_MODEL` | No | `gemini-2.5-flash` | ดันโมเดลที่ระบุขึ้นหัวแถวของ fallback chain |

\* ไม่ใส่เลยก็รันได้ แต่จะได้บทวิเคราะห์แบบ offline แทน AI

**Deploy (Streamlit Cloud):** ใส่ค่าเดียวกันนี้ใน **secrets.toml** (ไม่ใช่ `.env`) —
`app.py` จะ bridge ค่าจาก `st.secrets` เข้า `os.environ` ให้เอง และ `packages.txt`
ติดตั้ง system library ที่ Chromium ต้องใช้

## Scan Modules

**Active (passive — 7 modules + server info):**
headers · SSL/TLS · HTML/SRI · DNS (SPF/DMARC/DKIM/DNSSEC/CAA) · cookies ·
JS exposure · subdomain recon · server & CVE lookup

**Suspended** (`http_methods`, `cms`, `cors`, `open_files`) — โมดูลเหล่านี้ส่ง request
ที่ไม่ใช่ passive (PUT/DELETE, POST ไป xmlrpc, forced browsing) จึงถูกปิดไว้ที่จุดเรียกใช้
เพื่อให้คำว่า "Passive Scan Only" เป็นจริง โค้ดยังอยู่ครบและเปิดกลับได้ —
ดู `src/scanner/scanner.py:_SUSPENDED_MODULES` และ `SECURITY-AUDIT.md` (finding A1)

## Project Structure

```
app.py                  # Streamlit scan page
pages/user_manual.py    # คู่มือการใช้งาน (หน้าที่สอง)
src/
  ui_shared.py          # ฟอนต์ไทย + CSS + footer ที่ทุกหน้าใช้ร่วมกัน
  ai_engine.py          # Score engine + Gemini/OpenRouter cascade + offline fallback
  module_insight.py     # การ์ดสรุปราย module ในแท็บ Scan Modules
  prompt_builder.py     # AI prompt construction (+ prompt-injection fence)
  html_generator.py     # รายงาน 1 หน้า → HTML
  report_generator.py   # HTML → PDF (Playwright / Chromium)
  scanner/              # Passive scan modules
    scanner.py          # orchestrator (parallel) + SSRF guard + suspended modules
    headers.py ssl_check.py html_parser.py dns_security.py
    cookie_security.py js_exposure.py subdomain_recon.py server_info.py
    http_methods.py cors_policy.py open_files.py cms_fingerprint.py   # suspended
  utils/
    network.py          # SSRF guard + redirect guard
  frontend/index.css    # design tokens + styles
```

## Testing

```bash
# Test Gemini API connection
python tests/test_gemini.py

# Full scan + AI pipeline
python tests/test_ai.py

# Run a single scanner module standalone
python -m scanner.server_info https://nginx.org
```

## Security

เครื่องมือนี้เป็น **defensive tool** — สแกนแบบ passive อย่างเดียว มี SSRF guard
(รวมถึงตรวจ redirect), escape ทุกค่าที่มาจากภายนอกก่อน render และมีการป้องกัน
prompt injection ก่อนส่งข้อมูลให้ AI — รายละเอียดทั้งหมดใน `SECURITY-AUDIT.md`

## Dev Container

Open in GitHub Codespaces or VS Code Dev Containers — dependencies install automatically on attach.
