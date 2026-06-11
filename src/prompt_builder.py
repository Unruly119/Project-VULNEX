# src/prompt_builder.py — แปลง JSON → Prompt สำหรับ Gemini
import html as _html


def _sanitize(value: str, maxlen: int = 200) -> str:
    """Sanitize external values before prompt injection."""
    return _html.escape(str(value).strip()[:maxlen])


def build_prompt(scan_result: dict, server_data: dict | None = None) -> str:
    """สร้าง prompt จากผล scan + server data เพื่อส่งให้ Gemini"""

    server_data = server_data or {}

    # ── ดึงข้อมูลจาก scan_result ──────────────────────
    url     = _sanitize(scan_result.get("url", ""))
    headers = scan_result.get("headers", {})
    ssl     = scan_result.get("ssl", {})
    html    = scan_result.get("html", {})

    # ── ส่วนที่ 1: บทบาทของ AI ──────────────────────
    role = """คุณคือผู้เชี่ยวชาญด้าน Cybersecurity สำหรับสถานศึกษาไทย \
ที่ช่วยวิเคราะห์ความปลอดภัยเว็บไซต์และให้คำแนะนำภาษาไทยเข้าใจง่าย \
สำหรับครูและบุคลากรฝ่ายไอทีที่ไม่มีความเชี่ยวชาญด้านความปลอดภัยเป็นพิเศษ"""

    # ── ส่วนที่ 2: ข้อมูลจาก Scanner ────────────────
    score   = headers.get("score", 0)
    missing = headers.get("headers_missing", [])
    found   = headers.get("headers_found", {})
    ext_sc  = html.get("external_scripts", [])
    ins_fm  = html.get("insecure_forms", [])
    ssl_ok  = ssl.get("valid", False)
    days    = ssl.get("days_left", 0)
    ssl_warn= ssl.get("warning", "")

    missing_txt = ", ".join(missing) if missing else "ครบทุกตัว"
    found_txt   = ", ".join(found.keys()) if found else "ไม่มีเลย"
    ext_txt     = str(len(ext_sc)) + " ตัว"

    # ── ส่วนที่ 2b: ข้อมูลจาก Server/CVE Scanner ────
    stype     = _sanitize(server_data.get("server_type", "unknown"))
    sver      = _sanitize(server_data.get("server_version", "N/A"))
    ver_exposed = server_data.get("version_exposed", False)
    http_ver  = _sanitize(server_data.get("http_version", "unknown"))
    dos_risk  = server_data.get("dos_risk", False)
    vulns     = server_data.get("vulnerabilities", [])

    cve_lines = []
    for v in vulns:
        cve_id  = _sanitize(v.get("cve", ""))
        cve_sev = _sanitize(v.get("severity", ""))
        cve_desc = _sanitize(v.get("desc", ""))
        cve_lines.append(f"  - {cve_id} ({cve_sev}): {cve_desc}")
    cve_txt = "\n".join(cve_lines) if cve_lines else "  ไม่พบ CVE"

    # ── รวมเป็น Prompt เดียว ─────────────────────────
    data_section = f"""
ผลการตรวจสอบเว็บไซต์: {url}
────────────────────────────────
คะแนนความปลอดภัย: {score}/100
Security Headers ที่มี: {found_txt}
Security Headers ที่ขาด: {missing_txt}
SSL Certificate: {"ปลอดภัย เหลือ " + str(days) + " วัน" if ssl_ok else "มีปัญหา!"}
คำเตือน SSL: {ssl_warn if ssl_warn else "ไม่มี"}
External Scripts: {ext_txt}
Insecure Forms: {len(ins_fm)} ตัว

Web Server: {stype} {sver}
Version Exposed: {"ใช่ — ควรซ่อน" if ver_exposed else "ไม่"}
HTTP Version: {http_ver}
HTTP/2 DoS Risk (CVE-2023-44487): {"มีความเสี่ยง!" if dos_risk else "ไม่มี"}
CVE ที่พบ:
{cve_txt}
"""

    # ── ส่วนที่ 3: กำหนดรูปแบบคำตอบ ─────────────────
    output_format = """
กรุณาวิเคราะห์และตอบกลับเป็นภาษาไทย แบ่งเป็น 4 ส่วนชัดเจน:

## 🔍 สรุปภาพรวม
[อธิบายสถานะโดยรวม 2-3 ประโยค เหมาะสำหรับผู้บริหาร]

## 🚨 ปัญหาเร่งด่วน (ต้องแก้ทันที)
[bullet list ปัญหาที่อันตรายที่สุด พร้อมอธิบายว่าอันตรายอย่างไร — รวม CVE ที่พบด้วย]

## 🛠️ คำแนะนำการแก้ไข
[ขั้นตอนที่ทำได้จริง เรียงจากง่ายไปยาก]

## ✅ จุดที่ดีแล้ว
[สิ่งที่เว็บไซต์ทำได้ถูกต้อง เพื่อกำลังใจ]
"""

    return f"{role}\n\n{data_section}\n{output_format}"