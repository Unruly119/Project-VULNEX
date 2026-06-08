# src/prompt_builder.py — แปลง JSON → Prompt สำหรับ Gemini

def build_prompt(scan_result: dict) -> str:  
    """สร้าง prompt จากผล scan เพื่อส่งให้ Gemini"""

    # ── ดึงข้อมูลจาก scan_result ──────────────────────
    url     = scan_result.get("url", "")
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

    # แปลงรายการ list → ข้อความ bullet
    missing_txt = ", ".join(missing) if missing else "ครบทุกตัว"  
    found_txt   = ", ".join(found.keys()) if found else "ไม่มีเลย"
    ext_txt     = str(len(ext_sc)) + " ตัว"

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
"""

    # ── ส่วนที่ 3: กำหนดรูปแบบคำตอบ ─────────────────
    output_format = """
กรุณาวิเคราะห์และตอบกลับเป็นภาษาไทย แบ่งเป็น 4 ส่วนชัดเจน:

## 🔍 สรุปภาพรวม
[อธิบายสถานะโดยรวม 2-3 ประโยค เหมาะสำหรับผู้บริหาร]

## 🚨 ปัญหาเร่งด่วน (ต้องแก้ทันที)
[bullet list ปัญหาที่อันตรายที่สุด พร้อมอธิบายว่าอันตรายอย่างไร]

## 🛠️ คำแนะนำการแก้ไข
[ขั้นตอนที่ทำได้จริง เรียงจากง่ายไปยาก]

## ✅ จุดที่ดีแล้ว
[สิ่งที่เว็บไซต์ทำได้ถูกต้อง เพื่อกำลังใจ]
"""

    # รวม 3 ส่วนเป็น prompt เดียว
    return f"{role}\n\n{data_section}\n{output_format}"  