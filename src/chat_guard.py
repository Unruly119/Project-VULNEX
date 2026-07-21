# src/chat_guard.py — การ์ดความปลอดภัยของ dotRED ("ถามต่อกับ AI")
# ────────────────────────────────────────────────────────────────
#   สามชั้นการป้องกัน (แทนที่ chat_assistant.py เดิมที่หายไปจากโปรเจกต์):
#     1) in_scope()       — pre-flight: กันคำถามนอกเรื่อง/jailbreak ก่อนเรียก AI เลย
#                           (ประหยัด API call + กันโมเดลถูกหลอกให้เปลี่ยนบทบาท)
#     2) sanitize_reply() — post-flight: ตัด system-prompt leakage ถ้าหลุดออกมา
#     3) suggested_questions() — สร้างคำถามแนะนำจาก findings จริงของ scan นี้
#
#   หมายเหตุ: ภาษาไทยไม่มีการเว้นวรรคคำ จึงจับคำไทยแบบ substring ตรง ๆ
#   (ใช้ \\b กับคำอังกฤษเท่านั้น เพราะภาษาไทยไม่มี word boundary ที่ใช้ได้กับ \\b)
# ────────────────────────────────────────────────────────────────
from __future__ import annotations

import re

# ── Scope gate ────────────────────────────────────────────────────
_JAILBREAK_PATTERNS = [
    r"\bignore (all |previous |above )?instructions?\b",
    r"\bforget (all |your )?(instructions?|rules?|system prompt)\b",
    r"\byou are now\b",
    r"\bact as\b",
    r"\bdan mode\b",
    r"\bjailbreak\b",
    r"\bsystem prompt\b",
    r"\breveal your (prompt|instructions?)\b",
    r"\bpretend (you|to)\b",
    "ลืมคำสั่งเดิม",
    "เปลี่ยนบทบาท",
    "สวมบทบาทเป็น",
    "ไม่ต้องทำตามกฎ",
    "บอกprompt",
    "system prompt คือ",
]

_WEAPONIZATION_PATTERNS = [
    r"\bhow (do i|to) (hack|exploit|attack|breach)\b",
    r"\bwrite (a |me a )?(malware|virus|ransomware|exploit)\b",
    r"\bsql injection payload\b",
    r"\breverse shell\b",
    "วิธีแฮก",
    "แฮกเว็บ",
    "เจาะระบบเว็บอื่น",
    "โจมตีเว็บ",
    "เขียนไวรัส",
    "ทำ ddos",
    "สร้างมัลแวร์",
]

_OFF_TOPIC_HINTS = [
    r"\bwrite (a |me a )?(poem|song|story|essay)\b",
    r"\btranslate this\b",
    r"\bmath (problem|homework)\b",
    "แต่งกลอน",
    "แต่งเพลง",
    "เขียนเรียงความ",
    "ทำการบ้าน",
    "สูตรคูณ",
    "ดูดวง",
    "ทำนายอนาคต",
]

_ALL_BLOCK_RE = re.compile(
    "|".join(_JAILBREAK_PATTERNS + _WEAPONIZATION_PATTERNS), re.IGNORECASE
)
_OFF_TOPIC_RE = re.compile("|".join(_OFF_TOPIC_HINTS), re.IGNORECASE)

_REFUSAL_JAILBREAK = (
    "ขอโทษครับ ผม dotRED ช่วยเรื่องนี้ไม่ได้ — ผมตอบเฉพาะคำถามเกี่ยวกับ"
    "ผลการสแกนความปลอดภัยเว็บไซต์นี้เท่านั้น ลองถามเรื่อง Headers, SSL, DNS, Cookies หรือ CVE "
    "ที่พบในการสแกนดูนะครับ"
)
_REFUSAL_OFF_TOPIC = (
    "อันนี้อยู่นอกเหนือขอบเขตของผม dotRED ครับ — ผมช่วยได้เฉพาะคำถามเกี่ยวกับผลการสแกนความปลอดภัย"
    "เว็บไซต์นี้ ลองถามเรื่องคะแนนความปลอดภัย, ช่องโหว่ที่พบ, หรือวิธีแก้ไขดูนะครับ"
)


def in_scope(user_message: str) -> tuple[bool, str | None]:
    """คืน (True, None) ถ้าคำถามอยู่ในขอบเขต, หรือ (False, ข้อความปฏิเสธ) ถ้าไม่.

    ทำงานแบบ pre-flight — ไม่เรียก AI เลยถ้าตรวจพบว่าอยู่นอกเรื่อง ประหยัด
    API call และกันการหลอกโมเดลให้ทำตัวนอกบทบาทตั้งแต่ต้นทาง."""
    msg = (user_message or "").strip()
    if not msg:
        return False, "พิมพ์คำถามมาได้เลยครับ"

    if _ALL_BLOCK_RE.search(msg):
        return False, _REFUSAL_JAILBREAK

    if _OFF_TOPIC_RE.search(msg):
        return False, _REFUSAL_OFF_TOPIC

    return True, None


# ── Post-flight sanitizer ─────────────────────────────────────────
_LEAK_LINE_RE = re.compile(
    r"^(system prompt|SYSTEM:|=== BEGIN|=== END|UNTRUSTED SCAN DATA|"
    r"คุณคือ \"?dotRED\"?)",
    re.IGNORECASE,
)


def sanitize_reply(text: str) -> str:
    """ตัดบรรทัดที่อาจเป็นการหลุดของ system prompt/context fence ออกจากคำตอบ."""
    if not text:
        return text
    lines = text.split("\n")
    cleaned = [ln for ln in lines if not _LEAK_LINE_RE.match(ln.strip())]
    return "\n".join(cleaned).strip()


# ── Suggested questions (empty-state) ─────────────────────────────
def suggested_questions(scan_data: dict, server_data: dict, ai_data: dict) -> list[str]:
    """สร้างคำถามแนะนำ 3-4 ข้อจาก findings จริงของ scan นี้ (ไม่ใช้ AI — deterministic)."""
    qs: list[str] = []
    scan_data = scan_data or {}
    server_data = server_data or {}

    headers = scan_data.get("headers", {}) or {}
    missing = headers.get("headers_missing", []) or []
    if missing:
        qs.append(f"ควรแก้ {missing[0]} ยังไง?")

    ssl = scan_data.get("ssl", {}) or {}
    if not ssl.get("valid"):
        qs.append("ปัญหา SSL ที่เจอร้ายแรงแค่ไหน?")
    elif ssl.get("days_left", 999) < 30:
        qs.append("ใบรับรอง SSL ใกล้หมดอายุ ต้องทำอะไรบ้าง?")

    vulns = server_data.get("vulnerabilities", []) or []
    if vulns:
        qs.append(f"{vulns[0].get('cve', 'CVE ที่พบ')} อันตรายแค่ไหน?")

    dns = scan_data.get("dns", {}) or {}
    if not dns.get("error"):
        if not (dns.get("spf", {}) or {}).get("present"):
            qs.append("ทำไมต้องมี SPF/DMARC?")

    if not qs:
        qs.append("สรุปผลสแกนให้ฟังหน่อย")
    qs.append("ควรแก้อะไรก่อนเป็นอันดับแรก?")

    seen = set()
    out = []
    for q in qs:
        if q not in seen:
            seen.add(q)
            out.append(q)
        if len(out) >= 4:
            break
    return out
