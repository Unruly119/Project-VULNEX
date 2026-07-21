# src/chat_context.py — จัดการความจำบทสนทนาของ dotRED (ChatBOT)
# ────────────────────────────────────────────────────────────────
#   แหล่งข้อมูลที่ dotRED เข้าถึงได้ (ตามที่ยืนยันแล้ว):
#     ✅ AI สรุปที่แสดงบนหน้าเว็บ (ai_data["analysis"])
#     ✅ Raw scan data ทั้งหมดของ session นี้ (scan_data, server_data)
#     ✅ Qdrant Cloud (ผ่าน rag.retrieve ที่เรียกใน prompt_builder.build_chat_prompt —
#        คลังความรู้ OWASP/CWE/NIST/CVE)
#     ❌ Supabase — ห้ามแตะเด็ดขาด (ตามที่ยืนยัน) ไฟล์นี้ไม่ import supabase_client เลย
#
#   หน่วยความจำบทสนทนา: เก็บใน st.session_state["dotred_history"] เป็น
#   list[{"role": "user"|"assistant", "content": str}] คงอยู่ตลอด session
#   (จนกว่าจะสแกนเว็บใหม่ หรือกด "ล้างแชท") — ทำให้ dotRED ไม่ลืมว่าคุยอะไรมาก่อน
#   แม้จะคุยไปนาน ๆ ก็ตาม
# ────────────────────────────────────────────────────────────────
from __future__ import annotations

import streamlit as st

_HISTORY_KEY = "dotred_history"
_SCAN_FINGERPRINT_KEY = "dotred_scan_fingerprint"

# จำนวนคู่ user/assistant ล่าสุดที่ส่งเข้า prompt เต็ม ๆ (ยิ่งมาก = จำได้ไกลขึ้น
# แต่ prompt ยาวขึ้น/ช้าลง) ประวัติที่เกินนี้ยังอยู่ใน session_state ครบ เพียงแต่ไม่ถูก
# ส่งซ้ำทุกครั้ง — ผู้ใช้เลื่อนดูย้อนหลังได้เต็ม แต่ AI "จำ" อย่างมีประสิทธิภาพหลายเทิร์นล่าสุด
_MAX_TURNS_IN_PROMPT = 12


def _fingerprint(scan_data: dict) -> str:
    """ลายนิ้วมือคร่าว ๆ ของผลสแกนปัจจุบัน ใช้ตรวจว่าเป็น target เดิมหรือสแกนใหม่แล้ว."""
    scan_data = scan_data or {}
    url = scan_data.get("url", "")
    ts = scan_data.get("scan_time", "") or scan_data.get("timestamp", "")
    return f"{url}|{ts}"


def ensure_history_for_scan(scan_data: dict) -> None:
    """เรียกทุกครั้งที่ render หน้า AI Analysis — ถ้าเป็นการสแกนเว็บใหม่ (URL/เวลาต่าง
    จากที่จำไว้) ให้เริ่มแชทใหม่อัตโนมัติ เพราะบริบทเก่าไม่เกี่ยวกับเว็บใหม่แล้ว."""
    fp = _fingerprint(scan_data)
    if st.session_state.get(_SCAN_FINGERPRINT_KEY) != fp:
        st.session_state[_SCAN_FINGERPRINT_KEY] = fp
        st.session_state[_HISTORY_KEY] = []


def get_history() -> list[dict]:
    return st.session_state.setdefault(_HISTORY_KEY, [])


def append_turn(role: str, content: str) -> None:
    get_history().append({"role": role, "content": content})


def clear_history() -> None:
    st.session_state[_HISTORY_KEY] = []


def recent_turns_for_prompt() -> list[dict]:
    """ประวัติล่าสุดสำหรับใส่ใน prompt (build_chat_prompt ตัดที่ 12 เทิร์นอยู่แล้ว
    ตรงกับค่านี้ — ปรับคู่กันถ้าจะขยาย context window ในอนาคต)."""
    hist = get_history()
    return hist[-_MAX_TURNS_IN_PROMPT:]
