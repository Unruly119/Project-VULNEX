"""VULNEX RAG (Retrieval-Augmented Generation) layer.

คลังความรู้ด้านความปลอดภัย (OWASP / CVE / NIST CSF / CIS / คำอธิบายแต่ละโมดูล) ถูก
ฝังเป็นเวกเตอร์ไว้บน Qdrant Cloud เมื่อผู้ใช้ถามแชท หรือระบบสร้างบทวิเคราะห์ ตัว
retriever จะค้นชิ้นความรู้ที่เกี่ยวข้องที่สุดมาเติมใน prompt เพื่อให้ AI อ้างอิงข้อมูล
มาตรฐานจริง แทนการตอบจากความจำล้วน ๆ

ออกแบบให้ degrade อย่างนุ่มนวล: ถ้าไม่ได้ตั้งค่า Qdrant/embedding หรือเชื่อมต่อไม่ได้
`retrieve()` จะคืนลิสต์ว่าง และ pipeline เดิม (Gemini/OpenRouter/offline) ทำงานต่อได้ปกติ

โมดูลนี้ตั้งใจไม่ import ai_engine เพื่อเลี่ยง circular import
(ai_engine → prompt_builder → rag).
"""
from .retriever import format_context, get_retriever, retrieve

__all__ = ["retrieve", "format_context", "get_retriever"]
