# test_gemini.py — ทดสอบ Gemini API
import os
import sys

from dotenv import load_dotenv

sys.path.insert(0, "src")

from ai_engine import _build_fallback_models, generate_with_fallback

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    print("[FAIL] ไม่พบ GEMINI_API_KEY ใน .env")
    sys.exit(1)

models = _build_fallback_models()
print(f"Model priority: {', '.join(models)}")

try:
    text = generate_with_fallback(
        "พูดว่า 'PTC AI Web Shield พร้อมใช้งาน!' เป็นภาษาไทย ตอบสั้นๆ 1 ประโยค"
    )
    print("[OK] ตอบกลับจาก AI:")
    print(text)
except Exception as exc:
    print(f"[FAIL] ทุก model ล้มเหลว: {exc}")
    sys.exit(1)
