# test_ai.py — ทดสอบ AI Engine ทั้งระบบ
import sys
sys.path.insert(0, "src")  

from scanner import run_scan
from ai_engine import analyze

# ── เปลี่ยน URL ที่นี่ ──────────────────────────
TEST_URL = "https://www.ptc.ac.th"           

print(f"🔍 Step 1: กำลังสแกน {TEST_URL} ...")
scan_data = run_scan(TEST_URL)
print(f"✅ Scan เสร็จ — คะแนน: {scan_data['headers']['score']}/100")

print("\n🤖 Step 2: กำลังส่งให้ Gemini วิเคราะห์ ...")
ai_result = analyze(scan_data)

print(f"\n{'='*50}")
print(f"🎯 ระดับความเสี่ยง : {ai_result['risk_level']}")
print(f"📊 คะแนน          : {ai_result['score']}/100")
print(f"{'='*50}\n")
print("📝 ผลวิเคราะห์จาก AI:")
print(ai_result["analysis"])

if ai_result["error"]:
    print(f"\n❌ Error: {ai_result['error']}")