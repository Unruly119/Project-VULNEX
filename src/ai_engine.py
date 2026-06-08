# src/ai_engine.py — เชื่อมต่อ Gemini API
import os
from dotenv import load_dotenv              
import google.generativeai as genai        
from cachetools import TTLCache              
from prompt_builder import build_prompt      

# ── โหลด API Key จาก .env ────────────────────
load_dotenv()                                   
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# ── ตั้งค่า Model ─────────────────────────────
MODEL_NAME = "gemini-3.5-flash"               
model = genai.GenerativeModel(
    MODEL_NAME,
    generation_config={
        "temperature": 0.3,      
        "max_output_tokens": 1500, 
    }
)

# ── Cache: ไม่เรียก AI ซ้ำถ้าสแกน URL เดิม ──
# maxsize=50 เก็บได้ 50 URL, ttl=3600 หมดอายุใน 1 ชั่วโมง
_cache = TTLCache(maxsize=50, ttl=3600)      

def analyze(scan_result: dict) -> dict:   
    """
    รับ scan_result จาก scanner.py
    ส่งคืน dict ที่มี analysis และ score สรุป
    """
    url = scan_result.get("url", "")

    # ตรวจ cache ก่อน — ถ้ามีผลแล้วไม่ต้องเรียก API ใหม่
    if url in _cache:                          
        return _cache[url]

    result = {
        "analysis": "",     # คำวิเคราะห์จาก AI
        "risk_level": "",   # HIGH / MEDIUM / LOW
        "score": 0,          # คะแนน headers 0-100
        "error": None
    }

    try:
        # 1. สร้าง prompt จากข้อมูล scan
        prompt = build_prompt(scan_result)     

        # 2. ส่ง prompt ให้ Gemini
        response = model.generate_content(prompt)  
        result["analysis"] = response.text

        # 3. คำนวณ risk level จากคะแนน
        score = scan_result.get("headers", {}).get("score", 0)
        result["score"] = score
        if   score >= 70: result["risk_level"] = "LOW"     
        elif score >= 40: result["risk_level"] = "MEDIUM"  
        else:            result["risk_level"] = "HIGH"    

        # 4. บันทึก cache เพื่อไม่ต้องเรียก API ซ้ำ
        _cache[url] = result                     

    except Exception as e:
        result["error"] = str(e)
        result["analysis"] = f"❌ เรียก AI ไม่สำเร็จ: {e}"

    return result