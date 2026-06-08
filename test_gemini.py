# test_gemini.py — ทดสอบ Gemini API
import os
from dotenv import load_dotenv
import google.generativeai as genai

# โหลด API Key จากไฟล์ .env
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

# ตั้งค่า Gemini
genai.configure(api_key=api_key)
model = genai.GenerativeModel("gemini-2.0-flash")

# ส่งข้อความทดสอบ
response = model.generate_content(
    "พูดว่า 'PTC AI Web Shield พร้อมใช้งาน!' เป็นภาษาไทย"
)

print("✅ ตอบกลับจาก AI:")
print(response.text)