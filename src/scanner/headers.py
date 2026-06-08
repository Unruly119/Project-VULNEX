# ── src/scanner/headers.py ──────────────────────
# หน้าที่: ดึง HTTP Security Headers จากเว็บไซต์

import httpx  
from typing import Dict, Optional  

# Security Headers ที่เราจะตรวจสอบ
# เก็บเป็น list เพื่อให้เพิ่มได้ง่ายในอนาคต
SECURITY_HEADERS = [  
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

def check_headers(url: str) -> Dict:  
    """
    ดึง Security Headers จาก URL ที่ระบุ
    Return: dict ที่บอกว่า header แต่ละตัวมีหรือไม่
    """
    result = {  
        "url": url,
        "headers_found": {},   # headers ที่เจอ
        "headers_missing": [], # headers ที่หายไป
        "score": 0,            # คะแนน 0-100
        "error": None,         # error message ถ้ามี
    }

    try:  
        # ส่ง HTTP request ไปยัง URL
        # timeout=10 รอไม่เกิน 10 วินาที
        # follow_redirects เพื่อตามไป https อัตโนมัติ
        with httpx.Client(
            timeout=10,
            follow_redirects=True,
            verify=False  # ยอมรับ SSL cert ที่หมดอายุด้วย
        ) as client:
            response = client.head(url)  

        # ตรวจสอบทีละ header
        for header in SECURITY_HEADERS:  
            if header.lower() in response.headers:  
                result["headers_found"][header] = response.headers[header.lower()]
            else:
                result["headers_missing"].append(header)  

        # คำนวณคะแนน: กี่ % ของ headers ที่มี
        found = len(result["headers_found"])
        total = len(SECURITY_HEADERS)
        result["score"] = round(found / total * 100)  

    except Exception as e:  
        result["error"] = str(e)

    return result  