# src/scanner.py — ประตูหลักของ Scanner
from scanner.headers    import check_headers   
from scanner.ssl_check  import check_ssl
from scanner.html_parser import parse_html

def run_scan(url: str) -> dict:  
    """รัน Scanner ทั้งหมด ส่งคืน dict รวม"""

    # normalize URL: เพิ่ม https:// ถ้าลืมใส่
    if not url.startswith("http"):
        url = "https://" + url  

    # รัน 3 module พร้อมกัน (ตอนนี้ทยอยรัน)
    headers_data = check_headers(url)  
    ssl_data     = check_ssl(url)      
    html_data    = parse_html(url)     

    # รวมผลทั้งหมดเป็น dict เดียว
    return {
        "url":     url,
        "headers": headers_data,
        "ssl":     ssl_data,
        "html":    html_data,
    }

# ── ทดสอบ: รันไฟล์นี้ตรง ๆ ──────────────
if __name__ == "__main__":  
    import json
    test_url = "www.technictani.ac.th"  
    print(f"🔍 กำลังสแกน: {test_url}")
    result = run_scan(test_url)
    print(json.dumps(result, indent=2, ensure_ascii=False))  