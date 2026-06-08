import ssl, socket  
from datetime import datetime
from urllib.parse import urlparse  

def check_ssl(url: str) -> dict:
    """ตรวจสอบ SSL Certificate ของ URL"""
    result = {
        "has_ssl": False,      # มี https ไหม
        "valid": False,        # cert ยังใช้งานได้ไหม
        "days_left": 0,       # เหลืออีกกี่วัน
        "issuer": "",          # ใครออก cert (Let's Encrypt, DigiCert ฯลฯ)
        "expires": "",         # วันหมดอายุ
        "warning": "",         # คำเตือนถ้ามี
        "error": None
    }

    # ตรวจว่าใช้ HTTPS ไหม
    if not url.startswith("https://"):
        result["warning"] = "เว็บไม่ได้ใช้ HTTPS — ข้อมูลไม่เข้ารหัส!"
        return result  

    result["has_ssl"] = True

    try:
        # แยก hostname ออกจาก URL
        # เช่น "https://school.ac.th/page" → "school.ac.th"
        hostname = urlparse(url).hostname  

        # เชื่อมต่อ SSL และดึง certificate
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()  

        # ดึงวันหมดอายุ
        expire_str = cert["notAfter"]  # เช่น "Dec 31 23:59:59 2025 GMT"
        expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expire_date - datetime.utcnow()).days

        result["expires"]   = expire_date.strftime("%d/%m/%Y")
        result["days_left"] = days_left
        result["valid"]    = days_left > 0

        # เตือนถ้าจะหมดอายุใน 30 วัน
        if 0 < days_left <= 30:
            result["warning"] = f"⚠️ SSL จะหมดอายุใน {days_left} วัน!"  

        # ดึงชื่อผู้ออก cert
        issuer_dict = dict(x[0] for x in cert["issuer"])
        result["issuer"] = issuer_dict.get("organizationName", "Unknown")

    except Exception as e:
        result["error"] = str(e)
        result["valid"] = False

    return result