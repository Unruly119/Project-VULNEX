# src/scanner/ssl_check.py — SSL/TLS Certificate & Protocol Analysis
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from utils.network import is_safe_host

# Weak cipher patterns
_WEAK_CIPHERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "anon")


def check_ssl(url: str) -> dict:
    """ตรวจสอบ SSL Certificate + TLS version + cipher suite"""
    result = {
        "has_ssl":      False,
        "valid":        False,
        "days_left":    0,
        "issuer":       "",
        "expires":      "",
        "warning":      "",
        "tls_version":  "",
        "cipher_suite": "",
        "cipher_bits":  0,
        "tls_warnings": [],
        "error":        None,
        "error_type":   None,   # "expired" | "connection" | "other"
    }

    if not url.startswith("https://"):
        result["warning"] = "เว็บไม่ได้ใช้ HTTPS — ข้อมูลไม่เข้ารหัส!"
        return result

    result["has_ssl"] = True
    hostname = urlparse(url).hostname

    # SECURITY: re-validate the (resolved) host before opening a raw TLS socket —
    # is_safe_host() blocks loopback/private/link-local and DNS-based SSRF.
    if not is_safe_host(hostname or ""):
        result["error"] = "SSRF blocked: non-public host"
        result["error_type"] = "blocked"
        return result

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # TLS version
                tls_ver = ssock.version()  # e.g. "TLSv1.3"
                result["tls_version"] = tls_ver or ""
                if tls_ver and tls_ver in ("TLSv1", "TLSv1.0", "TLSv1.1"):
                    result["tls_warnings"].append(
                        f"⚠️ TLS version {tls_ver} is deprecated — upgrade to TLS 1.2+"
                    )

                # Cipher suite
                cipher_info = ssock.cipher()  # (name, version, bits)
                if cipher_info:
                    result["cipher_suite"] = cipher_info[0]
                    result["cipher_bits"]  = cipher_info[2]
                    cipher_name = cipher_info[0].upper()
                    for weak in _WEAK_CIPHERS:
                        if weak in cipher_name:
                            result["tls_warnings"].append(
                                f"⚠️ Weak cipher detected: {cipher_info[0]}"
                            )
                            break

        # Certificate expiry
        expire_str  = cert["notAfter"]
        expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
        expire_date = expire_date.replace(tzinfo=timezone.utc)
        days_left   = (expire_date - datetime.now(timezone.utc)).days

        result["expires"]   = expire_date.strftime("%d/%m/%Y")
        result["days_left"] = days_left
        result["valid"]     = days_left > 0

        if days_left <= 0:
            result["warning"]    = "❌ SSL Certificate หมดอายุแล้ว!"
            result["error_type"] = "expired"
        elif days_left <= 30:
            result["warning"] = f"⚠️ SSL จะหมดอายุใน {days_left} วัน!"

        # Issuer
        issuer_dict = dict(x[0] for x in cert["issuer"])
        result["issuer"] = issuer_dict.get("organizationName", "Unknown")

    except ssl.SSLCertVerificationError as e:
        result["error"]      = str(e)
        result["error_type"] = "expired" if "CERTIFICATE_VERIFY_FAILED" in str(e) else "ssl_error"
        result["valid"]      = False
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"]      = str(e)
        result["error_type"] = "connection"
        result["valid"]      = False
    except Exception as e:
        result["error"]      = str(e)
        result["error_type"] = "other"
        result["valid"]      = False

    return result