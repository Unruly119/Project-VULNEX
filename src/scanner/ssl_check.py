# src/scanner/ssl_check.py — SSL/TLS Certificate & Protocol Analysis
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509

from utils.network import is_safe_host

# Weak cipher patterns
_WEAK_CIPHERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "anon")


def _tls_connect(hostname: str, verify: bool):
    """Open a TLS socket and return (tls_version, cipher_tuple, der_cert_bytes).

    When ``verify`` is False the handshake completes even for expired / self-signed /
    hostname-mismatch certs — so we can still READ the certificate and TLS parameters.
    getpeercert(binary_form=True) returns the DER cert regardless of verify mode
    (the dict form is empty under CERT_NONE), which cryptography can then parse."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, 443), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            return ssock.version(), ssock.cipher(), ssock.getpeercert(True)


def _cert_expiry_issuer(der: bytes):
    """Parse notAfter (tz-aware UTC) + issuer org from a DER cert. Returns (None, '')
    on parse failure."""
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None, ""
    try:
        expire = cert.not_valid_after_utc          # cryptography ≥ 42
    except AttributeError:                          # older fallback
        expire = cert.not_valid_after.replace(tzinfo=timezone.utc)
    issuer = ""
    try:
        org = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        if org:
            issuer = org[0].value
        else:
            cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            issuer = cn[0].value if cn else ""
    except Exception:
        issuer = ""
    return expire, issuer


def check_ssl(url: str) -> dict:
    """ตรวจสอบ SSL Certificate + TLS version + cipher suite

    RELIABILITY: connects verified first (fast path for trusted certs); if the cert is
    untrusted (expired / self-signed / hostname mismatch) it reconnects WITHOUT
    verification so the report can still show issuer, expiry and TLS details instead of
    a bare error — the common case for Thai school sites with lapsed certificates."""
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
        "error_type":   None,   # "expired" | "ssl_error" | "connection" | "blocked" | "other"
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

    tls_ver = cipher = der = None
    trusted = False

    # 1) Verified handshake — fast path for well-configured sites.
    try:
        tls_ver, cipher, der = _tls_connect(hostname, verify=True)
        trusted = True
    except ssl.SSLCertVerificationError as e:
        # Cert is present but not trusted (expired / self-signed / hostname mismatch).
        msg = str(e)
        result["error"] = msg
        result["error_type"] = "expired" if ("expired" in msg.lower()
                                              or "CERTIFICATE_VERIFY_FAILED" in msg) else "ssl_error"
        # 2) Re-connect unverified to still extract cert + TLS details.
        try:
            tls_ver, cipher, der = _tls_connect(hostname, verify=False)
        except Exception:
            pass
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = str(e)
        result["error_type"] = "connection"
        return result
    except Exception as e:
        result["error"] = str(e)
        result["error_type"] = "other"
        return result

    # ── TLS version ──
    if tls_ver:
        result["tls_version"] = tls_ver
        if tls_ver in ("TLSv1", "TLSv1.0", "TLSv1.1"):
            result["tls_warnings"].append(
                f"⚠️ TLS version {tls_ver} is deprecated — upgrade to TLS 1.2+"
            )

    # ── Cipher suite ──
    if cipher:
        result["cipher_suite"] = cipher[0]
        result["cipher_bits"]  = cipher[2]
        cipher_upper = str(cipher[0]).upper()
        for weak in _WEAK_CIPHERS:
            if weak in cipher_upper:
                result["tls_warnings"].append(f"⚠️ Weak cipher detected: {cipher[0]}")
                break

    # ── Certificate expiry + issuer ──
    expire_date, issuer = (_cert_expiry_issuer(der) if der else (None, ""))
    if expire_date:
        days_left = (expire_date - datetime.now(timezone.utc)).days
        result["expires"]   = expire_date.strftime("%d/%m/%Y")
        result["days_left"] = days_left
        result["issuer"]    = issuer or "Unknown"
        result["valid"]     = trusted and days_left > 0

        if days_left <= 0:
            result["warning"]    = "❌ SSL Certificate หมดอายุแล้ว!"
            result["error_type"] = result["error_type"] or "expired"
        elif not trusted:
            result["warning"] = ("⚠️ ใบรับรองไม่ผ่านการตรวจสอบ "
                                 "(self-signed / ไม่น่าเชื่อถือ / ชื่อโดเมนไม่ตรง)")
        elif days_left <= 30:
            result["warning"] = f"⚠️ SSL จะหมดอายุใน {days_left} วัน!"
    else:
        # Couldn't read the cert at all — reflect trust state without inventing data.
        result["valid"] = trusted

    return result


if __name__ == "__main__":
    import sys, json
    target = sys.argv[1] if len(sys.argv) > 1 else "https://www.google.com"
    print(json.dumps(check_ssl(target), ensure_ascii=False, indent=2))
