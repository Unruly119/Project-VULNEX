# src/scanner/dns_security.py — DNS Security Scanner (SPF, DMARC, DKIM, DNSSEC, CAA, MX)
import re
from typing import Dict, List
from urllib.parse import urlparse

try:
    import dns.resolver
    import dns.exception
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

_DKIM_SELECTORS = ("default", "google", "mail", "k1", "selector1", "selector2", "s1", "s2")
_SPF_LOOKUP_RE = re.compile(r"include:|a:|mx:|ptr:|exists:|redirect=", re.I)


def _extract_domain(url: str) -> str:
    host = urlparse(url).hostname or ""
    parts = host.split(".")
    if len(parts) > 2 and len(parts[-2]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _txt_records(domain: str) -> List[str]:
    if not _DNS_AVAILABLE:
        return []
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
    except Exception:
        return []


def _has_record(domain: str, rtype: str) -> bool:
    if not _DNS_AVAILABLE:
        return False
    try:
        dns.resolver.resolve(domain, rtype)
        return True
    except Exception:
        return False


def _count_spf_lookups(spf: str) -> int:
    return len(_SPF_LOOKUP_RE.findall(spf))


def _spf_policy(spf: str) -> str:
    for token in ("-all", "~all", "?all", "+all"):
        if token in spf:
            return token
    return "none"


def check_dns(url: str) -> Dict:
    """ตรวจ SPF, DMARC, DKIM, DNSSEC, CAA, MX — passive DNS only"""
    domain = _extract_domain(url)
    result: Dict = {
        "domain": domain,
        "spf": {"present": False, "record": "", "policy": "", "lookups": 0, "issues": []},
        "dmarc": {"present": False, "record": "", "policy": "none", "issues": []},
        "dkim": {"selectors_found": [], "present": False},
        "dnssec": {"signed": False},
        "caa": {"present": False, "records": []},
        "mx": {"records": [], "count": 0},
        "ns": {"count": 0, "diverse": False},
        "findings": [],
        "score": 0,
        "error": None,
    }

    if not _DNS_AVAILABLE:
        result["error"] = "dnspython not installed"
        return result

    if not domain:
        result["error"] = "Cannot extract domain from URL"
        return result

    score = 100

    # ── SPF ───────────────────────────────────────────────────────
    txts = _txt_records(domain)
    spf_recs = [t for t in txts if t.lower().startswith("v=spf1")]
    if spf_recs:
        spf = spf_recs[0]
        policy = _spf_policy(spf)
        lookups = _count_spf_lookups(spf)
        result["spf"] = {
            "present": True,
            "record": spf[:200],
            "policy": policy,
            "lookups": lookups,
            "issues": [],
        }
        if policy in ("~all", "?all", "none", "+all"):
            result["spf"]["issues"].append(f"SPF policy {policy} — แนะนำ -all")
            score -= 15 if policy == "~all" else 25
        if lookups > 10:
            result["spf"]["issues"].append(f"SPF DNS lookups ({lookups}) เกิน 10 ตาม RFC")
            score -= 10
    else:
        result["spf"]["issues"].append("ไม่พบ SPF record — เสี่ยง email spoofing")
        result["findings"].append({"severity": "HIGH", "title": "SPF ขาด", "detail": "ไม่มี SPF record"})
        score -= 30

    # ── DMARC ─────────────────────────────────────────────────────
    dmarc_txts = _txt_records(f"_dmarc.{domain}")
    dmarc_recs = [t for t in dmarc_txts if t.lower().startswith("v=dmarc1")]
    if dmarc_recs:
        dmarc = dmarc_recs[0]
        pol_match = re.search(r"\bp=(\w+)", dmarc, re.I)
        policy = pol_match.group(1).lower() if pol_match else "none"
        result["dmarc"] = {"present": True, "record": dmarc[:200], "policy": policy, "issues": []}
        if policy == "none":
            result["dmarc"]["issues"].append("DMARC p=none — ยังไม่บังคับใช้")
            result["findings"].append({"severity": "MEDIUM", "title": "DMARC อ่อนแอ", "detail": "policy=none"})
            score -= 15
        elif policy == "quarantine":
            score -= 5
    else:
        result["dmarc"]["issues"].append("ไม่พบ DMARC record")
        result["findings"].append({"severity": "HIGH", "title": "DMARC ขาด", "detail": "ไม่มี _dmarc TXT record"})
        score -= 25

    # ── DKIM ──────────────────────────────────────────────────────
    found_selectors = []
    for sel in _DKIM_SELECTORS:
        dkim_txts = _txt_records(f"{sel}._domainkey.{domain}")
        if dkim_txts:
            found_selectors.append(sel)
    result["dkim"]["selectors_found"] = found_selectors
    result["dkim"]["present"] = bool(found_selectors)
    if not found_selectors:
        result["findings"].append({"severity": "MEDIUM", "title": "DKIM ไม่พบ", "detail": "ไม่พบ common DKIM selectors"})
        score -= 15

    # ── DNSSEC ────────────────────────────────────────────────────
    try:
        dns.resolver.resolve(domain, "DNSKEY")
        result["dnssec"]["signed"] = True
    except Exception:
        result["dnssec"]["signed"] = False
        result["findings"].append({"severity": "LOW", "title": "DNSSEC ไม่ได้ signed", "detail": "Zone ไม่มี DNSKEY"})
        score -= 5

    # ── CAA ───────────────────────────────────────────────────────
    caa_recs = []
    try:
        answers = dns.resolver.resolve(domain, "CAA")
        for r in answers:
            caa_recs.append(str(r))
        result["caa"] = {"present": True, "records": caa_recs[:5]}
    except Exception:
        result["caa"]["present"] = False
        score -= 5

    # ── MX ────────────────────────────────────────────────────────
    try:
        mx_answers = dns.resolver.resolve(domain, "MX")
        mx_list = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in mx_answers])
        result["mx"] = {"records": [{"priority": p, "host": h} for p, h in mx_list], "count": len(mx_list)}
    except Exception:
        result["mx"]["count"] = 0

    # ── NS diversity ──────────────────────────────────────────────
    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        ns_hosts = [str(r).rstrip(".").lower() for r in ns_answers]
        result["ns"]["count"] = len(ns_hosts)
        # diverse if nameservers on different base domains
        bases = {h.split(".")[-2] + "." + h.split(".")[-1] for h in ns_hosts if len(h.split(".")) >= 2}
        result["ns"]["diverse"] = len(bases) > 1
        if len(ns_hosts) < 2:
            score -= 5
    except Exception:
        pass

    result["score"] = max(0, min(100, score))
    return result
