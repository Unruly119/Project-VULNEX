# src/scanner/dns_security.py — DNS Security Scanner (SPF, DMARC, DKIM, DNSSEC, CAA, MX)
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional
from urllib.parse import urlparse

try:
    import dns.resolver
    import dns.exception
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

_DKIM_SELECTORS = ("default", "google", "mail", "k1", "selector1", "selector2", "s1", "s2")
_SPF_LOOKUP_RE = re.compile(r"include:|a:|mx:|ptr:|exists:|redirect=", re.I)

# RELIABILITY: bound every DNS query so a slow/unreachable resolver can't stall the
# whole scan. A missing record (NXDOMAIN) still returns fast; these caps only bite when
# a nameserver goes silent. lifetime = total wall-clock budget per resolve() call.
_DNS_TIMEOUT = 2.0     # per-nameserver
_DNS_LIFETIME = 6.0    # total per resolve() across all nameservers

# Some hosts' default/primary nameserver is slow or silent, costing ~timeout seconds on
# EVERY query (observed: ~3 s/query → a 21 s DNS scan). Query fast public resolvers
# first and keep the system nameservers as fallback, in case outbound 53 to public
# resolvers is filtered on the deploy host.
_PUBLIC_NS = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
_RESOLVER = None


def _resolver() -> "dns.resolver.Resolver":
    """Shared, lazily-built resolver (built once, reused for every query). Concurrent
    resolve() calls (parallel DKIM) are read-only on its config, so sharing is safe."""
    global _RESOLVER
    if _RESOLVER is None:
        try:
            r = dns.resolver.Resolver()
            system_ns = list(r.nameservers or [])
        except Exception:
            r = dns.resolver.Resolver(configure=False)
            system_ns = []
        seen, merged = set(), []
        for ns in _PUBLIC_NS + system_ns:
            if ns not in seen:
                seen.add(ns)
                merged.append(ns)
        r.nameservers = merged or list(_PUBLIC_NS)
        r.timeout = _DNS_TIMEOUT
        r.lifetime = _DNS_LIFETIME
        _RESOLVER = r
    return _RESOLVER


def _extract_domain(url: str) -> str:
    host = urlparse(url).hostname or ""
    parts = host.split(".")
    if len(parts) > 2 and len(parts[-2]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _txt_records(domain: str, resolver: Optional["dns.resolver.Resolver"] = None) -> List[str]:
    if not _DNS_AVAILABLE:
        return []
    try:
        answers = (resolver or _resolver()).resolve(domain, "TXT")
        return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
    except Exception:
        return []


def _has_record(domain: str, rtype: str) -> bool:
    if not _DNS_AVAILABLE:
        return False
    try:
        _resolver().resolve(domain, rtype)
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

    # ── DKIM (parallel: 8 selector lookups at once — was ~8× sequential DNS waits) ──
    shared = _resolver()
    def _dkim_probe(sel: str):
        return sel if _txt_records(f"{sel}._domainkey.{domain}", shared) else None
    with ThreadPoolExecutor(max_workers=len(_DKIM_SELECTORS)) as _dkim_pool:
        found_selectors = [s for s in _dkim_pool.map(_dkim_probe, _DKIM_SELECTORS) if s]
    result["dkim"]["selectors_found"] = found_selectors
    result["dkim"]["present"] = bool(found_selectors)
    if not found_selectors:
        result["findings"].append({"severity": "MEDIUM", "title": "DKIM ไม่พบ", "detail": "ไม่พบ common DKIM selectors"})
        score -= 15

    # Remaining record types reuse the same shared short-timeout resolver
    resolver = _resolver()

    # ── DNSSEC ────────────────────────────────────────────────────
    try:
        resolver.resolve(domain, "DNSKEY")
        result["dnssec"]["signed"] = True
    except Exception:
        result["dnssec"]["signed"] = False
        result["findings"].append({"severity": "LOW", "title": "DNSSEC ไม่ได้ signed", "detail": "Zone ไม่มี DNSKEY"})
        score -= 5

    # ── CAA ───────────────────────────────────────────────────────
    caa_recs = []
    try:
        answers = resolver.resolve(domain, "CAA")
        for r in answers:
            caa_recs.append(str(r))
        result["caa"] = {"present": True, "records": caa_recs[:5]}
    except Exception:
        result["caa"]["present"] = False
        score -= 5

    # ── MX ────────────────────────────────────────────────────────
    try:
        mx_answers = resolver.resolve(domain, "MX")
        mx_list = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in mx_answers])
        result["mx"] = {"records": [{"priority": p, "host": h} for p, h in mx_list], "count": len(mx_list)}
    except Exception:
        result["mx"]["count"] = 0

    # ── NS diversity ──────────────────────────────────────────────
    try:
        ns_answers = resolver.resolve(domain, "NS")
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
