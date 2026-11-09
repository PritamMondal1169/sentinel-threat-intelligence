"""Module 1: deterministic URL structure analysis + Adaptive URL DNA."""
import re
from urllib.parse import urlsplit

from ..core.normalize import canonical_url, split_domain

BRANDS = ["sbi", "hdfc", "icici", "axis", "kotak", "paytm", "phonepe", "gpay", "google", "amazon", "flipkart",
          "microsoft", "paypal", "apple", "netflix", "irctc", "indiapost", "whatsapp", "facebook", "instagram"]
BRAND_DOMAINS = {"sbi": "sbi.co.in", "hdfc": "hdfcbank.com", "icici": "icicibank.com", "axis": "axisbank.com",
                 "paytm": "paytm.com", "phonepe": "phonepe.com", "google": "google.com", "amazon": "amazon.in",
                 "flipkart": "flipkart.com", "microsoft": "microsoft.com", "paypal": "paypal.com",
                 "apple": "apple.com", "netflix": "netflix.com", "irctc": "irctc.co.in"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "icu", "click", "link", "gq", "tk", "ml", "cf", "ga", "buzz", "rest", "cfd"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}
LURE_WORDS = {"login", "verify", "secure", "update", "kyc", "account", "suspend", "wallet", "reward", "gift", "claim", "otp"}
CONFUSABLES = {"0": "o", "1": "l", "5": "s", "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
               "\u0441": "c", "\u0445": "x", "\u0456": "i", "\u0131": "i", "\u0261": "g"}


def skeleton(host: str) -> str:
    s = host.lower()
    s = "".join(CONFUSABLES.get(c, c) for c in s)
    return s.replace("rn", "m").replace("vv", "w")


def edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def analyse(url: str) -> dict:
    canon = canonical_url(url)
    p = urlsplit(canon)
    d = split_domain(p.hostname or "")
    flags, score = [], 0

    def add(code, points, detail):
        nonlocal score
        flags.append({"code": code, "points": points, "detail": detail})
        score += points

    host = d["fqdn"]
    reg_label = d["registrable"].split(".")[0]
    if d["is_ip"]:
        add("ip_host", 30, "URL uses an IP address instead of a domain")
    if "xn--" in host:
        add("punycode", 20, "Host contains punycode (internationalised) labels")
        try:
            decoded = host.encode("ascii").decode("idna")
            if re.search(r"[^\x00-\x7f]", decoded) and re.search(r"[a-z]", decoded):
                add("mixed_script", 15, "Host mixes ASCII and non-ASCII characters")
        except UnicodeError:
            pass
    if "@" in (urlsplit(url.strip()).netloc):
        add("userinfo_trick", 25, "URL contains '@' in the authority part")
    depth = len(d["subdomain"].split(".")) if d["subdomain"] else 0
    if depth >= 3:
        add("deep_subdomains", 12, f"{depth} subdomain levels")
    if d["tld"] in SUSPICIOUS_TLDS:
        add("suspicious_tld", 10, f".{d['tld']} is frequently abused")
    if d["registrable"] in SHORTENERS:
        add("shortener", 8, "URL shortener hides the final destination")
    if host.count("-") >= 3:
        add("many_hyphens", 8, "Many hyphens in host")
    if len(host) > 40:
        add("long_host", 6, "Unusually long hostname")
    lures = sorted(w for w in LURE_WORDS if w in host or w in p.path.lower())
    if lures:
        add("lure_keywords", min(5 * len(lures), 15), "Lure words: " + ", ".join(lures))

    # brand impersonation: brand label present but registrable domain is not the real one
    brand_hit = None
    sk = skeleton(host)
    for b in BRANDS:
        real = BRAND_DOMAINS.get(b)
        if real and d["registrable"] == real:
            continue
        in_host = b in host or b in sk
        near = any(edit_distance(skeleton(reg_label), b) <= 1 for _ in [0]) and reg_label != b
        if in_host or near:
            brand_hit = b
            kind = "typosquat/homoglyph of" if near and not b in host else "keyword impersonation of"
            add("brand_impersonation", 30, f"{kind} '{b}' on a domain that is not {real or 'the official site'}")
            break
    return {"canonical_url": canon, "domain": d, "flags": flags, "score": min(score, 100), "brand": brand_hit,
            "dna": url_dna(canon, d)}


def _shape(s: str) -> str:
    s = re.sub(r"[0-9a-f]{16,}", "H", s)
    return re.sub(r"\d+", "D", s)


def url_dna(canon: str, d: dict) -> dict:
    p = urlsplit(canon)
    host = d["fqdn"]
    tokens = {f"tld:{d['tld']}", f"depth:{min(len(d['subdomain'].split('.')) if d['subdomain'] else 0, 4)}",
              f"path:{_shape(p.path)}"}
    tokens |= {f"q:{k}" for k in re.findall(r"([^=&]+)=", p.query)}
    tokens |= {f"w:{w}" for w in LURE_WORDS if w in host or w in p.path.lower()}
    tokens |= {f"b:{b}" for b in BRANDS if b in host}
    return {"tokens": sorted(tokens), "len": len(host), "digit_ratio": round(sum(c.isdigit() for c in host) / max(len(host), 1), 3),
            "hyphens": host.count("-")}


def dna_similarity(a: dict, b: dict) -> float:
    ta, tb = set(a["tokens"]), set(b["tokens"])
    jac = len(ta & tb) / len(ta | tb) if ta | tb else 0.0
    num = 1 - min(abs(a["len"] - b["len"]) / 40, 1) * 0.5 - abs(a["digit_ratio"] - b["digit_ratio"]) * 0.5
    return round(0.8 * jac + 0.2 * max(num, 0), 3)
