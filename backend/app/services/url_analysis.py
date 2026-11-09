"""Module 1: deterministic URL structure analysis + Adaptive URL DNA.
Enterprise-grade heuristics for detecting credential phishing, brand impersonation,
punycode confusion, homoglyphs, and malicious redirection patterns.
"""
import re
from urllib.parse import urlsplit

from ..core.normalize import canonical_url, split_domain

BRAND_DOMAINS = {
    # Global Tech & Cloud
    "google": ["google.com", "google.co.in", "accounts.google.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "sharepoint.com", "azure.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com"],
    "meta": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "netflix": ["netflix.com"],
    "yahoo": ["yahoo.com"],
    "adobe": ["adobe.com"],
    "dropbox": ["dropbox.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "telegram": ["telegram.org", "t.me"],
    
    # Global Banking & Financial
    "paypal": ["paypal.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "citibank": ["citi.com", "citibank.com"],
    "barclays": ["barclays.co.uk", "barclays.com"],
    "hsbc": ["hsbc.com", "hsbc.co.uk"],
    "capitalone": ["capitalone.com"],
    "usbank": ["usbank.com"],
    "pnc": ["pnc.com"],
    "stripe": ["stripe.com"],
    
    # Regional Banking & Payments (India/Asia/EMEA)
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"],
    "hdfc": ["hdfcbank.com", "hdfc.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
    "kotak": ["kotak.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "gpay": ["google.com", "pay.google.com"],
    "flipkart": ["flipkart.com"],
    "irctc": ["irctc.co.in"],
    "indiapost": ["indiapost.gov.in"],

    # Crypto & Web3 Exchanges
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "trustwallet": ["trustwallet.com"],
    "kraken": ["kraken.com"],
    "bybit": ["bybit.com"],
    "ledger": ["ledger.com"],
    "trezor": ["trezor.io"],
    
    # Shipping & Parcel Logistics
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"]
}

BRANDS = list(BRAND_DOMAINS.keys())

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "icu", "click", "link", "gq", "tk", "ml", "cf", "ga",
    "buzz", "rest", "cfd", "online", "site", "live", "club", "space", "monster", "fun",
    "website", "work", "loan", "win", "fit", "surf", "cam", "bid", "pw", "cc"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"
}

LURE_WORDS = {
    "login", "signin", "verify", "verification", "secure", "security", "update", "kyc",
    "account", "banking", "wallet", "suspend", "suspended", "reward", "rewards", "claim",
    "otp", "confirm", "confirmation", "auth", "portal", "recovery", "recover", "unlock",
    "alert", "validate", "validation", "passcode", "billing", "invoice", "refund"
}

CONFUSABLES = {
    "0": "o", "1": "l", "5": "s", "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0456": "i", "\u0131": "i", "\u0261": "g"
}


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


def is_official_brand_domain(brand: str, domain: str) -> bool:
    official = BRAND_DOMAINS.get(brand, [])
    if isinstance(official, str):
        official = [official]
    return any(domain.lower() == d.lower() or domain.lower().endswith("." + d.lower()) for d in official)


def analyse(url: str) -> dict:
    canon = canonical_url(url)
    p = urlsplit(canon)
    d = split_domain(p.hostname or "")
    flags, score = [], 0

    def add(code, points, detail):
        nonlocal score
        flags.append({"code": code, "points": points, "detail": detail})
        score += points

    host = d["fqdn"].lower()
    reg_label = d["registrable"].split(".")[0].lower() if d.get("registrable") else ""

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
        add("deep_subdomains", 15, f"{depth} subdomain levels (often used to obscure origin)")
    if d["tld"] in SUSPICIOUS_TLDS:
        add("suspicious_tld", 12, f".{d['tld']} is frequently abused for phishing campaigns")
    if d["registrable"] in SHORTENERS:
        add("shortener", 8, "URL shortener hides the final destination")
    if host.count("-") >= 3:
        add("many_hyphens", 10, f"Many hyphens in host ({host.count('-')}) indicate domain masquerading")
    if len(host) > 40:
        add("long_host", 8, "Unusually long hostname commonly seen in phishing infrastructure")

    lures = sorted(w for w in LURE_WORDS if w in host or w in p.path.lower())
    if lures:
        add("lure_keywords", min(6 * len(lures), 20), "Phishing lure keywords: " + ", ".join(lures))

    # brand impersonation: brand label present but registrable domain is not the official one
    brand_hit = None
    sk = skeleton(host)
    sk_reg = skeleton(reg_label)

    for b in BRANDS:
        if is_official_brand_domain(b, d["registrable"]):
            continue

        # Check if brand appears in hostname or skeleton with proper boundary or sub-match
        in_host = False
        if len(b) <= 3:
            # Short acronyms (e.g. sbi, dhl, ups) require word or delimiter boundary
            in_host = bool(re.search(r"(^|[._\-])" + re.escape(b) + r"([._\-]|$)", host)) or bool(re.search(r"(^|[._\-])" + re.escape(b) + r"([._\-]|$)", sk))
        else:
            in_host = b in host or b in sk

        near = (edit_distance(sk_reg, b) <= 1 and reg_label != b and len(b) >= 4)
        if in_host or near:
            brand_hit = b
            kind = "typosquat/homoglyph of" if near and not in_host else "keyword impersonation of"
            add("brand_impersonation", 35, f"{kind} '{b}' on an unauthorized domain ({d['registrable']})")
            break

    # Phishing synergy boost: brand impersonation + lure keywords or suspicious TLD
    if brand_hit and lures:
        add("credential_harvesting_pattern", 15, "Co-occurrence of brand impersonation and credential harvest lures")

    return {
        "canonical_url": canon,
        "domain": d,
        "flags": flags,
        "score": min(score, 100),
        "brand": brand_hit,
        "dna": url_dna(canon, d)
    }


def _shape(s: str) -> str:
    s = re.sub(r"[0-9a-f]{16,}", "H", s)
    return re.sub(r"\d+", "D", s)


def url_dna(canon: str, d: dict) -> dict:
    p = urlsplit(canon)
    host = d["fqdn"]
    tokens = {
        f"tld:{d['tld']}",
        f"depth:{min(len(d['subdomain'].split('.')) if d['subdomain'] else 0, 4)}",
        f"path:{_shape(p.path)}"
    }
    tokens |= {f"q:{k}" for k in re.findall(r"([^=&]+)=", p.query)}
    tokens |= {f"w:{w}" for w in LURE_WORDS if w in host or w in p.path.lower()}
    tokens |= {f"b:{b}" for b in BRANDS if b in host}
    return {
        "tokens": sorted(tokens),
        "len": len(host),
        "digit_ratio": round(sum(c.isdigit() for c in host) / max(len(host), 1), 3),
        "hyphens": host.count("-")
    }


def dna_similarity(a: dict, b: dict) -> float:
    ta, tb = set(a["tokens"]), set(b["tokens"])
    jac = len(ta & tb) / len(ta | tb) if ta | tb else 0.0
    num = 1 - min(abs(a["len"] - b["len"]) / 40, 1) * 0.5 - abs(a["digit_ratio"] - b["digit_ratio"]) * 0.5
    return round(0.8 * jac + 0.2 * max(num, 0), 3)
