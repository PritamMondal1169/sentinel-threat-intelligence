"""Canonicalisation of URLs and indicators."""
import posixpath
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MULTI_SUFFIX = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.in", "org.in", "net.in",
                "gov.in", "ac.in", "nic.in", "res.in", "co.jp", "com.br", "co.za", "com.cn", "com.sg"}


def to_ascii_host(host: str) -> str:
    host = host.strip().strip(".").lower()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def canonical_url(raw: str) -> str:
    p = urlsplit(raw.strip())
    host = to_ascii_host(p.hostname or "")
    port = p.port
    if (p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443):
        port = None
    netloc = host + (f":{port}" if port else "")
    path = posixpath.normpath(p.path) if p.path else "/"
    if p.path.endswith("/") and not path.endswith("/"):
        path += "/"
    if not path.startswith("/"):
        path = "/" + path
    query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
    return urlunsplit((p.scheme.lower(), netloc, path, query, ""))


def split_domain(host: str) -> dict:
    host = to_ascii_host(host)
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) or ":" in host:
        return {"fqdn": host, "registrable": host, "subdomain": "", "tld": "", "is_ip": True}
    labels = host.split(".")
    n = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIX else 2
    reg = ".".join(labels[-n:]) if len(labels) >= n else host
    sub = ".".join(labels[:-n]) if len(labels) > n else ""
    return {"fqdn": host, "registrable": reg, "subdomain": sub, "tld": labels[-1], "is_ip": False}


def norm_phone(s: str, default_cc: str = "91"):
    digits = re.sub(r"\D", "", s)
    if s.strip().startswith("+") and 8 <= len(digits) <= 15:
        return "+" + digits
    if len(digits) == 10 and digits[0] in "6789":
        return f"+{default_cc}{digits}"
    if len(digits) == 12 and digits.startswith(default_cc) and digits[2] in "6789":
        return "+" + digits
    if len(digits) == 11 and digits.startswith("0") and digits[1] in "6789":
        return f"+{default_cc}{digits[1:]}"
    return None


def norm_email(s: str) -> str:
    return s.strip().lower()


def norm_upi(s: str) -> str:
    return s.strip().lower()
