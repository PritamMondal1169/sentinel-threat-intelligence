"""Module 5: passive header/TLS/DNS posture analysis.
Calculates grade, posture diffs, and risk-based remediation.
"""
import re

SEV_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3}


def analyse_headers(headers: dict, https: bool, redirects_to_https: bool | None = None) -> list[dict]:
    h = {k.lower(): v for k, v in headers.items()}
    out = []

    def f(code, sev, title, fix, evidence="", exposure=1.0, effort=1.0):
        out.append({
            "code": code,
            "category": "misconfiguration",
            "severity": sev,
            "title": title,
            "remediation": fix,
            "evidence": evidence,
            "priority": round(SEV_ORDER[sev] * exposure / effort, 2)
        })

    if not https:
        f("no_https", "high", "Site not reachable over HTTPS", "Install a TLS certificate and serve the site over HTTPS.", exposure=1.5)
    elif redirects_to_https is False:
        f("no_http_redirect", "medium", "HTTP does not redirect to HTTPS", "Add a 301 redirect from http:// to https://.")

    hsts = h.get("strict-transport-security")
    if https and not hsts:
        f("no_hsts", "medium", "HSTS header missing", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", exposure=1.2)
    elif hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if not m or int(m.group(1)) < 15552000:
            f("weak_hsts", "low", "HSTS max-age is short", "Use max-age of at least 15552000 (6 months).", hsts)

    csp = h.get("content-security-policy")
    if not csp:
        f("no_csp", "medium", "Content-Security-Policy missing", "Define a CSP, starting with: default-src 'self'", exposure=1.2, effort=2.0)
    elif "unsafe-inline" in csp or "unsafe-eval" in csp or re.search(r"(^|\s)\*(\s|;|$)", csp):
        f("weak_csp", "low", "CSP allows unsafe sources", "Remove 'unsafe-inline'/'unsafe-eval' and wildcard sources.", csp, effort=2.0)

    if "x-frame-options" not in h and not (csp and "frame-ancestors" in csp):
        f("no_clickjacking_protection", "medium", "No clickjacking protection", "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.")

    if h.get("x-content-type-options", "").lower() != "nosniff":
        f("no_xcto", "low", "X-Content-Type-Options missing", "Add: X-Content-Type-Options: nosniff")

    if "referrer-policy" not in h:
        f("no_referrer_policy", "informational", "Referrer-Policy missing", "Add: Referrer-Policy: strict-origin-when-cross-origin")

    if re.search(r"/\d", h.get("server", "")) or "x-powered-by" in h:
        f("version_disclosure", "informational", "Server software/version disclosed", "Hide Server and X-Powered-By version details.",
          h.get("server", "") or h.get("x-powered-by", ""))

    sc = h.get("set-cookie", "")
    if sc and https and not re.search(r"(?i);\s*secure", sc):
        f("cookie_not_secure", "medium", "Cookie without Secure flag", "Add Secure, HttpOnly and SameSite attributes to cookies.")

    return sorted(out, key=lambda x: -x["priority"])


def analyse_dns_security(dns_sec: dict) -> list[dict]:
    """Evaluate DNS records for email/domain spoofing protection."""
    findings = []
    
    # SPF
    spf = dns_sec.get("spf", {})
    if not spf.get("present"):
        findings.append({
            "code": "no_spf",
            "category": "misconfiguration",
            "severity": "medium",
            "title": "SPF Record Missing",
            "remediation": "Publish an SPF TXT record (e.g., 'v=spf1 -all' or include your mail services) to prevent sender spoofing.",
            "evidence": "",
            "priority": 1.5
        })
    elif not spf.get("valid"):
        findings.append({
            "code": "weak_spf",
            "category": "misconfiguration",
            "severity": "low",
            "title": "Weak SPF Record",
            "remediation": "Ensure SPF record ends with a strict qualifier like '~all' or '-all'.",
            "evidence": spf.get("record", ""),
            "priority": 1.0
        })

    # DMARC
    dmarc = dns_sec.get("dmarc", {})
    if not dmarc.get("present"):
        findings.append({
            "code": "no_dmarc",
            "category": "misconfiguration",
            "severity": "medium",
            "title": "DMARC Record Missing",
            "remediation": "Publish a DMARC TXT record at _dmarc.<domain> with at least 'v=DMARC1; p=quarantine'.",
            "evidence": "",
            "priority": 1.6
        })
    elif dmarc.get("policy") == "none":
        findings.append({
            "code": "dmarc_p_none",
            "category": "misconfiguration",
            "severity": "low",
            "title": "DMARC Policy Set to None",
            "remediation": "Upgrade DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject' once mail streams are verified.",
            "evidence": dmarc.get("record", ""),
            "priority": 1.0
        })

    # CAA
    caa = dns_sec.get("caa", {})
    if not caa.get("present"):
        findings.append({
            "code": "no_caa",
            "category": "misconfiguration",
            "severity": "low",
            "title": "CAA Record Missing",
            "remediation": "Add CAA DNS records specifying which Certificate Authorities are authorized to issue certificates for your domain.",
            "evidence": "",
            "priority": 0.8
        })

    # DNSSEC
    dnssec = dns_sec.get("dnssec", {})
    if not dnssec.get("has_ds"):
        findings.append({
            "code": "no_dnssec",
            "category": "misconfiguration",
            "severity": "informational",
            "title": "DNSSEC Not Configured",
            "remediation": "Enable DNSSEC at your domain registrar to cryptographically protect DNS responses against spoofing.",
            "evidence": "",
            "priority": 0.5
        })

    return findings


def grade(findings: list[dict]) -> str:
    pts = sum({"informational": 0, "low": 3, "medium": 8, "high": 20}.get(f["severity"], 0) for f in findings)
    return "A" if pts <= 3 else "B" if pts <= 11 else "C" if pts <= 22 else "D" if pts <= 35 else "F"


def posture_diff(prev: list[dict] | None, cur: list[dict]) -> dict:
    p, c = {f["code"] for f in (prev or [])}, {f["code"] for f in cur}
    return {"new_findings": sorted(c - p), "resolved": sorted(p - c)}
