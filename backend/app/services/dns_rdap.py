"""DNS queries, DNS security records (SPF, DMARC, CAA, DNSSEC), and RDAP domain age.
Uses dnspython when available with graceful stdlib fallback.
"""
import json
import logging
import re
import socket
import urllib.request
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.dnssec
    import dns.rdatatype
    DNSPYTHON = True
except ImportError:
    DNSPYTHON = False


def query_dns_records(domain: str, timeout: float = 4.0) -> dict:
    """Fetch standard DNS records: A, AAAA, NS, MX, TXT, CNAME."""
    records = {"A": [], "AAAA": [], "NS": [], "MX": [], "TXT": [], "CNAME": []}
    
    if not DNSPYTHON:
        # Standard library fallback
        try:
            infos = socket.getaddrinfo(domain, 80, proto=socket.IPPROTO_TCP)
            for item in infos:
                ip = item[4][0]
                if ":" in ip:
                    if ip not in records["AAAA"]: records["AAAA"].append(ip)
                else:
                    if ip not in records["A"]: records["A"].append(ip)
        except Exception:
            pass
        return records

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    for rtype in ("A", "AAAA", "NS", "MX", "TXT", "CNAME"):
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                records[rtype].append(str(rdata).strip('"'))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception as e:
            logger.debug(f"DNS {rtype} query for {domain} error: {e}")

    return records


def query_dns_security(domain: str, timeout: float = 4.0) -> dict:
    """Check DNS security posture: SPF, DMARC, CAA, DNSSEC."""
    result = {
        "spf": {"present": False, "record": None, "valid": False},
        "dmarc": {"present": False, "record": None, "policy": None},
        "caa": {"present": False, "records": []},
        "dnssec": {"present": False, "has_ds": False}
    }

    if not DNSPYTHON:
        return result

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    # 1. SPF record in apex TXT
    try:
        txts = resolver.resolve(domain, "TXT")
        for rdata in txts:
            txt_str = str(rdata).strip('"')
            if txt_str.startswith("v=spf1"):
                result["spf"]["present"] = True
                result["spf"]["record"] = txt_str
                # Valid if contains all/redirect mechanism
                result["spf"]["valid"] = any(m in txt_str for m in ("~all", "-all", "+all", "?all", "redirect="))
                break
    except Exception:
        pass

    # 2. DMARC record in _dmarc.{domain}
    try:
        dmarc_name = f"_dmarc.{domain}"
        dmarc_answers = resolver.resolve(dmarc_name, "TXT")
        for rdata in dmarc_answers:
            txt_str = str(rdata).strip('"')
            if txt_str.startswith("v=DMARC1"):
                result["dmarc"]["present"] = True
                result["dmarc"]["record"] = txt_str
                p_match = re.search(r"p=([a-zA-Z]+)", txt_str)
                if p_match:
                    result["dmarc"]["policy"] = p_match.group(1).lower()
                break
    except Exception:
        pass

    # 3. CAA records
    try:
        caa_answers = resolver.resolve(domain, "CAA")
        for rdata in caa_answers:
            result["caa"]["present"] = True
            result["caa"]["records"].append(str(rdata))
    except Exception:
        pass

    # 4. DNSSEC check (DS record)
    try:
        ds_answers = resolver.resolve(domain, "DS")
        if len(ds_answers) > 0:
            result["dnssec"]["present"] = True
            result["dnssec"]["has_ds"] = True
    except Exception:
        pass

    return result


def query_rdap_age(domain: str, timeout: float = 4.0) -> dict:
    """Fetch domain registration date and age via public RDAP."""
    clean_domain = domain.strip().lower().lstrip("*.")
    url = f"https://rdap.org/domain/{clean_domain}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Sentinel/1.0 (Threat Intelligence)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(500_000).decode("utf-8", "ignore"))
            events = data.get("events", [])
            reg_date_str = None
            for event in events:
                if event.get("eventAction") == "registration":
                    reg_date_str = event.get("eventDate")
                    break

            if reg_date_str:
                # e.g. "2020-04-15T12:00:00Z"
                reg_date = datetime.fromisoformat(reg_date_str.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - reg_date).days
                return {
                    "registered_at": reg_date_str,
                    "domain_age_days": max(0, age_days),
                    "is_young": age_days < 30,
                    "registrar": (data.get("entities", [{}])[0].get("vcardArray", [None, [None]])[1] if data.get("entities") else None)
                }
    except Exception as e:
        logger.debug(f"RDAP query for {domain} error/skipped: {e}")

    return {"registered_at": None, "domain_age_days": None, "is_young": False, "registrar": None}

