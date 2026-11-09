"""crt.sh Certificate Transparency client (Module 2).
Discovers sibling certificates, historical certificates, and co-listed SANs.
Degrades gracefully if crt.sh is unreachable or in offline mode.
"""
import json
import logging
from typing import Optional
from urllib.error import URLError
import urllib.request

logger = logging.getLogger(__name__)


def query_crtsh(domain: str, timeout: float = 6.0) -> list[dict]:
    """Query crt.sh for certificates issued to a domain or wildcards."""
    clean_domain = domain.strip().lower().lstrip("*.")
    url = f"https://crt.sh/?q={clean_domain}&output=json"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Sentinel-CT/1.0 (Passive Threat Intelligence)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(2_000_000)
            items = json.loads(data.decode("utf-8", "ignore"))
            # Process and deduplicate certificates by min_cert_id / serial
            results = []
            seen = set()
            for item in items[:40]:  # limit to 40 recent entries
                cid = item.get("id") or item.get("serial_number")
                if cid and cid in seen:
                    continue
                seen.add(cid)
                name_value = item.get("name_value", "")
                sans = [s.strip().lower() for s in name_value.split("\n") if s.strip()]
                results.append({
                    "crtsh_id": item.get("id"),
                    "logged_at": item.get("entry_timestamp"),
                    "not_before": item.get("not_before"),
                    "not_after": item.get("not_after"),
                    "common_name": item.get("common_name"),
                    "issuer_name": item.get("issuer_name"),
                    "sans": sans
                })
            return results
    except Exception as e:
        logger.debug(f"crt.sh query for {domain} skipped: {e}")
        return []


def crtsh_summary(entries: list[dict], current_domain: str) -> dict:
    """Summarise Certificate Transparency observations."""
    if not entries:
        return {"total_observed": 0, "issuers": [], "sibling_domains": [], "first_seen": None, "last_seen": None}
    
    issuers = set()
    sibling_domains = set()
    current_clean = current_domain.lower().lstrip("*.")
    
    for e in entries:
        if e.get("issuer_name"):
            issuers.add(e["issuer_name"])
        for s in e.get("sans", []):
            s_clean = s.lstrip("*.")
            if s_clean and s_clean != current_clean:
                sibling_domains.add(s_clean)
                
    dates = [e["not_before"] for e in entries if e.get("not_before")]
    first_seen = min(dates) if dates else None
    last_seen = max(dates) if dates else None
    
    return {
        "total_observed": len(entries),
        "issuers": sorted(issuers)[:5],
        "sibling_domains": sorted(sibling_domains)[:15],
        "first_seen": first_seen,
        "last_seen": last_seen,
        "recent_certs": entries[:10]
    }

