"""Module 2: TLS certificate inspection. Network access goes through the SSRF guard first."""
import hashlib
import socket
import ssl
from datetime import datetime, timezone

from ..core.ssrf import resolve_public

try:  # optional: richer parsing (SPKI hash, SAN, self-signed)
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
except ImportError:  # pragma: no cover
    x509 = None


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count(".") and host.endswith(n[1:]):
            return True
    return False


def inspect(host: str, port: int = 443, timeout: float = 6.0, resolver=socket.getaddrinfo) -> dict:
    ips = resolve_public(host, port, resolver)
    res = {"host": host, "ip": ips[0], "checked_at": datetime.now(timezone.utc).isoformat(), "findings": []}
    # 1) verified handshake to learn *why* verification fails
    try:
        with socket.create_connection((ips[0], port), timeout) as s:
            with ssl.create_default_context().wrap_socket(s, server_hostname=host) as t:
                res["verified"], res["protocol"], res["cipher"] = True, t.version(), t.cipher()[0]
    except ssl.SSLCertVerificationError as e:
        res["verified"], res["verify_error"] = False, e.verify_message
    except (OSError, ssl.SSLError) as e:
        return {**res, "error": str(e)[:150], "verified": False}
    # 2) unverified handshake just to read the certificate
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with socket.create_connection((ips[0], port), timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                der = t.getpeercert(binary_form=True)
                res.setdefault("protocol", t.version())
    except (OSError, ssl.SSLError) as e:
        return {**res, "error": str(e)[:150]}
    res["cert_sha256"] = hashlib.sha256(der).hexdigest()
    if x509:
        c = x509.load_der_x509_certificate(der)
        try:
            san = list(c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            san = []
        spki = c.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        nb, na = c.not_valid_before_utc, c.not_valid_after_utc
        now = datetime.now(timezone.utc)
        res.update({"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(), "san": san,
                    "spki_sha256": hashlib.sha256(spki).hexdigest(), "not_before": nb.isoformat(), "not_after": na.isoformat(),
                    "serial": hex(c.serial_number), "self_signed": c.subject == c.issuer,
                    "hostname_match": hostname_matches(host, san), "days_remaining": (na - now).days})
        F = res["findings"]
        if now > na: F.append({"code": "cert_expired", "severity": "high", "category": "misconfiguration"})
        elif (na - now).days < 14: F.append({"code": "cert_expiring_soon", "severity": "low", "category": "misconfiguration"})
        if now < nb: F.append({"code": "cert_not_yet_valid", "severity": "high", "category": "misconfiguration"})
        if not res["hostname_match"]: F.append({"code": "hostname_mismatch", "severity": "high", "category": "suspicious_indicator"})
        if res["self_signed"]: F.append({"code": "self_signed", "severity": "medium", "category": "suspicious_indicator"})
        if not res.get("verified") and not res["self_signed"]:
            F.append({"code": "chain_invalid", "severity": "medium", "category": "suspicious_indicator", "detail": res.get("verify_error", "")})
    return res
