"""SSRF guard: the ONLY gate for outbound requests to user-supplied hosts."""
import ipaddress
import re
import socket
from urllib.parse import urlsplit

ALLOWED_PORTS = {80, 443, 8080, 8443}
MAX_URL_LEN = 2048


class UrlBlocked(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def ip_is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def _normalise_ip_literal(host: str) -> str:
    """Turn decimal/hex/octal IPv4 encodings (2130706433, 0x7f.1) into dotted form."""
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    if h and all(c in "0123456789abcdefxABCDEFX." for c in h):
        try:
            return socket.inet_ntoa(socket.inet_aton(h))
        except OSError:
            pass
    return h


def resolve_public(host: str, port: int = 443, resolver=socket.getaddrinfo) -> list[str]:
    """Resolve once; every returned address must be public or the target is blocked."""
    host = _normalise_ip_literal(host)
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        try:
            infos = resolver(host, port, proto=socket.IPPROTO_TCP)
        except OSError as e:
            raise UrlBlocked(f"DNS resolution failed: {e}")
        ips = sorted({i[4][0] for i in infos})
    if not ips:
        raise UrlBlocked("no addresses")
    for ip in ips:
        if not ip_is_public(ip):
            raise UrlBlocked(f"target resolves to non-public address {ip}")
    return ips


def validate_url(url: str, resolver=socket.getaddrinfo, resolve: bool = True) -> tuple[str, list[str]]:
    if not url or len(url) > MAX_URL_LEN:
        raise UrlBlocked("URL empty or too long")
    if any(ord(c) < 32 for c in url):
        raise UrlBlocked("control characters in URL")
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise UrlBlocked("only http and https are allowed")
    if parts.username or parts.password:
        raise UrlBlocked("credentials in URL are not allowed")
    host = parts.hostname
    if not host:
        raise UrlBlocked("missing host")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        raise UrlBlocked("invalid port")
    if port not in ALLOWED_PORTS:
        raise UrlBlocked(f"port {port} not allowed")
    if host.lower() == "localhost" or host.lower().endswith((".local", ".internal", ".localhost")):
        raise UrlBlocked("local hostname")
    lit = _normalise_ip_literal(host)
    try:  # IP literals are always checked, even when DNS resolution is skipped (offline mode)
        ipaddress.ip_address(lit)
        if not ip_is_public(lit):
            raise UrlBlocked(f"target is a non-public address {lit}")
    except ValueError:
        pass
    ips = resolve_public(host, port, resolver) if resolve else []
    return url.strip(), ips
