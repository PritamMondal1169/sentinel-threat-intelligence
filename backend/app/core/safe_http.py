"""Minimal safe fetcher: pinned IP, re-validated redirects, size/time limits, no JS, nothing kept."""
import http.client
import socket
import ssl
from urllib.parse import urljoin, urlsplit

from .ssrf import UrlBlocked, validate_url

MAX_BYTES = 1_000_000
TIMEOUT = 8
MAX_REDIRECTS = 5
UA = "SentinelScanner/0.1 (passive security research)"


class _Pinned(http.client.HTTPSConnection):
    """Connect to a pre-validated IP but keep the real hostname for SNI and verification."""

    def __init__(self, host, ip, port, **kw):
        super().__init__(ip, port, **kw)
        self._real_host = host

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(sock, server_hostname=self._real_host)


def fetch_once(url: str, method: str = "GET", resolver=socket.getaddrinfo):
    url, ips = validate_url(url, resolver)
    p = urlsplit(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    path = (p.path or "/") + (f"?{p.query}" if p.query else "")
    if p.scheme == "https":
        conn = _Pinned(p.hostname, ips[0], port, timeout=TIMEOUT)
    else:
        conn = http.client.HTTPConnection(ips[0], port, timeout=TIMEOUT)
    try:
        conn.request(method, path, headers={"Host": p.netloc, "User-Agent": UA, "Accept": "*/*"})
        r = conn.getresponse()
        body = r.read(MAX_BYTES) if method == "GET" else b""
        return r.status, {k.lower(): v for k, v in r.getheaders()}, body, ips[0]
    finally:
        conn.close()


def fetch_chain(url: str, resolver=socket.getaddrinfo):
    """Follow redirects manually. Returns (hops, final_headers, final_status). Every hop is re-validated."""
    hops, current = [], url
    for _ in range(MAX_REDIRECTS + 1):
        try:
            status, headers, _body, ip = fetch_once(current, "GET", resolver)
        except UrlBlocked as e:
            hops.append({"url": current, "blocked": e.reason})
            return hops, {}, None
        except (OSError, ssl.SSLError, http.client.HTTPException) as e:
            hops.append({"url": current, "error": str(e)[:120]})
            return hops, {}, None
        hops.append({"url": current, "status": status, "ip": ip})
        loc = headers.get("location")
        if status in (301, 302, 303, 307, 308) and loc:
            current = urljoin(current, loc)
            continue
        return hops, headers, status
    hops.append({"url": current, "error": "too many redirects"})
    return hops, {}, None
