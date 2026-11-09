"""Threat-feed adapters for Module 1.
Implements Google Safe Browsing, OpenPhish, URLhaus, PhishTank, VirusTotal, and Local Blocklist.
Each adapter returns a normalised verdict; failures degrade to 'unavailable', never raising exceptions.
"""
import base64
import json
import os
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DATA = Path(__file__).resolve().parents[2] / "data"


def verdict(source: str, status: str, reliability: float, detail: str = "", raw_ref: Optional[str] = None):
    """Normalised verdict object per PRD: status is 'listed' | 'clean' | 'unavailable'."""
    return {
        "source": source,
        "status": status,
        "reliability": reliability,
        "detail": detail,
        "raw_ref": raw_ref,
        "queried_at": datetime.now(timezone.utc).isoformat()
    }


class LocalBlocklist:
    """Offline fallback: data/blocklist.txt. Also used for the demo."""
    name = "local-blocklist"

    def __init__(self, path: Path = DATA / "blocklist.txt"):
        self.entries = set()
        if path.exists():
            self.entries = {
                line.strip().lower()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            }

    def check(self, url: str, fqdn: str) -> dict:
        hit = fqdn.lower() in self.entries or url.lower() in self.entries
        return verdict(self.name, "listed" if hit else "clean", 0.90, "local demo/offline list")


class OpenPhishFeed:
    """OpenPhish community feed (plain-text URL list). Cached in memory for 1 hour."""
    name = "openphish"
    URL = "https://openphish.com/feed.txt"

    def __init__(self):
        self.cache: set[str] = set()
        self.at = 0.0

    def check(self, url: str, fqdn: str) -> dict:
        try:
            if time.time() - self.at > 3600:
                req = urllib.request.Request(self.URL, headers={"User-Agent": "Sentinel/0.2"})
                with urllib.request.urlopen(req, timeout=6) as r:
                    content = r.read(5_000_000).decode("utf-8", "ignore")
                    self.cache = {l.strip().lower() for l in content.splitlines() if l.strip()}
                self.at = time.time()
            hit = url.lower() in self.cache or any(fqdn.lower() in item for item in self.cache)
            return verdict(self.name, "listed" if hit else "clean", 0.85)
        except Exception as e:
            return verdict(self.name, "unavailable", 0.85, str(e)[:80])


class GoogleSafeBrowsing:
    """Safe Browsing v4 threatMatches:find. Requires GSB_API_KEY."""
    name = "google-safe-browsing"
    API = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"

    def check(self, url: str, fqdn: str) -> dict:
        key = os.getenv("GSB_API_KEY")
        if not key:
            return verdict(self.name, "unavailable", 0.95, "GSB_API_KEY not configured")
        body = {
            "client": {"clientId": "sentinel", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}, {"url": f"http://{fqdn}/"}]
            }
        }
        try:
            req = urllib.request.Request(
                self.API.format(key=key),
                json.dumps(body).encode(),
                {"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=6) as r:
                data = json.loads(r.read())
            matches = data.get("matches", [])
            hit = len(matches) > 0
            detail = f"Matched: {matches[0].get('threatType')}" if hit else ""
            return verdict(self.name, "listed" if hit else "clean", 0.95, detail)
        except Exception as e:
            return verdict(self.name, "unavailable", 0.95, str(e)[:80])


class URLhausFeed:
    """abuse.ch URLhaus online database. Checks URLhaus API; cached fallback."""
    name = "urlhaus"
    API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
    HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"

    def __init__(self):
        self.cached_offline: set[str] = set()
        # load offline snapshot if available
        offline_path = DATA / "urlhaus_offline.txt"
        if offline_path.exists():
            self.cached_offline = {l.strip().lower() for l in offline_path.read_text().splitlines() if l.strip()}

    def check(self, url: str, fqdn: str) -> dict:
        auth_key = os.getenv("URLHAUS_AUTH_KEY")
        headers = {"User-Agent": "Sentinel/1.0"}
        if auth_key:
            headers["Auth-Key"] = auth_key
        try:
            # First check URL
            data = urllib.parse.urlencode({"url": url}).encode()
            req = urllib.request.Request(self.API_URL, data=data, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as resp:
                res = json.loads(resp.read().decode())
                query_status = res.get("query_status")
                if query_status == "ok":
                    u_status = res.get("url_status", "")
                    threat = res.get("threat", "malware_download")
                    return verdict(self.name, "listed", 0.92, f"Threat: {threat} ({u_status})", raw_ref=res.get("urlhaus_reference"))
                elif query_status == "no_results":
                    pass

            # Check offline fallback cache
            if url.lower() in self.cached_offline or fqdn.lower() in self.cached_offline:
                return verdict(self.name, "listed", 0.88, "Cached URLhaus snapshot hit")

            return verdict(self.name, "clean", 0.92)
        except Exception as e:
            if url.lower() in self.cached_offline or fqdn.lower() in self.cached_offline:
                return verdict(self.name, "listed", 0.88, "Cached URLhaus hit (API unavailable)")
            return verdict(self.name, "unavailable", 0.92, str(e)[:80])


class PhishTankFeed:
    """PhishTank verified online phish feed / API."""
    name = "phishtank"
    API_URL = "https://checkurl.phishtank.com/checkurl/"

    def check(self, url: str, fqdn: str) -> dict:
        app_key = os.getenv("PHISHTANK_APP_KEY")
        post_data = {"url": url, "format": "json"}
        if app_key:
            post_data["app_key"] = app_key
        try:
            req = urllib.request.Request(
                self.API_URL,
                urllib.parse.urlencode(post_data).encode(),
                {"User-Agent": f"phishtank/sentinel"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                results = data.get("results", {})
                in_db = results.get("in_database")
                verified = results.get("verified")
                valid = results.get("valid")
                if in_db and verified and valid:
                    return verdict(self.name, "listed", 0.90, f"PhishTank phish_id: {results.get('phish_id')}")
                elif in_db:
                    return verdict(self.name, "clean", 0.70, "Unverified submission in PhishTank")
                return verdict(self.name, "clean", 0.90)
        except Exception as e:
            return verdict(self.name, "unavailable", 0.90, str(e)[:80])


class VirusTotalFeed:
    """VirusTotal API v3 URL analysis. Requires VT_API_KEY."""
    name = "virustotal"
    API_URL = "https://www.virustotal.com/api/v3/urls/{id}"

    def check(self, url: str, fqdn: str) -> dict:
        api_key = os.getenv("VT_API_KEY")
        if not api_key:
            return verdict(self.name, "unavailable", 0.90, "VT_API_KEY not configured")
        try:
            # VT API v3 uses URL identifier base64 without padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            req = urllib.request.Request(
                self.API_URL.format(id=url_id),
                headers={"x-apikey": api_key, "User-Agent": "Sentinel/1.0"}
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read().decode())
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                # PRD rule: VirusTotal alone needs >= 5 engines to count as a trusted malicious source
                if malicious >= 5:
                    return verdict(self.name, "listed", 0.95, f"{malicious} security engines detected malicious")
                elif malicious + suspicious >= 2:
                    return verdict(self.name, "clean", 0.75, f"{malicious} malicious, {suspicious} suspicious engines")
                return verdict(self.name, "clean", 0.90, "No significant detections")
        except Exception as e:
            return verdict(self.name, "unavailable", 0.90, str(e)[:80])


def default_feeds(offline: bool):
    """Returns list of active feeds. If offline, only uses offline-safe feeds."""
    if offline:
        return [LocalBlocklist()]
    return [
        LocalBlocklist(),
        OpenPhishFeed(),
        GoogleSafeBrowsing(),
        URLhausFeed(),
        PhishTankFeed(),
        VirusTotalFeed()
    ]
