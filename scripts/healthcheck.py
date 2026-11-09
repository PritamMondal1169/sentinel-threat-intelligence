#!/usr/bin/env python3
"""Automated Health & Latency Probe for SENTINEL.
Checks API responsiveness, database connectivity, and active threat detection modules.
"""
import json
import sys
import time
import urllib.request
import urllib.error

def probe(url="http://127.0.0.1:8000/health"):
    start = time.perf_counter()
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Sentinel-Monitor/1.0", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            latency_ms = round((time.perf_counter() - start) * 1000, 2)
            code = response.getcode()
            body = json.loads(response.read().decode("utf-8"))

            if code == 200 and body.get("status") == "ok":
                print(f"[+] HEALTHY | {latency_ms}ms | Service: {body.get('service')} v{body.get('version')}")
                print(f"    - Investigations: {body.get('investigations_count')}")
                print(f"    - Active Modules: {body.get('active_modules')}/6")
                print(f"    - Mode: {'Offline Demo Fallback' if body.get('offline') else 'Live Online Threat Feeds'}")
                print(f"    - Database: {body.get('database', {}).get('status')}")
                return 0
            else:
                print(f"[-] UNHEALTHY response: {body} (code={code})")
                return 1
    except urllib.error.URLError as e:
        print(f"[-] FAILED to reach SENTINEL at {url}: {e.reason}")
        return 2
    except Exception as e:
        print(f"[-] ERROR probing {url}: {e}")
        return 3

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/health"
    sys.exit(probe(target))

