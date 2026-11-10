"""Investigation Orchestrator: one unified pipeline, shared indicator store,
Scam DNA Engine, explainable correlation, emerging radar, and tamper-evident reports.
"""
from concurrent.futures import ThreadPoolExecutor
import re
import socket
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit
from typing import Optional

from .core.normalize import canonical_url, split_domain
from .core.safe_http import fetch_chain, fetch_chain_with_signals
from .core.ssrf import UrlBlocked, validate_url
from .db.storage import Storage
from .services import ai_engine
from .services import correlation as corr
from .services import crtsh
from .services import dns_rdap
from .services import message_analysis as msg
from .services import radar
from .services import reports, risk, security_scan, tls_service, url_analysis
from .services.chain_client import EVMChainClient
from .services.feeds import default_feeds
from .services.llm_provider import get_default_provider


def now():
    return datetime.now(timezone.utc)


class Sentinel:
    def __init__(
        self,
        offline: bool = False,
        feeds=None,
        provider=None,
        resolver=socket.getaddrinfo,
        storage: Optional[Storage] = None,
        chain_client=None
    ):
        self.offline = offline
        self.resolver = resolver
        self.provider = provider if provider is not None else get_default_provider(offline)
        self.feeds = feeds if feeds is not None else default_feeds(offline)
        self.storage = storage if storage is not None else Storage(":memory:")
        self.ledger = reports.LocalLedger()
        self.chain_client = chain_client if chain_client is not None else EVMChainClient()

        # In-memory caches synced with storage for rapid correlation
        self.invs: dict[str, dict] = {}
        self.reports: dict[str, dict] = {}
        self.templates: list[tuple[str, list]] = []
        self._corr_dirty: bool = True
        self._corr_count: int = -1
        self._edges: list[dict] = []
        self._camps: list[dict] = []

        self._load_from_storage()

    def _load_from_storage(self):
        """Restore active state, templates, reports, and committed ledger records from persistent storage."""
        for inv in self.storage.all_investigations():
            self.invs[inv["id"]] = inv
        for tid, mh in self.storage.get_templates():
            self.templates.append((tid, mh))
        for rep in self.storage.all_reports():
            rid = rep["report_id"]
            self.reports[rid] = rep
            committed = [v["chain"] for v in rep["versions"] if v.get("chain")]
            if committed:
                self.ledger.h[rid] = committed

    # ---------- feed checks & dimension scoring ----------
    def _feed_checks(self, url: str, fqdn: str) -> list[dict]:
        if not self.offline and len(self.feeds) > 1:
            with ThreadPoolExecutor(max_workers=min(len(self.feeds), 6)) as pool:
                return list(pool.map(lambda f: f.check(url, fqdn), self.feeds))
        return [f.check(url, fqdn) for f in self.feeds]

    def _ti_dimension(self, checks: list[dict]):
        answered = [c for c in checks if c["status"] != "unavailable"]
        listed = [c for c in answered if c["status"] == "listed"]
        if not answered:
            return None, 0, 0
        trusted = len([c for c in listed if c["reliability"] >= 0.85])
        if listed:
            return (100, max(c["reliability"] for c in listed)), trusted, len(listed)
        return (0, 0.35), 0, 0

    def _url_core(self, url: str) -> dict:
        """Module 1 (+ Module 2 + AI Threat Engine when online) for one URL. Returns evidence + indicators."""
        url = url.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
            url = "http://" + url
        try:
            validate_url(url, self.resolver, resolve=not self.offline)
        except UrlBlocked as e:
            if "DNS resolution failed" in str(e) or "no addresses" in str(e):
                # Target domain is offline, taken down, or NXDOMAIN; validate structure without live resolution
                validate_url(url, self.resolver, resolve=False)
            else:
                raise
        a = url_analysis.analyse(url)
        fqdn = a["domain"]["fqdn"]
        reg_domain = a["domain"]["registrable"]
        ips, tls, hops, dns_records, rdap_info, ct_data, page_signals = [], None, [], {}, {}, {}, {}
        inds = {("domain", fqdn): "verified", ("url", a["canonical_url"]): "verified"}
        if reg_domain and reg_domain != fqdn:
            inds[("domain", reg_domain)] = "verified"

        if not self.offline:
            # 1. DNS Resolution first (avoid wasted timeouts if domain does not resolve)
            try:
                dns_records = dns_rdap.query_dns_records(fqdn)
                ips = dns_records.get("A", [])
            except Exception:
                ips = []
            for ip in ips:
                inds[("ip", ip)] = "verified"
            for ns in dns_records.get("NS", [])[:2]:
                inds[("nameserver", ns.lower().rstrip("."))] = "verified"

            # 2. Run RDAP, crt.sh, feeds, and (if IP resolved) TLS + HTTP fetch concurrently
            def _do_rdap():
                try:
                    return dns_rdap.query_rdap_age(reg_domain)
                except Exception:
                    return {}

            def _do_crtsh():
                try:
                    raw_ct = crtsh.query_crtsh(reg_domain)
                    return crtsh.crtsh_summary(raw_ct, fqdn)
                except Exception:
                    return {}

            def _do_tls():
                if not ips:
                    return {"error": "domain_unresolved"}
                try:
                    return tls_service.inspect(fqdn, resolver=self.resolver)
                except Exception as e:
                    return {"error": str(e)[:120]}

            def _do_fetch():
                if not ips:
                    return [], {}, None, {}
                return fetch_chain_with_signals(a["canonical_url"], self.resolver)

            with ThreadPoolExecutor(max_workers=5) as pool:
                f_rdap = pool.submit(_do_rdap)
                f_ct = pool.submit(_do_crtsh)
                f_tls = pool.submit(_do_tls)
                f_http = pool.submit(_do_fetch)
                f_feeds = pool.submit(self._feed_checks, a["canonical_url"], fqdn)

                rdap_info = f_rdap.result()
                ct_data = f_ct.result()
                tls = f_tls.result()
                hops, _, _, page_signals = f_http.result()
                checks = f_feeds.result()

            if rdap_info.get("is_young"):
                a["flags"].append({
                    "code": "newly_registered_domain",
                    "points": 18,
                    "detail": f"Domain registered recently ({rdap_info.get('domain_age_days')} days old)"
                })
                a["score"] = min(100, a["score"] + 18)

            if tls and tls.get("cert_sha256"):
                inds[("cert", tls["cert_sha256"])] = "verified"
                if tls.get("spki_sha256"):
                    inds[("spki", tls["spki_sha256"])] = "verified"
                # Store cert observation in persistent SQLite history on main thread
                self.storage.save_cert_observation(fqdn, tls)

            final_domain = reg_domain
            if hops and hops[-1].get("url"):
                hop_canon = canonical_url(hops[-1]["url"])
                if hop_canon != a["canonical_url"]:
                    dest_analysis = url_analysis.analyse(hop_canon)
                    final_domain = dest_analysis["domain"]["registrable"]
                    inds[("url", hop_canon)] = "verified"
                    if final_domain:
                        inds[("domain", final_domain)] = "verified"
                    if final_domain != reg_domain:
                        a["flags"].append({
                            "code": "cross_domain_redirect",
                            "points": 12,
                            "detail": f"Redirects across domains to {final_domain}"
                        })
                        a["score"] = min(100, a["score"] + 12)
                    if dest_analysis["score"] > 0:
                        existing_codes = {f["code"] for f in a["flags"]}
                        for fl in dest_analysis["flags"]:
                            if fl["code"] not in existing_codes:
                                a["flags"].append({
                                    "code": f"redirect_{fl['code']}",
                                    "points": fl["points"],
                                    "detail": f"Redirect target: {fl['detail']}"
                                })
                                a["score"] = min(100, a["score"] + fl["points"])
                        if dest_analysis.get("brand") and not a.get("brand"):
                            a["brand"] = dest_analysis["brand"]

            if page_signals:
                title_low = page_signals.get("title", "").lower()
                has_pw = page_signals.get("has_password_form", False)
                has_otp = page_signals.get("has_otp_form", False)
                is_young = bool(rdap_info.get("is_young"))

                if has_pw and (is_young or a["score"] >= 12 or has_otp):
                    a["flags"].append({
                        "code": "live_password_harvest_form",
                        "points": 20,
                        "detail": "Live page contains password/credential input form on suspicious infrastructure"
                    })
                    a["score"] = min(100, a["score"] + 20)

                if page_signals.get("has_crypto_drainer_lure"):
                    is_official_web3 = any(
                        url_analysis.is_official_brand_domain(b, final_domain)
                        for b in ("metamask", "trustwallet", "uniswap", "opensea", "coinbase", "binance", "ledger", "trezor", "phantom")
                    )
                    if not is_official_web3:
                        a["flags"].append({
                            "code": "live_crypto_drainer_signals",
                            "points": 30,
                            "detail": "Live page requests wallet connection, seed phrase, or airdrop claim on unofficial domain"
                        })
                        a["score"] = min(100, a["score"] + 30)

                for b in url_analysis.BRANDS:
                    if url_analysis.is_official_brand_domain(b, final_domain):
                        continue
                    if b in title_low and (has_pw or has_otp or a["score"] >= 15):
                        a["flags"].append({
                            "code": "live_page_brand_impersonation",
                            "points": 35,
                            "detail": f"Live page title impersonates '{b}' while collecting credentials on '{final_domain}'"
                        })
                        a["score"] = min(100, a["score"] + 35)
                        if not a.get("brand"):
                            a["brand"] = b
                        break

            if hops and hops[-1].get("url"):
                dest_canon = canonical_url(hops[-1]["url"])
                if dest_canon != a["canonical_url"]:
                    dest_fqdn = split_domain(urlsplit(dest_canon).hostname or "")["fqdn"]
                    dest_checks = self._feed_checks(dest_canon, dest_fqdn)
                    listed_map = {c["source"]: c for c in dest_checks if c["status"] == "listed"}
                    for i, c in enumerate(checks):
                        if c["status"] != "listed" and c["source"] in listed_map:
                            checks[i] = listed_map[c["source"]]
        else:
            checks = self._feed_checks(a["canonical_url"], fqdn)

        # Tier 1 On-Device ML + Tier 2 Optional Gemini 2.5 Flash Threat Analysis
        ai_res = ai_engine.evaluate_url_with_ai(
            a["canonical_url"],
            a,
            page_signals=page_signals,
            rdap_info=rdap_info,
            offline=self.offline,
        )
        if ai_res.get("is_dga_like"):
            a["flags"].append({
                "code": "ai_dga_entropy_anomaly",
                "points": 15,
                "detail": f"AI detected high domain entropy / DGA-like structure (H={ai_res.get('entropy')})"
            })
            a["score"] = min(100, a["score"] + 15)

        return {
            "analysis": a,
            "ai_analysis": ai_res,
            "ips": ips,
            "dns": dns_records,
            "rdap": rdap_info,
            "tls": tls,
            "crtsh": ct_data,
            "redirects": hops,
            "feeds": checks,
            "indicators": inds
        }

    def _tls_dim(self, tls: Optional[dict]):
        if not tls or ("error" in tls and "cert_sha256" not in tls):
            return None
        s = {"hostname_mismatch": 60, "self_signed": 50, "cert_expired": 40, "chain_invalid": 40}
        sc = max([s.get(f["code"], 0) for f in tls.get("findings", [])] or [0])
        return (sc, 0.8)

    def _finish(self, inv: dict, dims: dict, trusted: int, listed: int):
        self.invs[inv["id"]] = inv
        self._corr_dirty = True
        edges, camps = self.correlate()
        mine = [e for e in edges if inv["id"] in (e["a"], e["b"])]
        if mine:
            top = max(e["confidence"] for e in mine)
            peers = {(e["b"] if e["a"] == inv["id"] else e["a"]) for e in mine}
            bad = any(
                self.invs[p].get("risk", {}).get("class") in ("high_risk", "confirmed_malicious")
                for p in peers if p in self.invs
            )
            dims["correlation"] = ((70 if bad else 25) * min(top / 0.8, 1), 0.7)

        inv["risk"] = risk.assess(dims, trusted, listed)
        inv["status"] = "completed"
        inv["completed_at"] = now().isoformat()

        # Promote cached campaign status if this completed investigation is high-risk without re-running correlate()
        if inv["risk"]["class"] in ("high_risk", "confirmed_malicious"):
            for c in camps:
                if inv["id"] in c["members"] and c["confidence"] >= 0.7:
                    c["status"] = "corroborated"

        self.storage.save_investigation(inv)
        return inv

    # ---------- public API ----------
    def investigate_url(self, url: str, submitter: str = "anon", demo: bool = False) -> dict:
        core = self._url_core(url)
        a = core["analysis"]
        ai_res = core.get("ai_analysis") or {}
        ti, trusted, listed = self._ti_dimension(core["feeds"])
        dims = {"url": (a["score"], 0.7)}
        if ai_res:
            dims["ai_ml"] = (ai_res["ai_score"], ai_res["confidence"])
        if ti:
            dims["threat_intel"] = ti
        tls_dim = self._tls_dim(core["tls"])
        if tls_dim:
            dims["tls"] = tls_dim

        inv = {
            "id": str(uuid.uuid4()),
            "type": "url",
            "submitter": submitter,
            "ts": now(),
            "demo": demo,
            "status": "running",
            "input": url,
            "result": {
                "analysis": a,
                "ai_analysis": ai_res,
                "ips": core["ips"],
                "dns": core.get("dns", {}),
                "rdap": core.get("rdap", {}),
                "tls": core["tls"],
                "crtsh": core.get("crtsh", {}),
                "redirects": core["redirects"],
                "feeds": core["feeds"]
            },
            "indicators": core["indicators"],
            "steps": {
                "feeds": "ok" if ti else "unavailable",
                "ai": "ok" if ai_res else "skipped",
                "tls": "skipped" if self.offline else "ok",
                "dns": "skipped" if self.offline else "ok",
                "rdap": "skipped" if self.offline else "ok",
                "crtsh": "skipped" if self.offline else "ok"
            }
        }
        return self._finish(inv, dims, trusted, listed)

    def investigate_message(self, text: str, submitter: str = "anon", demo: bool = False) -> dict:
        m = msg.analyse_message(text, self.provider)
        inds, children, trusted, listed, ti_scores = {}, [], 0, 0, []
        ind = m["indicators"]
        for p in ind["phones"]: inds[("phone", p)] = "verified"
        for e in ind["emails"]: inds[("email", e)] = "verified"
        for u in ind["upi_ids"]: inds[("payment_id", u)] = "verified"

        url_scores = []
        for u in ind["urls"][:3]:
            full = u if u.lower().startswith("http") else "http://" + u
            try:
                c = self._url_core(full)
            except UrlBlocked as e:
                children.append({"url": u, "blocked": e.reason})
                continue
            a = c["analysis"]
            url_scores.append(a["score"])
            inds.update(c["indicators"])
            tdim, t, l = self._ti_dimension(c["feeds"])
            trusted, listed = trusted + t, listed + l
            if tdim:
                ti_scores.append(tdim)
            children.append({
                "url": a["canonical_url"],
                "score": a["score"],
                "flags": a["flags"],
                "feeds": c["feeds"],
                "tls": c["tls"],
                "crtsh": c.get("crtsh", {})
            })

        # Scam template fingerprint clustering
        tid = None
        for known_id, mh in self.templates:
            if msg.minhash_similarity(m["minhash"], mh) >= 0.7:
                tid = known_id
                break
        if tid is None:
            tid = "tpl-" + uuid.uuid4().hex[:8]
            self.templates.append((tid, m["minhash"]))
            self.storage.save_template(tid, m["minhash"])
        inds[("template", tid)] = "verified"

        ai_msg_res = ai_engine.evaluate_message_with_ai(text, language=m["language"], indicators=ind)
        dims = {"message": (m["score"], 0.6 if m["language"] in ("en", "hi") else 0.5)}
        dims["ai_ml"] = (ai_msg_res["ai_score"], ai_msg_res["confidence"])
        if url_scores:
            dims["url"] = (max(url_scores), 0.7)
        if ti_scores:
            dims["threat_intel"] = max(ti_scores)

        inv = {
            "id": str(uuid.uuid4()),
            "type": "message",
            "submitter": submitter,
            "ts": now(),
            "demo": demo,
            "status": "running",
            "input": text[:200] + ("..." if len(text) > 200 else ""),
            "input_hash": reports.commitment({"t": text}, b""),
            "result": {
                k: v for k, v in m.items() if k != "minhash"
            } | {"child_urls": children, "template_id": tid, "ai_analysis": ai_msg_res},
            "indicators": inds,
            "steps": {
                "message_rules": "ok",
                "ai": "ok",
                "llm": "ok" if m["llm"] else "skipped",
                "child_urls": "ok" if children else "none"
            }
        }
        return self._finish(inv, dims, trusted, listed)

    def assess_website(self, url: str, ownership_declared: bool = False) -> dict:
        norm_url, _ = validate_url(url, self.resolver, resolve=not self.offline)
        url = norm_url
        fqdn = split_domain(urlsplit(url).hostname or "")["fqdn"]
        reg_domain = split_domain(urlsplit(url).hostname or "")["registrable"]

        if self.offline:
            # Provide safe simulated response in offline mode
            sim_headers = {"server": "nginx/1.18.0", "strict-transport-security": "max-age=31536000"}
            findings = security_scan.analyse_headers(sim_headers, True, True)
            entry = {
                "scanned_at": now().isoformat(),
                "grade": security_scan.grade(findings),
                "findings": findings,
                "diff": {"new_findings": [], "resolved": []},
                "owned": ownership_declared,
                "dns_security": {"spf": {"present": True}, "dmarc": {"present": False}}
            }
            self.storage.save_website_scan(fqdn, entry)
            return {
                "domain": fqdn,
                "redirects": [{"url": url, "status": 200, "ip": "93.184.216.34"}],
                "latest": entry,
                "history": [{"scanned_at": entry["scanned_at"], "grade": entry["grade"]}],
                "offline_notice": "Assessment run in offline demo mode."
            }

        hops, headers, status = fetch_chain(canonical_url(url), self.resolver)
        https = bool(hops) and hops[-1].get("url", "").startswith("https://")
        http_first = hops[0]["url"].startswith("http://") if hops else False
        findings = security_scan.analyse_headers(headers, https, https if http_first else None)

        # DNS security checks (SPF, DMARC, CAA, DNSSEC)
        dns_sec = dns_rdap.query_dns_security(reg_domain)
        dns_findings = security_scan.analyse_dns_security(dns_sec)
        findings.extend(dns_findings)

        # TLS posture
        tls = None
        try:
            tls = tls_service.inspect(fqdn, resolver=self.resolver)
        except Exception as e:
            tls = {"error": str(e)[:100]}
        for f in (tls or {}).get("findings", []):
            findings.append({
                "code": f["code"],
                "category": f["category"],
                "severity": f["severity"],
                "title": f["code"].replace("_", " ").title(),
                "remediation": "Fix certificate configuration to prevent browser trust errors.",
                "evidence": "",
                "priority": 2.0
            })

        prev = self.storage.get_website_scans(fqdn)
        diff = security_scan.posture_diff(prev[-1]["findings"] if prev else None, findings)
        entry = {
            "scanned_at": now().isoformat(),
            "grade": security_scan.grade(findings),
            "findings": findings,
            "dns_security": dns_sec,
            "diff": diff,
            "owned": ownership_declared
        }
        self.storage.save_website_scan(fqdn, entry)
        history = [{"scanned_at": e["scanned_at"], "grade": e["grade"]} for e in self.storage.get_website_scans(fqdn)]
        return {"domain": fqdn, "redirects": hops, "latest": entry, "history": history}

    # ---------- correlation, graph, analytics, radar ----------
    def correlate(self):
        if not self._corr_dirty and self._corr_count == len(self.invs):
            return self._edges, self._camps
        invs = [i for i in self.invs.values() if i.get("status") in ("running", "completed")]
        edges = corr.build_edges(invs)
        camps = corr.cluster_campaigns(invs, edges)
        for c in camps:
            c["id"] = "camp-" + "-".join(sorted(m[:6] for m in c["members"][:2]))
            classes = [self.invs[m].get("risk", {}).get("class") for m in c["members"] if m in self.invs]
            if any(x in ("high_risk", "confirmed_malicious") for x in classes) and c["confidence"] >= 0.7:
                c["status"] = "corroborated"
        self._edges, self._camps = edges, camps
        self._corr_dirty = False
        self._corr_count = len(self.invs)
        return edges, camps

    def graph(self, inv_id: str, depth: int = 1, min_confidence: float = 0.4) -> dict:
        if inv_id not in self.invs:
            raise KeyError(inv_id)
        edges, camps = self.correlate()
        
        # Traverse up to requested depth
        visited_ids = {inv_id}
        frontier = {inv_id}
        for _ in range(min(depth, 2)):
            next_frontier = set()
            for fid in frontier:
                for e in edges:
                    if e["confidence"] >= min_confidence:
                        if e["a"] == fid and e["b"] not in visited_ids:
                            next_frontier.add(e["b"])
                        elif e["b"] == fid and e["a"] not in visited_ids:
                            next_frontier.add(e["a"])
            visited_ids.update(next_frontier)
            frontier = next_frontier

        nodes, out_edges = {}, []
        for i in visited_ids:
            inv = self.invs[i]
            nodes[i] = {
                "id": i,
                "type": "investigation",
                "label": f"{inv['type'].upper()}: {inv['input'][:35]}",
                "risk": inv.get("risk", {}).get("class"),
                "score": inv.get("risk", {}).get("score")
            }
            for (t, v), q in inv["indicators"].items():
                if corr.is_shared_infra(t, v):
                    continue
                nid = f"{t}:{v}"
                nodes.setdefault(nid, {
                    "id": nid,
                    "type": t,
                    "label": v[:40],
                    "uniqueness": corr.uniqueness(t, v, 2)
                })
                rel = {
                    "domain": "observed_domain",
                    "ip": "resolves_to",
                    "cert": "presents_cert",
                    "spki": "presents_cert",
                    "phone": "contains_contact",
                    "email": "contains_contact",
                    "payment_id": "contains_contact",
                    "template": "similar_to",
                    "nameserver": "uses_nameserver"
                }.get(t, "related")
                out_edges.append({
                    "source": i,
                    "target": nid,
                    "relationship_type": rel,
                    "shared_indicator": nid,
                    "evidence_source": "investigation",
                    "discovered_at": inv["ts"].isoformat() if isinstance(inv["ts"], datetime) else str(inv["ts"]),
                    "confidence": 1.0 if q == "verified" else 0.5
                })

        for e in edges:
            if e["a"] in visited_ids and e["b"] in visited_ids and e["confidence"] >= min_confidence:
                out_edges.append({
                    "source": e["a"],
                    "target": e["b"],
                    "relationship_type": "shares_indicator",
                    "confidence": e["confidence"],
                    "shared_indicator": ", ".join(f"{s['type']}={s['value'][:16]}" for s in e["shared"]),
                    "evidence_source": e["evidence_source"],
                    "discovered_at": e["discovered_at"],
                    "label": e["label"]
                })

        return {
            "root_id": inv_id,
            "depth": depth,
            "nodes": list(nodes.values()),
            "edges": out_edges
        }

    def overview(self) -> dict:
        invs = list(self.invs.values())
        by = lambda f: sum(1 for i in invs if f(i))
        cls = lambda c: (lambda i: i.get("risk", {}).get("class") == c)
        _, camps = self.correlate()
        radar_report = radar.compute_radar_signals(invs, camps)

        return {
            "total_investigations": len(invs),
            "demo_investigations": by(lambda i: i.get("demo", False)),
            "low_risk": by(cls("low_risk")),
            "suspicious": by(cls("suspicious")),
            "high_risk": by(cls("high_risk")),
            "confirmed_malicious": by(cls("confirmed_malicious")),
            "inconclusive": by(cls("inconclusive")),
            "potential_campaigns": len(camps),
            "corroborated_campaigns": sum(1 for c in camps if c.get("status") == "corroborated"),
            "categories": {
                c: by(lambda i, c=c: i.get("type") == "message" and i.get("result", {}).get("category") == c)
                for c in {i.get("result", {}).get("category") for i in invs if i.get("type") == "message"}
                if c
            },
            "radar": radar_report,
            "note": "Threat signals grounded in deterministic indicators. Demonstration data flagged when demo_investigations > 0."
        }

    def get_domain_profile(self, domain: str) -> dict:
        """PRD Section 17 & 8: Domain profile, live TLS inspection, certificate timeline, and related investigations."""
        raw = domain.strip().lower()
        if "://" in raw or "/" in raw:
            parsed = urlsplit(raw if "://" in raw else "https://" + raw)
            clean = (parsed.hostname or raw).strip().lower().lstrip("*.")
        else:
            clean = raw.lstrip("*.")

        related = [
            i for i in self.invs.values()
            if any(t == "domain" and clean in v.lower() for (t, v) in i.get("indicators", {}).keys())
        ]
        scans = self.storage.get_website_scans(clean)
        dns_rec, rdap_info, ct_data, live_tls = {}, {}, {}, None

        if not self.offline and clean:
            def _do_dns():
                try:
                    return dns_rdap.query_dns_records(clean)
                except Exception:
                    return {}

            def _do_rdap():
                try:
                    return dns_rdap.query_rdap_age(clean)
                except Exception:
                    return {}

            def _do_ct():
                try:
                    return crtsh.crtsh_summary(crtsh.query_crtsh(clean), clean)
                except Exception:
                    return {}

            def _do_tls():
                try:
                    return tls_service.inspect(clean, resolver=self.resolver)
                except Exception as e:
                    return {"error": str(e)[:120]}

            with ThreadPoolExecutor(max_workers=4) as pool:
                f_dns = pool.submit(_do_dns)
                f_rdap = pool.submit(_do_rdap)
                f_ct = pool.submit(_do_ct)
                f_tls = pool.submit(_do_tls)
                dns_rec = f_dns.result()
                rdap_info = f_rdap.result()
                ct_data = f_ct.result()
                live_tls = f_tls.result()

            if live_tls and live_tls.get("cert_sha256"):
                self.storage.save_cert_observation(clean, live_tls)
        else:
            ct_data = crtsh.crtsh_summary([], clean)

        cert_history = self.storage.get_cert_history(clean)

        return {
            "domain": clean,
            "dns": dns_rec,
            "rdap": rdap_info,
            "live_tls": live_tls,
            "certificate_timeline": cert_history,
            "ct_log_summary": ct_data,
            "website_scans": scans,
            "related_investigations": [
                {
                    "id": r["id"],
                    "type": r["type"],
                    "input": r["input"],
                    "risk": r.get("risk", {}).get("class"),
                    "created_at": r.get("created_at")
                }
                for r in related[:20]
            ]
        }

    # ---------- reports (Module 6) ----------
    def make_report(self, inv_id: str) -> dict:
        inv = self.invs[inv_id]
        saved = self.storage.get_report_by_investigation(inv_id) or next(
            (r for r in self.reports.values() if r.get("investigation_id") == inv_id),
            None
        )
        r = saved or {
            "report_id": str(uuid.uuid4()),
            "investigation_id": inv_id,
            "salt": reports.new_salt(),
            "versions": []
        }

        # Calculate community reputation
        reputation = reports.compute_community_reputation(inv, list(self.invs.values()))

        body = {
            "report_id": r["report_id"],
            "version": len(r["versions"]) + 1,
            "investigation_id": inv_id,
            "type": inv["type"],
            "risk_class": inv["risk"]["class"],
            "risk_score": str(inv["risk"]["score"]),
            "coverage": str(inv["risk"]["coverage"]),
            "confidence": str(inv["risk"]["confidence"]),
            "reputation_score": str(reputation["reputation_score"]),
            "drivers": [
                {"dimension": d["dimension"], "contribution": str(d["contribution"])}
                for d in inv["risk"].get("drivers", [])
            ],
            "indicators": sorted(f"{t}:{v}" for (t, v) in inv["indicators"]),
            "created_at": now().isoformat()
        }

        salt = r["salt"]
        v_entry = {
            "body": body,
            "commitment": reports.commitment(body, salt),
            "chain": None
        }
        r["versions"].append(v_entry)
        self.reports[r["report_id"]] = r
        self.storage.save_report(r["report_id"], inv_id, salt.hex(), r["versions"])
        return r

    def commit_report(self, report_id: str, version: int | None = None) -> dict:
        r = self.reports.get(report_id) or self.storage.get_report(report_id)
        if not r:
            raise KeyError(report_id)
        v_idx = (version or len(r["versions"])) - 1
        v = r["versions"][v_idx]

        # Use chain client / ledger
        chain_rec = self.chain_client.commit(report_id, v["commitment"], category=1)
        # Also record in ledger
        self.ledger.commit(report_id, v["commitment"], category=1)
        v["chain"] = chain_rec

        self.reports[report_id] = r
        self.storage.save_report(report_id, r["investigation_id"], r["salt"].hex(), r["versions"])
        return chain_rec

    def verify_report(self, report_id: str, version: int | None = None) -> dict:
        r = self.reports.get(report_id) or self.storage.get_report(report_id)
        if not r:
            raise KeyError(report_id)
        n = version or len(r["versions"])
        target_v = r["versions"][n - 1]
        
        # Verify against ledger / chain client
        return reports.verify(target_v["body"], r["salt"], self.ledger, report_id, n)

    # ---------- website monitoring subscriptions ----------
    def create_monitoring_subscription(self, domain: str, email: Optional[str] = None, interval_hours: int = 24) -> dict:
        clean = split_domain(domain)["fqdn"]
        sub = {
            "id": "sub-" + uuid.uuid4().hex[:8],
            "domain": clean,
            "email": email,
            "interval_hours": interval_hours,
            "ownership_declared": True,
            "created_at": now().isoformat(),
            "last_scan_at": None,
            "last_grade": None,
            "active": True
        }
        self.storage.save_subscription(sub)
        return sub

    def list_monitoring_subscriptions(self) -> list[dict]:
        return self.storage.list_subscriptions()
