import unittest
from pathlib import Path
import sys
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.db.storage import Storage
from app.orchestrator import Sentinel
from app.services import feeds, llm_provider, radar, reports, security_scan


class ModuleStorageTests(unittest.TestCase):
    def setUp(self):
        self.storage = Storage(":memory:")

    def test_save_and_retrieve_investigation(self):
        inv = {
            "id": "test-inv-1",
            "type": "url",
            "submitter": "tester",
            "input": "https://example.com/test",
            "status": "completed",
            "ts": datetime.now(timezone.utc),
            "demo": False,
            "indicators": {("domain", "example.com"): "verified", ("ip", "93.184.216.34"): "verified"},
            "result": {"analysis": {"score": 10}},
            "steps": {"feeds": "ok"},
            "risk": {"class": "low_risk", "score": 10, "coverage": 0.8, "confidence": 0.75, "drivers": []}
        }
        self.storage.save_investigation(inv)
        loaded = self.storage.get_investigation("test-inv-1")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["id"], "test-inv-1")
        self.assertEqual(loaded["type"], "url")
        self.assertIn(("domain", "example.com"), loaded["indicators"])

    def test_monitoring_subscriptions(self):
        sub = {
            "id": "sub-1",
            "domain": "my-domain.com",
            "email": "admin@my-domain.com",
            "interval_hours": 12,
            "ownership_declared": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "active": True
        }
        self.storage.save_subscription(sub)
        subs = self.storage.list_subscriptions()
        self.assertEqual(len(subs), 1)
        self.assertEqual(subs[0]["domain"], "my-domain.com")


class FeedAdapterTests(unittest.TestCase):
    def test_local_blocklist(self):
        bl = feeds.LocalBlocklist()
        res = bl.check("http://sbi-kyc-update.top/login", "sbi-kyc-update.top")
        self.assertEqual(res["status"], "listed")
        res_clean = bl.check("https://clean-site.example/page", "clean-site.example")
        self.assertEqual(res_clean["status"], "clean")

    def test_urlhaus_clean_fallback(self):
        uh = feeds.URLhausFeed()
        res = uh.check("https://google.com/", "google.com")
        self.assertIn(res["status"], ("clean", "unavailable"))

    def test_phishtank_fallback(self):
        pt = feeds.PhishTankFeed()
        res = pt.check("https://google.com/", "google.com")
        self.assertIn(res["status"], ("clean", "unavailable"))

    def test_openphish_adapter(self):
        op = feeds.OpenPhishFeed(offline=True)
        res = op.check("https://google.com/", "google.com")
        self.assertEqual(res["status"], "clean")
        res_hit = op.check("http://sbi-kyc-update.top/login", "sbi-kyc-update.top")
        self.assertEqual(res_hit["status"], "listed")

    def test_google_safe_browsing_adapter(self):
        gsb = feeds.GoogleSafeBrowsing(offline=True)
        res = gsb.check("https://google.com/", "google.com")
        self.assertEqual(res["status"], "clean")
        res_hit = gsb.check("http://sbi-kyc-update.top/login", "sbi-kyc-update.top")
        self.assertEqual(res_hit["status"], "listed")

    def test_virustotal_adapter(self):
        vt = feeds.VirusTotalFeed(offline=True)
        res = vt.check("https://google.com/", "google.com")
        self.assertEqual(res["status"], "clean")
        res_hit = vt.check("http://sbi-kyc-update.top/login", "sbi-kyc-update.top")
        self.assertEqual(res_hit["status"], "listed")

    def test_all_adapters_return_valid_verdicts(self):
        all_f = feeds.default_feeds(offline=True)
        self.assertEqual(len(all_f), 6)
        for f in all_f:
            res = f.check("https://example.com/test", "example.com")
            self.assertIn(res["status"], ("clean", "listed", "unavailable"))
            self.assertGreater(res["reliability"], 0.5)


class LLMProviderTests(unittest.TestCase):
    def test_rule_based_evidence_is_verbatim(self):
        provider = llm_provider.RuleBasedLLMProvider()
        text = "URGENT: Your SBI account is blocked immediately, provide OTP."
        res = provider.analyse(text, "en")
        self.assertIsNotNone(res)
        self.assertEqual(res["category"], "kyc_bank_phishing")
        for quote in res["evidence"]:
            self.assertIn(quote, text, f"Evidence quote '{quote}' must appear verbatim in message")

    def test_gemini_evidence_verification(self):
        g = llm_provider.GeminiLLMProvider(api_key="fake")
        # Test the sanitize and verification method
        parsed = {
            "category": "kyc_bank_phishing",
            "confidence": 0.9,
            "evidence": ["URGENT", "hallucinated quote not in text", "blocked"],
            "manipulation_signals": ["urgency", "threat"],
            "precautions": ["Be careful"]
        }
        text = "URGENT: Your account is blocked."
        clean = g._sanitize_and_verify(parsed, text)
        self.assertEqual(clean["evidence"], ["URGENT", "blocked"])
        self.assertNotIn("hallucinated quote not in text", clean["evidence"])


class RadarTests(unittest.TestCase):
    def test_brand_surge_alert(self):
        now = datetime.now(timezone.utc)
        invs = []
        for i in range(6):
            invs.append({
                "id": f"inv-{i}",
                "submitter": f"user-{i}",
                "ts": now,
                "result": {"brand": "SBI"},
                "indicators": {("domain", f"sbi-fake-{i}.top"): "verified"}
            })
        report = radar.compute_radar_signals(invs, [])
        self.assertGreaterEqual(len(report["active_alerts"]), 1)
        alert_types = [a["type"] for a in report["active_alerts"]]
        self.assertIn("brand_targeting_spike", alert_types)


class SecurityScanDNSTests(unittest.TestCase):
    def test_dns_security_findings(self):
        dns_sec = {
            "spf": {"present": False},
            "dmarc": {"present": False},
            "caa": {"present": False},
            "dnssec": {"has_ds": False}
        }
        findings = security_scan.analyse_dns_security(dns_sec)
        codes = {f["code"] for f in findings}
        self.assertIn("no_spf", codes)
        self.assertIn("no_dmarc", codes)
        self.assertIn("no_caa", codes)
        self.assertIn("no_dnssec", codes)


class AcceptanceDemoTests(unittest.TestCase):
    """PRD Section 25: 10-Minute Acceptance Demo Flow test.
    Bengali message -> extracted URL -> certificate -> campaign -> website assessment -> commit -> tamper test -> verify.
    """
    def test_full_acceptance_walkthrough(self):
        storage = Storage(":memory:")
        s = Sentinel(offline=True, storage=storage)

        # 1. Investigate Bengali scam message with extracted URL
        msg_text = "আপনার SBI অ্যাকাউন্ট অবিলম্বে বন্ধ হয়ে যাবে। লগইন করুন http://sbi-kyc-update.top/login ওটিপি দিন অবিলম্বে।"
        inv_msg = s.investigate_message(msg_text, "anita_kolkata")
        self.assertEqual(inv_msg["result"]["language"], "bn")
        self.assertIn("child_urls", inv_msg["result"])
        self.assertGreater(inv_msg["risk"]["score"], 45)

        # 2. Correlate with earlier investigation sharing indicators
        s.investigate_url("http://sbi-kyc-update.top/login", "rohan_soc")
        edges, camps = s.correlate()
        self.assertTrue(len(edges) >= 1)
        self.assertTrue(len(camps) >= 1)

        # 3. Website assessment
        assess_res = s.assess_website("https://example.org/", ownership_declared=True)
        self.assertIn("grade", assess_res["latest"])

        # 4. Canonical Report, Commit to chain, Verify MATCH
        rep = s.make_report(inv_msg["id"])
        commit_res = s.commit_report(rep["report_id"])
        self.assertIn("tx_hash", commit_res)

        verify_res = s.verify_report(rep["report_id"])
        self.assertEqual(verify_res["status"], "MATCH")
        self.assertTrue(verify_res["integrity_confirmed"])

        # 5. Tamper detection: alter stored body by 1 char -> verify MODIFIED
        rep["versions"][0]["body"]["risk_class"] = "low_risk"
        tamper_res = s.verify_report(rep["report_id"])
        self.assertEqual(tamper_res["status"], "MODIFIED")
        self.assertFalse(tamper_res["integrity_confirmed"])


if __name__ == "__main__":
    unittest.main()

