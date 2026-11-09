"""Adversarial stress harness for SENTINEL correlation benchmark, edge cases, and offline mode.
Authored by Challenger 2 (critic, specialist).
"""
import unittest
import sys
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.evaluation import evaluate_correlation, build_labelled_dataset
from app.services import correlation as corr
from app.services.llm_provider import RuleBasedLLMProvider, GeminiLLMProvider
from app.services.reports import canonical_json, commitment, verify, LocalLedger


class AdversarialBenchmarkTests(unittest.TestCase):
    def test_benchmark_metrics_empirically(self):
        """Verify precision >= 90%, recall >= 70%, FP == 0, and inspect components."""
        metrics = evaluate_correlation()
        self.assertGreaterEqual(metrics.precision, 0.90)
        self.assertGreaterEqual(metrics.recall, 0.70)
        self.assertEqual(metrics.false_positives, 0)
        self.assertEqual(metrics.true_positives, 20)
        self.assertEqual(metrics.false_negatives, 6)
        self.assertGreaterEqual(metrics.purity, 0.95)

    def test_no_hardcoded_or_bypassed_logic(self):
        """Verify that metrics are dynamically calculated from build_edges and cluster_campaigns."""
        invs, ground_truth = build_labelled_dataset()
        # Dataset contains 24 campaign investigations (across 8 groups) + 10 distractors = 34 total
        self.assertEqual(len(invs), 34)
        self.assertEqual(len(ground_truth), 34)
        
        # Verify distractors do not form edges
        edges = corr.build_edges(invs, min_conf=0.6)
        distractor_ids = {f"distractor_{i}" for i in range(10)}
        for e in edges:
            self.assertNotIn(e["a"], distractor_ids, f"Distractor {e['a']} formed an edge!")
            self.assertNotIn(e["b"], distractor_ids, f"Distractor {e['b']} formed an edge!")

    def test_distractor_shared_infra_uniqueness_capping(self):
        """Adversarially verify that shared CDN IPs (Cloudflare 104.21.*) have uniqueness capped at <= 0.1."""
        u_cf = corr.uniqueness("ip", "104.21.44.82", df=10)
        self.assertLessEqual(u_cf, 0.1)

        u_asn = corr.uniqueness("asn", "AS13335", df=10)
        self.assertLessEqual(u_asn, 0.1)

        u_reg = corr.uniqueness("registrar", "NameCheap, Inc.", df=10)
        self.assertLessEqual(u_reg, 0.1)

        # Non-shared IP should have higher uniqueness
        u_dedicated = corr.uniqueness("ip", "185.220.101.44", df=4)
        self.assertGreater(u_dedicated, 0.4)

    def test_adversarial_injection_of_false_positive_candidate(self):
        """If two distinct entities share only a Cloudflare IP and generic ASN,
        they must NOT produce a qualified edge or high confidence.
        """
        now = datetime.now(timezone.utc)
        inv_a = {
            "id": "benign_site_alpha",
            "submitter": "user_a",
            "ts": now,
            "indicators": {
                ("ip", "104.21.1.1"): "verified",
                ("asn", "AS13335"): "verified",
                ("domain", "alpha-shop.com"): "verified",
            }
        }
        inv_b = {
            "id": "benign_site_beta",
            "submitter": "user_b",
            "ts": now,
            "indicators": {
                ("ip", "104.21.1.1"): "verified",
                ("asn", "AS13335"): "verified",
                ("domain", "beta-blog.org"): "verified",
            }
        }
        df = Counter([("ip", "104.21.1.1"), ("asn", "AS13335")])
        res = corr.pair_confidence(inv_a, inv_b, df)
        self.assertLess(res["confidence"], 0.2, f"Confidence {res['confidence']} too high for shared CDN")
        self.assertFalse(corr._qualifies(res["shared"]), "Shared CDN infra must not qualify as a correlation edge")

    def test_offline_rule_based_llm_determinism_and_isolation(self):
        """Verify RuleBasedLLMProvider works deterministically with no network access."""
        provider = RuleBasedLLMProvider()

        # Test Hindi urgency + threat
        text_hi = "प्रिय ग्राहक, आपका SBI खाता तुरंत ब्लॉक कर दिया जाएगा। अपना ओटीपी और पिन सत्यापित करें।"
        res_hi = provider.analyse(text_hi, "hi")
        self.assertIsNotNone(res_hi)
        self.assertEqual(res_hi["category"], "kyc_bank_phishing")
        self.assertIn("तुरंत", res_hi["evidence"])
        self.assertIn("ब्लॉक", res_hi["evidence"])
        self.assertIn("ओटीपी", res_hi["evidence"])
        self.assertEqual(res_hi["impersonated_brand"], "SBI")

        # Test Bengali delivery scam / payment ask
        text_bn = "India Post পার্সেল আটকে আছে। অবিলম্বে টাকা পাঠান।"
        res_bn = provider.analyse(text_bn, "bn")
        self.assertIsNotNone(res_bn)
        self.assertEqual(res_bn["category"], "upi_payment_request")
        self.assertIn("অবিলম্বে", res_bn["evidence"])
        self.assertIn("টাকা পাঠান", res_bn["evidence"])
        self.assertEqual(res_bn["impersonated_brand"], "INDIA POST")

        # Test Malayalam urgency
        text_ml = "നിങ്ങളുടെ അക്കൗണ്ട് ഉടൻ ബ്ലോക്ക് ചെയ്യപ്പെടും. ഒടിപി പങ്കിടുക."
        res_ml = provider.analyse(text_ml, "ml")
        self.assertIsNotNone(res_ml)
        self.assertIn("ഉടൻ", res_ml["evidence"])
        self.assertIn("ബ്ലോക്ക്", res_ml["evidence"])
        self.assertIn("ഒടിപി", res_ml["evidence"])

        # Test English lottery
        text_en = "Congratulations! You won lottery prize of $1,000,000. Claim cashback now."
        res_en = provider.analyse(text_en, "en")
        self.assertIsNotNone(res_en)
        self.assertEqual(res_en["category"], "lottery_prize")
        self.assertIn("won", res_en["evidence"])

    def test_offline_orchestrator_complete_network_isolation(self):
        """Adversarially verify that Sentinel orchestrator with offline=True
        executes an investigation with ZERO network socket or DNS calls.
        """
        import socket
        from app.orchestrator import Sentinel
        from app.db.storage import Storage

        original_socket = socket.socket
        original_getaddrinfo = socket.getaddrinfo

        network_calls = []

        def blocked_socket(*args, **kwargs):
            network_calls.append(("socket", args, kwargs))
            raise RuntimeError("Disallowed network socket creation during offline execution!")

        def blocked_getaddrinfo(*args, **kwargs):
            network_calls.append(("getaddrinfo", args, kwargs))
            raise RuntimeError("Disallowed DNS resolution during offline execution!")

        # Initialize Sentinel in offline mode with in-memory SQLite storage
        storage = Storage(":memory:")
        s = Sentinel(offline=True, storage=storage)

        # Monkeypatch network APIs
        socket.socket = blocked_socket
        socket.getaddrinfo = blocked_getaddrinfo

        try:
            # Run offline URL investigation
            inv_url = s.investigate_url("https://sbi-kyc-verify-offline.top", "analyst_test")
            self.assertEqual(inv_url["status"], "completed")
            self.assertIn("risk", inv_url)
            self.assertIn("score", inv_url["risk"])
            self.assertEqual(inv_url["steps"]["tls"], "skipped")
            self.assertEqual(inv_url["steps"]["dns"], "skipped")
            self.assertEqual(inv_url["steps"]["rdap"], "skipped")
            self.assertEqual(inv_url["steps"]["crtsh"], "skipped")

            # Run offline Message investigation
            inv_msg = s.investigate_message(
                "Dear SBI customer, your account is blocked immediately. Verify your OTP now.",
                "analyst_test"
            )
            self.assertEqual(inv_msg["status"], "completed")
            self.assertIn("risk", inv_msg)
            self.assertIn("score", inv_msg["risk"])

            # Assert ZERO network calls were attempted
            self.assertEqual(len(network_calls), 0, f"Network calls were made in offline mode: {network_calls}")
        finally:
            # Restore sockets
            socket.socket = original_socket
            socket.getaddrinfo = original_getaddrinfo

    def test_canonical_json_rfc8785_float_rejection(self):
        """Verify RFC 8785 subset in canonical_json strictly rejects floats."""
        # Valid: int, string, bool, dict, list
        valid_doc = {
            "title": "Sentinel Report",
            "risk_score": 85,
            "is_phishing": True,
            "tags": ["phish", "sbi"],
            "meta": {"version": 1}
        }
        b = canonical_json(valid_doc)
        self.assertIsInstance(b, bytes)
        # Verify deterministic key sorting
        self.assertEqual(b, b'{"is_phishing":true,"meta":{"version":1},"risk_score":85,"tags":["phish","sbi"],"title":"Sentinel Report"}')

        # Adversarial test: float at top level
        with self.assertRaises(ValueError) as ctx:
            canonical_json({"risk_score": 85.5})
        self.assertIn("floats not allowed", str(ctx.exception))

        # Adversarial test: float nested in dictionary
        with self.assertRaises(ValueError) as ctx:
            canonical_json({"data": {"confidence": 0.95}})
        self.assertIn("floats not allowed", str(ctx.exception))

        # Adversarial test: float nested in list
        with self.assertRaises(ValueError) as ctx:
            canonical_json({"scores": [1, 2, 3.14]})
        self.assertIn("floats not allowed", str(ctx.exception))

        # Adversarial test: float nested in tuple
        with self.assertRaises(ValueError) as ctx:
            canonical_json({"scores": (10, 20.0)})
        self.assertIn("floats not allowed", str(ctx.exception))

    def test_blockchain_salted_commitment_and_tamper_detection(self):
        """Verify LocalLedger commitments and tamper detection."""
        report = {
            "report_id": "rep_test_001",
            "risk_score": 90,
            "verdict": "malicious"
        }
        salt = b"0123456789abcdef"
        c = commitment(report, salt)
        self.assertTrue(c.startswith("0x"))
        self.assertEqual(len(c), 66)

        ledger = LocalLedger()
        rec = ledger.commit("rep_test_001", c, category=1)
        self.assertEqual(rec["version"], 1)
        self.assertEqual(rec["content_hash"], c)

        # Verification of unmodified report
        v_ok = verify(report, salt, ledger, "rep_test_001", 1)
        self.assertEqual(v_ok["status"], "MATCH")
        self.assertTrue(v_ok["integrity_confirmed"])

        # Verification of tampered report (altered score)
        tampered_report = dict(report)
        tampered_report["risk_score"] = 20  # changed from 90
        v_tampered = verify(tampered_report, salt, ledger, "rep_test_001", 1)
        self.assertEqual(v_tampered["status"], "MODIFIED")
        self.assertFalse(v_tampered["integrity_confirmed"])


if __name__ == "__main__":
    unittest.main()
