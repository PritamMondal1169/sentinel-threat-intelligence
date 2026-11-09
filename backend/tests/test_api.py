import os
os.environ["SENTINEL_OFFLINE"] = "true"
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import (
    health,
    overview,
    get_settings,
    inv_url,
    inv_msg,
    get_inv,
    list_inv,
    get_domain_profile,
    campaigns,
    graph,
    assess,
    create_monitoring,
    list_monitoring,
    make_report,
    get_report,
    commit,
    verify,
    export_report_bundle,
    UrlIn,
    MsgIn,
    AssessIn,
    MonitoringIn,
    S
)
from app.services.feeds import default_feeds


class ApiEndpointsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        S.offline = True
        S.feeds = default_feeds(offline=True)

    def test_health(self):
        res = health()
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["active_modules"], 6)

    def test_overview(self):
        data = overview()
        self.assertIn("total_investigations", data)
        self.assertIn("radar", data)
        self.assertIn("categories", data)

    def test_settings(self):
        data = get_settings()
        self.assertIn("adapters", data)
        self.assertIn("llm_provider", data)
        self.assertIn("blockchain", data)

    def test_url_investigation_and_graph(self):
        inv = inv_url(UrlIn(url="http://sbi-kyc-update.top/login"))
        iid = inv["id"]
        self.assertIn("risk", inv)

        # Retrieve investigation
        loaded = get_inv(iid)
        self.assertEqual(loaded["id"], iid)

        # Query threat graph
        g = graph(iid, depth=1, min_confidence=0.4)
        self.assertIn("nodes", g)
        self.assertIn("edges", g)

    def test_message_investigation(self):
        text = "URGENT: Your SBI account will be blocked today. Update KYC now http://sbi-kyc-update.top/verify and call 9000000001"
        data = inv_msg(MsgIn(text=text))
        self.assertEqual(data["type"], "message")
        self.assertIn("indicators", data)

    def test_domain_profile(self):
        data = get_domain_profile("sbi.co.in")
        self.assertEqual(data["domain"], "sbi.co.in")
        self.assertIn("certificate_timeline", data)

    def test_campaigns(self):
        camps = campaigns()
        self.assertIsInstance(camps, list)

    def test_website_assessment_and_monitoring(self):
        # Assessment
        data = assess(AssessIn(url="https://example.org", ownership_declared=True))
        self.assertIn("grade", data["latest"])

        # Create monitoring subscription
        sub = create_monitoring(MonitoringIn(domain="example.org", email="admin@example.org", ownership_declared=True))
        self.assertEqual(sub["domain"], "example.org")

        # List monitoring
        subs = list_monitoring()
        self.assertTrue(any(s["domain"] == "example.org" for s in subs))

    def test_report_lifecycle(self):
        # Create investigation
        inv = inv_url(UrlIn(url="http://sbi-kyc-update.top/login"))
        iid = inv["id"]

        # Make report
        rep = make_report(iid)
        rep_id = rep["report_id"]

        # Commit report
        c_res = commit(rep_id)
        self.assertIn("tx_hash", c_res)

        # Verify report
        v_res = verify(rep_id)
        self.assertEqual(v_res["status"], "MATCH")

        # Export bundle
        bundle = export_report_bundle(rep_id)
        self.assertIn("salt_hex", bundle)
        self.assertIn("verification_instructions", bundle)


if __name__ == "__main__":
    unittest.main()
