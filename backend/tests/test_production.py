"""Production hardening tests for SENTINEL.
Tests JWT authentication, password hashing, RBAC, async background jobs, and security headers.
"""
import os
os.environ["SENTINEL_OFFLINE"] = "true"
os.environ["SENTINEL_DB_PATH"] = ":memory:"
import sys
import time
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.auth import (
    create_access_token,
    verify_token,
    hash_password,
    verify_password,
    ROLE_HIERARCHY,
    ensure_admin_user
)
from app.background import submit_job, get_job
from app.db.storage import Storage
from app.main import app, login, register, get_me, check_job_status, inv_url, UrlIn, LoginIn, RegisterIn
from fastapi import HTTPException


class TestAuthenticationAndRBAC:
    def test_password_hashing_and_verification(self):
        plain = "Secur3P@ssw0rd!"
        hashed = hash_password(plain)
        assert hashed.startswith("pbkdf2_sha256$100000$")
        assert verify_password(plain, hashed) is True
        assert verify_password("WrongPassword", hashed) is False

    def test_jwt_token_lifecycle(self):
        token = create_access_token("analyst_user", role="analyst", expires_in=10)
        payload = verify_token(token)
        assert payload["sub"] == "analyst_user"
        assert payload["role"] == "analyst"
        assert "exp" in payload

    def test_jwt_token_expiration(self):
        short_lived_token = create_access_token("expiring_user", role="viewer", expires_in=-5)
        with pytest.raises(HTTPException) as exc_info:
            verify_token(short_lived_token)
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail["code"] == "TOKEN_EXPIRED"

    def test_admin_user_seed_and_login(self):
        storage = Storage(":memory:")
        ensure_admin_user(storage)
        admin = storage.get_user_by_username("admin")
        assert admin is not None
        assert admin["role"] == "admin"
        assert verify_password("changeme123", admin["password_hash"]) is True

    def test_role_hierarchy(self):
        assert ROLE_HIERARCHY["admin"] > ROLE_HIERARCHY["analyst"]
        assert ROLE_HIERARCHY["analyst"] > ROLE_HIERARCHY["viewer"]

    def test_user_management_and_password_change(self):
        storage = Storage(":memory:")
        ensure_admin_user(storage)
        users = storage.list_users()
        assert any(u["username"] == "admin" for u in users)
        assert any(u["username"] == "analyst" for u in users)

        # Verify password change logic
        admin = storage.get_user_by_username("admin")
        assert verify_password("changeme123", admin["password_hash"]) is True
        admin["password_hash"] = hash_password("NewSecurePass456!")
        storage.save_user(admin)

        updated = storage.get_user_by_username("admin")
        assert verify_password("NewSecurePass456!", updated["password_hash"]) is True
        assert verify_password("changeme123", updated["password_hash"]) is False


class TestAsyncBackgroundJobs:
    def test_async_job_submission_and_completion(self):
        def sample_calculation(x, y):
            time.sleep(0.05)
            return {"sum": x + y}

        job_id = submit_job("test_calc", sample_calculation, 10, 25)
        assert job_id.startswith("job-")

        # Initial check
        job = get_job(job_id)
        assert job is not None
        assert job["job_id"] == job_id
        assert job["status"] in ("pending", "running", "completed")

        # Wait for completion
        for _ in range(20):
            time.sleep(0.05)
            job = get_job(job_id)
            if job["status"] == "completed":
                break

        assert job["status"] == "completed"
        assert job["result"] == {"sum": 35}
        assert job["progress"] == 1.0

    def test_async_job_failure_handled(self):
        def failing_task():
            raise ValueError("Intentional error for testing")

        job_id = submit_job("test_fail", failing_task)
        for _ in range(20):
            time.sleep(0.05)
            job = get_job(job_id)
            if job["status"] == "failed":
                break

        assert job["status"] == "failed"
        assert "Intentional error for testing" in job["error"]

    def test_investigation_async_mode(self):
        body = UrlIn(url="https://example.com/test-async", submitter="test_runner")
        response = inv_url(body, sync=False)
        assert response.status_code == 202
        data = response.body.decode("utf-8")
        assert "job_id" in data
        assert "pending" in data


class TestHttpRbacEnforcement:
    def setup_method(self):
        from app.auth import require_role, get_current_user
        self.require_role = require_role
        self.get_current_user = get_current_user
        self.admin_user = {"sub": "admin_test", "role": "admin"}
        self.analyst_user = {"sub": "analyst_test", "role": "analyst"}
        self.viewer_user = {"sub": "viewer_test", "role": "viewer"}

    def test_unauthenticated_request_fails_401(self):
        with pytest.raises(HTTPException) as exc:
            self.get_current_user(None)
        assert exc.value.status_code == 401
        assert exc.value.detail["code"] == "UNAUTHORIZED"

    def test_authenticated_user_passes_get_current_user(self):
        user = self.get_current_user(self.analyst_user)
        assert user["sub"] == "analyst_test"
        assert user["role"] == "analyst"

    def test_analyst_forbidden_from_admin_role(self):
        admin_guard = self.require_role("admin")
        with pytest.raises(HTTPException) as exc:
            admin_guard(self.analyst_user)
        assert exc.value.status_code == 403
        assert exc.value.detail["code"] == "FORBIDDEN"

    def test_admin_allowed_by_admin_role(self):
        admin_guard = self.require_role("admin")
        result = admin_guard(self.admin_user)
        assert result["role"] == "admin"

    def test_viewer_forbidden_from_analyst_role(self):
        analyst_guard = self.require_role("analyst")
        with pytest.raises(HTTPException) as exc:
            analyst_guard(self.viewer_user)
        assert exc.value.status_code == 403
        assert exc.value.detail["code"] == "FORBIDDEN"

    def test_analyst_allowed_by_analyst_role(self):
        analyst_guard = self.require_role("analyst")
        result = analyst_guard(self.analyst_user)
        assert result["role"] == "analyst"


class TestRealWorldMaliciousAndSpamScoring:
    @pytest.mark.parametrize("url", [
        "https://www.facebook-q.blogspot.com/",
        "https://free-crypto-giveaway.xyz/claim",
        "http://earn-fast-cash-now.click/bonus",
        "https://discord-nitro-free.icu/",
        "http://malicious-payload.top/download.exe",
    ])
    def test_real_malicious_and_spam_links_flagged_high_risk(self, url):
        from app.services import url_analysis, risk
        a = url_analysis.analyse(url)
        r = risk.assess({"url": (a["score"], 0.7), "threat_intel": (0, 0.35), "tls": (0, 0.8)}, 0, 0)
        assert r["class"] in ("high_risk", "confirmed_malicious")
        assert r["score"] >= 55.0

    @pytest.mark.parametrize("url", [
        "http://198.51.100.42/login.php",
        "http://verify-account-now.cfd/signin",
        "https://win-iphone-16-prize.buzz/",
        "http://bit.ly/3x9AbCd",
    ])
    def test_suspicious_ip_shortener_and_spam_links_never_low_risk(self, url):
        from app.services import url_analysis, risk
        a = url_analysis.analyse(url)
        r = risk.assess({"url": (a["score"], 0.7), "threat_intel": (0, 0.35), "tls": (0, 0.8)}, 0, 0)
        assert r["class"] in ("suspicious", "high_risk", "confirmed_malicious")
        assert r["score"] >= 25.0

    @pytest.mark.parametrize("url", [
        "https://google.com",
        "https://github.com/torvalds/linux",
        "https://www.sbi.co.in/",
        "https://example.org/",
    ])
    def test_benign_official_links_remain_low_risk(self, url):
        from app.services import url_analysis, risk
        a = url_analysis.analyse(url)
        r = risk.assess({"url": (a["score"], 0.7), "threat_intel": (0, 0.35), "tls": (0, 0.8)}, 0, 0)
        assert r["class"] == "low_risk"
        assert r["score"] == 0.0


class TestOnDeviceAIModel:
    def test_ai_detects_dga_high_entropy_domain(self):
        from app.services import url_analysis, ai_engine
        u = "https://xj8k2m9p4q7z.xyz/gate.php"
        a = url_analysis.analyse(u)
        ai = ai_engine.evaluate_url_with_ai(u, a, offline=True)
        assert ai["is_dga_like"] is True
        assert ai["entropy"] >= 3.35
        assert ai["ai_score"] >= 45.0

    def test_ai_classifies_malware_spam_and_phishing(self):
        from app.services import url_analysis, ai_engine
        for u, expected in [
            ("http://malicious-payload.top/download.exe", "malware_dropper"),
            ("https://free-crypto-giveaway.xyz/claim", "spam_scam"),
            ("https://discord-nitro-free.icu/", "phishing"),
        ]:
            a = url_analysis.analyse(u)
            ai = ai_engine.evaluate_url_with_ai(u, a, offline=True)
            assert ai["threat_type"] == expected
            assert ai["ai_score"] >= 80.0

    def test_ai_classifies_benign_official_domains_near_zero(self):
        from app.services import url_analysis, ai_engine
        for u in ["https://google.com", "https://www.sbi.co.in/"]:
            a = url_analysis.analyse(u)
            ai = ai_engine.evaluate_url_with_ai(u, a, offline=True)
            assert ai["threat_type"] == "benign"
            assert ai["ai_score"] <= 5.0

    def test_ai_multilingual_message_intent(self):
        from app.services import ai_engine
        res = ai_engine.evaluate_message_with_ai(
            "URGENT: Your account is suspended. Share OTP immediately at http://sbi-kyc.top",
            language="en",
            indicators={"urls": ["http://sbi-kyc.top"], "phones": [], "upis": []}
        )
        assert res["threat_type"] == "kyc_bank_phishing"
        assert res["ai_score"] >= 80.0
        assert "credential_request" in res["signals"]


class TestProductionSafetyGuards:
    def test_jwt_secret_never_hardcoded_fallback(self, monkeypatch):
        from app import auth
        monkeypatch.setenv("SENTINEL_JWT_SECRET", "env-provided-prod-secret-key-0123456789")
        assert auth._load_or_create_jwt_secret() == "env-provided-prod-secret-key-0123456789"
        monkeypatch.delenv("SENTINEL_JWT_SECRET", raising=False)
        generated = auth._load_or_create_jwt_secret()
        assert len(generated) >= 32
        assert "change-in-env-file" not in generated

    def test_rate_limiter_prunes_stale_entries(self):
        from collections import deque
        from types import SimpleNamespace
        from app.main import _hits, rate_limit
        _hits.clear()
        for i in range(2005):
            _hits[f"stale-{i}:10"] = deque([0.0])
        dep = rate_limit(10)
        dep(SimpleNamespace(client=SimpleNamespace(host="198.51.100.1")))
        assert len(_hits) < 100
        _hits.clear()

    def test_report_verification_survives_restart(self, tmp_path):
        from app.orchestrator import Sentinel
        db = tmp_path / "restart.db"
        s1 = Sentinel(offline=True, storage=Storage(db))
        inv = s1.investigate_message("Your KYC is suspended, verify at http://sbi-kyc-update.top/login")
        r1 = s1.make_report(inv["id"])
        s1.commit_report(r1["report_id"])

        s2 = Sentinel(offline=True, storage=Storage(db))
        assert s2.verify_report(r1["report_id"])["status"] == "MATCH"
        r2 = s2.make_report(inv["id"])
        assert r2["report_id"] == r1["report_id"]
        assert len(r2["versions"]) == 2
        assert r2["versions"][-1]["body"]["version"] == 2

    def test_storage_handles_concurrent_writes(self, tmp_path):
        from concurrent.futures import ThreadPoolExecutor
        st = Storage(tmp_path / "concurrent.db")

        def save_one(i: int):
            st.save_investigation({"id": f"inv-{i}", "type": "url", "input": f"https://example{i}.com",
                                   "ts": "2026-11-10T00:00:00+00:00",
                                   "indicators": {("host", f"example{i}.com"): "primary"}, "risk": {"score": i % 100}})
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(save_one, range(24)))
        assert len(st.all_investigations()) == 24

    def test_background_cleanup_uses_utc(self):
        import time
        from app import background
        recent = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        background._jobs["recent-utc-job"] = {"status": "completed", "completed_at": recent}
        background._cleanup_old_jobs()
        assert "recent-utc-job" in background._jobs
        background._jobs.pop("recent-utc-job", None)

    def test_monitoring_list_requires_auth(self):
        from fastapi.routing import APIRoute
        route = next(r for r in app.routes if isinstance(r, APIRoute) and r.path == "/api/v1/monitoring" and "GET" in r.methods)
        assert len(route.dependant.dependencies) == 1
        role_dep = route.dependant.dependencies[0]
        user_dep = role_dep.dependencies[0].call
        with pytest.raises(HTTPException) as unauth:
            user_dep(user=None)
        assert unauth.value.status_code == 401
        with pytest.raises(HTTPException) as forbid:
            role_dep.call(user={"username": "v", "role": "viewer"})
        assert forbid.value.status_code == 403

    def test_correlation_inverted_index_finds_shared_edges(self):
        from datetime import datetime, timezone
        from app.services.correlation import build_edges
        ts = datetime.now(timezone.utc)
        invs = [
            {"id": "a", "ts": ts, "submitter": "u1", "indicators": {("phone", "+919000000001"): "verified", ("host", "evil.top"): "direct"}},
            {"id": "b", "ts": ts, "submitter": "u2", "indicators": {("phone", "+919000000001"): "verified", ("host", "evil.top"): "direct"}},
            {"id": "c", "ts": ts, "submitter": "u3", "indicators": {("host", "unrelated.org"): "direct"}},
        ]
        edges = build_edges(invs)
        assert len(edges) == 1
        assert {edges[0]["a"], edges[0]["b"]} == {"a", "b"}


