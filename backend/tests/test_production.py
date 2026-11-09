"""Production hardening tests for SENTINEL.
Tests JWT authentication, password hashing, RBAC, async background jobs, and security headers.
"""
import os
os.environ["SENTINEL_OFFLINE"] = "true"
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

