"""Authentication and RBAC Module for SENTINEL.
Provides JWT-based authentication, PBKDF2 password hashing, and role-based access control.
Uses Python standard libraries (hmac, hashlib, base64, json) for 100% dependency-free reliability.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from typing import Optional

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .db.storage import Storage

logger = logging.getLogger("sentinel.auth")

DEFAULT_SECRET = os.getenv("SENTINEL_JWT_SECRET") or "sentinel-prod-jwt-secret-key-change-in-env-file-98341"
JWT_EXPIRATION_SECONDS = int(os.getenv("SENTINEL_JWT_EXPIRE_SECONDS", "86400"))  # 24 hours
ROLE_HIERARCHY = {"admin": 3, "analyst": 2, "viewer": 1}

security_bearer = HTTPBearer(auto_error=False)


# --- Cryptographic Helpers ---
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = 4 - (len(s) % 4)
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s.encode("ascii"))


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return f"pbkdf2_sha256$100000${salt}${pwd_hash.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        parts = hashed_password.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = parts[2]
        expected_hash = parts[3]
        calc = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), iterations)
        return hmac.compare_digest(calc.hex(), expected_hash)
    except Exception:
        return False


# --- JWT Implementation ---
def create_access_token(sub: str, role: str = "viewer", expires_in: int = JWT_EXPIRATION_SECONDS) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": sub,
        "role": role,
        "iat": now,
        "exp": now + expires_in,
        "jti": str(uuid.uuid4())
    }
    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
    sig = hmac.new(DEFAULT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{h_b64}.{p_b64}.{sig_b64}"


def verify_token(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(401, {"code": "INVALID_TOKEN", "message": "Malformed JWT token"})
    h_b64, p_b64, sig_b64 = parts
    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
    expected_sig = hmac.new(DEFAULT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        sig = _b64url_decode(sig_b64)
    except Exception:
        raise HTTPException(401, {"code": "INVALID_TOKEN", "message": "Invalid token encoding"})
    if not hmac.compare_digest(sig, expected_sig):
        raise HTTPException(401, {"code": "INVALID_SIGNATURE", "message": "Token signature mismatch"})

    try:
        payload = json.loads(_b64url_decode(p_b64).decode("utf-8"))
    except Exception:
        raise HTTPException(401, {"code": "INVALID_PAYLOAD", "message": "Could not decode payload"})

    now = int(time.time())
    if payload.get("exp", 0) < now:
        raise HTTPException(401, {"code": "TOKEN_EXPIRED", "message": "Token has expired"})

    return payload


# --- FastAPI Auth Dependencies ---
def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)
) -> Optional[dict]:
    # Check Bearer token first
    token = None
    if credentials:
        token = credentials.credentials
    elif "authorization" in request.headers:
        auth_hdr = request.headers["authorization"]
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()

    if token:
        try:
            return verify_token(token)
        except HTTPException:
            pass

    # Check X-API-Key fallback
    api_key = os.getenv("SENTINEL_API_KEY")
    client_key = request.headers.get("x-api-key")
    if api_key and client_key == api_key:
        return {"sub": "api-key-client", "role": "admin", "auth_method": "api_key"}

    return None


def get_current_user(user: Optional[dict] = Depends(get_current_user_optional)) -> dict:
    if not user:
        # If no auth configured and no token, allow anon viewer in non-strict mode
        if not os.getenv("SENTINEL_API_KEY") and not os.getenv("SENTINEL_REQUIRE_AUTH"):
            return {"sub": "anon", "role": "analyst", "auth_method": "open_access"}
        raise HTTPException(401, {"code": "UNAUTHORIZED", "message": "Authentication required"})
    return user


def require_role(min_role: str):
    min_level = ROLE_HIERARCHY.get(min_role, 1)

    def dependency(user: dict = Depends(get_current_user)) -> dict:
        user_role = user.get("role", "viewer")
        user_level = ROLE_HIERARCHY.get(user_role, 1)
        if user_level < min_level:
            raise HTTPException(403, {
                "code": "FORBIDDEN",
                "message": f"Operation requires '{min_role}' privileges (your role: '{user_role}')"
            })
        return user

    return dependency


def ensure_admin_user(storage: Storage):
    """Ensure default admin and analyst accounts exist in DB."""
    admin_user = storage.get_user_by_username("admin")
    if not admin_user:
        pwd = os.getenv("SENTINEL_ADMIN_PASSWORD", "changeme123")
        storage.save_user({
            "id": "usr-admin-01",
            "username": "admin",
            "password_hash": hash_password(pwd),
            "role": "admin",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "active": True
        })
        logger.info("Created initial admin user (username: admin)")

    analyst_user = storage.get_user_by_username("analyst")
    if not analyst_user:
        storage.save_user({
            "id": "usr-analyst-01",
            "username": "analyst",
            "password_hash": hash_password("analyst123"),
            "role": "analyst",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "active": True
        })
        logger.info("Created initial analyst user (username: analyst)")

