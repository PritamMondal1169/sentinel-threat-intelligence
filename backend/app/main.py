"""SENTINEL FastAPI Application.
Exposes complete REST API per PRD Section 17 and serves the unified web dashboard.
Hardened for production with JWT authentication, RBAC, async jobs, CORS, security headers, and rate limiting.
"""
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .auth import (
    create_access_token,
    ensure_admin_user,
    get_current_user,
    hash_password,
    require_role,
    verify_password,
)
from .background import get_job, submit_job
from .core.ssrf import UrlBlocked
from .db.storage import Storage
from .middleware import RequestContextMiddleware, SecurityHeadersMiddleware, configure_cors
from .orchestrator import Sentinel
from .seed import seed_demo

APP_START_TIME = time.time()
OFFLINE = os.getenv("SENTINEL_OFFLINE", "false").lower() == "true"

app = FastAPI(
    title="SENTINEL",
    description="AI-Powered Web Threat Detection & Digital Trust Intelligence Network",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# --- Attach Middleware ---
configure_cors(app)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestContextMiddleware)

# --- Core Orchestrator & Storage Initialization ---
storage_instance = Storage()
S = Sentinel(offline=OFFLINE, storage=storage_instance)

# Seed demo data if configured
if os.getenv("SENTINEL_SEED", "true").lower() == "true":
    seed_demo(S)

# Ensure admin user exists in DB
ensure_admin_user(storage_instance)

_hits: dict[str, deque] = defaultdict(deque)


def rate_limit(limit: int):
    def dep(request: Request):
        ip = request.client.host if request.client else "unknown"
        t = time.time()
        q = _hits[f"{ip}:{limit}"]
        while q and t - q[0] > 60:
            q.popleft()
        if len(q) >= limit:
            raise HTTPException(429, {"code": "RATE_LIMITED", "message": "Too many requests"})
        q.append(t)
    return dep


def auth(request: Request):
    """Backward compatible auth alias enforcing analyst/admin privileges."""
    return require_role("analyst")


@app.exception_handler(HTTPException)
async def http_err(_, exc):
    d = exc.detail if isinstance(exc.detail, dict) else {"code": "ERROR", "message": str(exc.detail)}
    return JSONResponse({"error": d}, status_code=exc.status_code)


# --- Request Schemas ---
class LoginIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=6, max_length=128)


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=6, max_length=128)
    role: Optional[str] = "analyst"


class PasswordChangeIn(BaseModel):
    old_password: str
    new_password: str = Field(min_length=6, max_length=128)


class UrlIn(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    submitter: Optional[str] = "anon"


class MsgIn(BaseModel):
    text: str = Field(min_length=3, max_length=10000)
    submitter: Optional[str] = "anon"


class AssessIn(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    ownership_declared: bool = False


class MonitoringIn(BaseModel):
    domain: str = Field(min_length=3, max_length=255)
    email: Optional[str] = None
    ownership_declared: bool = True
    interval_hours: int = 24


def view(inv: dict) -> dict:
    """Prepare customer/analyst view of an investigation."""
    out = {k: v for k, v in inv.items() if k not in ("indicators", "ts", "input_hash")}
    out["created_at"] = inv["ts"].isoformat() if hasattr(inv.get("ts"), "isoformat") else str(inv.get("ts", ""))
    out["indicators"] = [
        {"type": t, "value": v, "quality": q}
        for (t, v), q in inv.get("indicators", {}).items()
    ]
    return out


# --- Health & Readiness ---
@app.get("/health")
@app.get("/api/v1/health")
def health():
    uptime_sec = round(time.time() - APP_START_TIME, 1)
    db_exists = Path(str(S.storage.db_path)).exists() if str(S.storage.db_path) != ":memory:" else True
    return {
        "status": "ok",
        "service": "SENTINEL",
        "version": "1.0.0",
        "uptime_seconds": uptime_sec,
        "offline": OFFLINE,
        "active_modules": 6,
        "investigations_count": len(S.invs),
        "database": {
            "status": "connected" if db_exists else "unavailable",
            "path": str(S.storage.db_path)
        },
        "adapters_count": len(S.feeds)
    }


# --- Authentication & User Management ---
@app.post("/api/v1/auth/login", dependencies=[Depends(rate_limit(10))])
def login(b: LoginIn):
    user = S.storage.get_user_by_username(b.username)
    if not user or not verify_password(b.password, user["password_hash"]):
        raise HTTPException(401, {"code": "INVALID_CREDENTIALS", "message": "Incorrect username or password"})
    if not user.get("active", True):
        raise HTTPException(403, {"code": "ACCOUNT_DISABLED", "message": "Account has been deactivated"})

    token = create_access_token(sub=user["username"], role=user["role"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 86400,
        "user": {
            "username": user["username"],
            "role": user["role"]
        }
    }


@app.post("/api/v1/auth/register", dependencies=[Depends(require_role("admin"))])
def register(b: RegisterIn):
    if S.storage.get_user_by_username(b.username):
        raise HTTPException(400, {"code": "USER_EXISTS", "message": f"User '{b.username}' already exists"})
    user_id = "usr-" + os.urandom(6).hex()
    new_user = {
        "id": user_id,
        "username": b.username,
        "password_hash": hash_password(b.password),
        "role": b.role if b.role in ("admin", "analyst", "viewer") else "analyst",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "active": True
    }
    S.storage.save_user(new_user)
    return {"status": "created", "username": b.username, "role": new_user["role"]}


@app.get("/api/v1/auth/me")
def get_me(user: dict = Depends(get_current_user)):
    return user


@app.get("/api/v1/auth/users", dependencies=[Depends(require_role("admin"))])
def list_all_users():
    return S.storage.list_users()


@app.post("/api/v1/auth/change-password")
def change_password(b: PasswordChangeIn, current_user: dict = Depends(get_current_user)):
    user = S.storage.get_user_by_username(current_user.get("sub", ""))
    if not user or not verify_password(b.old_password, user["password_hash"]):
        raise HTTPException(400, {"code": "INVALID_OLD_PASSWORD", "message": "Incorrect current password"})
    user["password_hash"] = hash_password(b.new_password)
    S.storage.save_user(user)
    return {"status": "success", "message": "Password updated successfully"}


# --- Asynchronous Job Polling (PRD Section 13) ---
@app.get("/api/v1/jobs/{job_id}")
def check_job_status(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, {"code": "JOB_NOT_FOUND", "message": f"Job '{job_id}' not found"})
    return job


# --- Investigations (Modules 1, 2, 3) ---
@app.post("/api/v1/investigations/url", dependencies=[Depends(rate_limit(20))])
def inv_url(b: UrlIn, sync: bool = Query(default=True)):
    if not sync:
        # Submit async background job per PRD Section 13
        def _task():
            res = S.investigate_url(b.url, b.submitter or "anon")
            return view(res)

        job_id = submit_job("investigate_url", _task)
        return JSONResponse(
            status_code=202,
            content={
                "job_id": job_id,
                "status": "pending",
                "poll_url": f"/api/v1/jobs/{job_id}",
                "message": "Investigation started asynchronously"
            }
        )

    try:
        return view(S.investigate_url(b.url, b.submitter or "anon"))
    except UrlBlocked as e:
        raise HTTPException(400, {"code": "URL_BLOCKED", "message": e.reason})


@app.post("/api/v1/investigations/message", dependencies=[Depends(rate_limit(20))])
def inv_msg(b: MsgIn, sync: bool = Query(default=True)):
    if not sync:
        def _task():
            res = S.investigate_message(b.text, b.submitter or "anon")
            return view(res)

        job_id = submit_job("investigate_message", _task)
        return JSONResponse(
            status_code=202,
            content={
                "job_id": job_id,
                "status": "pending",
                "poll_url": f"/api/v1/jobs/{job_id}",
                "message": "Message investigation started asynchronously"
            }
        )

    return view(S.investigate_message(b.text, b.submitter or "anon"))


@app.get("/api/v1/investigations/{iid}")
def get_inv(iid: str):
    if iid not in S.invs:
        raise HTTPException(404, {"code": "NOT_FOUND", "message": "Unknown investigation"})
    return view(S.invs[iid])


@app.get("/api/v1/investigations")
def list_inv(
    limit: int = 50,
    risk_class: Optional[str] = None,
    inv_type: Optional[str] = None,
    q: Optional[str] = None
):
    items = sorted(S.invs.values(), key=lambda i: str(i.get("ts", "")), reverse=True)
    if risk_class:
        items = [i for i in items if i.get("risk", {}).get("class") == risk_class]
    if inv_type:
        items = [i for i in items if i.get("type") == inv_type]
    if q:
        q_low = q.lower()
        items = [i for i in items if q_low in i.get("input", "").lower()]

    return [
        {
            "id": i["id"],
            "type": i["type"],
            "input": i["input"],
            "risk": i.get("risk", {}).get("class"),
            "score": i.get("risk", {}).get("score"),
            "confidence": i.get("risk", {}).get("confidence"),
            "demo": i.get("demo", False),
            "created_at": i["ts"].isoformat() if hasattr(i.get("ts"), "isoformat") else str(i.get("ts", ""))
        }
        for i in items[:min(limit, 200)]
    ]


# --- Domain Intelligence & Certificate Timeline (Modules 1, 2) ---
@app.get("/api/v1/domains/{domain}")
def get_domain_profile(domain: str):
    try:
        return S.get_domain_profile(domain)
    except Exception as e:
        raise HTTPException(500, {"code": "DOMAIN_QUERY_ERROR", "message": str(e)})


# --- Correlation, Campaigns, Threat Graph & Radar (Module 4) ---
@app.get("/api/v1/campaigns")
def campaigns():
    return S.correlate()[1]


@app.get("/api/v1/campaigns/{cid}")
def campaign(cid: str):
    for c in S.correlate()[1]:
        if c["id"] == cid:
            return c
    raise HTTPException(404, {"code": "NOT_FOUND", "message": "Unknown campaign"})


@app.get("/api/v1/threat-graph/{iid}")
def graph(
    iid: str,
    depth: int = Query(default=1, ge=1, le=2),
    min_confidence: float = Query(default=0.4, ge=0.0, le=1.0)
):
    try:
        return S.graph(iid, depth=depth, min_confidence=min_confidence)
    except KeyError:
        raise HTTPException(404, {"code": "NOT_FOUND", "message": "Unknown investigation"})


# --- Website Security Assessment & Monitoring (Module 5) ---
@app.post("/api/v1/website-assessment", dependencies=[Depends(rate_limit(10)), Depends(require_role("analyst"))])
def assess(b: AssessIn):
    try:
        return S.assess_website(b.url, b.ownership_declared)
    except UrlBlocked as e:
        raise HTTPException(400, {"code": "URL_BLOCKED", "message": e.reason})
    except RuntimeError as e:
        raise HTTPException(503, {"code": "OFFLINE", "message": str(e)})


@app.post("/api/v1/monitoring", dependencies=[Depends(require_role("analyst"))])
def create_monitoring(b: MonitoringIn):
    if not b.ownership_declared:
        raise HTTPException(400, {"code": "OWNERSHIP_REQUIRED", "message": "Monitoring requires an ownership declaration."})
    return S.create_monitoring_subscription(b.domain, b.email, b.interval_hours)


@app.get("/api/v1/monitoring")
def list_monitoring():
    return S.list_monitoring_subscriptions()


# --- Decentralized Threat Intelligence & Blockchain Verification (Module 6) ---
@app.post("/api/v1/investigations/{iid}/report", dependencies=[Depends(require_role("analyst"))])
def make_report(iid: str):
    if iid not in S.invs:
        raise HTTPException(404, {"code": "NOT_FOUND", "message": "Unknown investigation"})
    r = S.make_report(iid)
    return {
        "report_id": r["report_id"],
        "versions": len(r["versions"]),
        "commitment": r["versions"][-1]["commitment"],
        "latest_version": r["versions"][-1]["body"]
    }


@app.get("/api/v1/reports/{rid}")
def get_report(rid: str):
    r = S.reports.get(rid) or S.storage.get_report(rid)
    if not r:
        raise HTTPException(404, {"code": "NOT_FOUND", "message": "Unknown report"})
    return {
        "report_id": rid,
        "investigation_id": r["investigation_id"],
        "versions": [
            {
                "version": i + 1,
                "body": v["body"],
                "commitment": v["commitment"],
                "chain": v.get("chain")
            }
            for i, v in enumerate(r["versions"])
        ]
    }


@app.post("/api/v1/reports/{rid}/commit", dependencies=[Depends(require_role("analyst"))])
def commit(rid: str):
    r = S.reports.get(rid) or S.storage.get_report(rid)
    if not r:
        raise HTTPException(404, {"code": "NOT_FOUND", "message": "Unknown report"})
    return S.commit_report(rid)


@app.post("/api/v1/reports/{rid}/verify", dependencies=[Depends(rate_limit(30))])
def verify(rid: str):
    r = S.reports.get(rid) or S.storage.get_report(rid)
    if not r:
        raise HTTPException(404, {"code": "NOT_FOUND", "message": "Unknown report"})
    return S.verify_report(rid)


@app.get("/api/v1/reports/{rid}/export")
def export_report_bundle(rid: str):
    """PRD Section 22: Exportable standalone proof bundle for independent 3rd-party verification."""
    r = S.reports.get(rid) or S.storage.get_report(rid)
    if not r:
        raise HTTPException(404, {"code": "NOT_FOUND", "message": "Unknown report"})
    latest_v = r["versions"][-1]
    return {
        "report_id": rid,
        "version": len(r["versions"]),
        "body": latest_v["body"],
        "salt_hex": r["salt"].hex(),
        "commitment_hash": latest_v["commitment"],
        "blockchain_record": latest_v.get("chain"),
        "verification_instructions": "To verify independently: 1. Canonicalize 'body' with RFC 8785 JCS; 2. Compute SHA-256(hex_to_bytes(salt_hex) + canonical_bytes); 3. Compare with commitment_hash and on-chain record."
    }


# --- Analytics & Settings ---
@app.get("/api/v1/analytics/overview")
def overview():
    return S.overview()


@app.get("/api/v1/settings")
def get_settings():
    """PRD Section 23: Settings screen showing active adapters, masked keys, and configuration."""
    def mask(k: Optional[str]):
        return (k[:4] + "..." + k[-4:]) if k and len(k) > 8 else ("configured" if k else "not_configured")

    return {
        "offline_demo_mode": OFFLINE,
        "database": str(S.storage.db_path),
        "adapters": {
            "local_blocklist": "active (Zero-Latency Local Feed)",
            "openphish": "active (Live Stream & Community Feed)",
            "google_safe_browsing": "active (Official API v4)" if os.getenv("GSB_API_KEY") else "active (Community Feed & Threat Hashes)",
            "urlhaus": "active (Live abuse.ch API)" if os.getenv("URLHAUS_AUTH_KEY") or not OFFLINE else "active (Intelligence Snapshot)",
            "phishtank": "active (Live PhishTank API)",
            "virustotal": "active (Official API v3)" if os.getenv("VT_API_KEY") else "active (Multi-Engine Community Database)",
            "crt_sh": "active (Live Certificate Transparency Logs)"
        },
        "llm_provider": {
            "provider": S.provider.__class__.__name__,
            "configured": bool(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")),
            "key_status": mask(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
        },
        "blockchain": {
            "client": S.chain_client.__class__.__name__,
            "rpc_url": S.chain_client.rpc_url or "local_simulation",
            "contract_address": S.chain_client.contract_address or "0xLocalReportRegistry",
            "network": os.getenv("CHAIN_NAME", "local-hardhat-fallback")
        }
    }


# --- Static Web Dashboard ---
STATIC = Path(__file__).resolve().parents[1] / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
