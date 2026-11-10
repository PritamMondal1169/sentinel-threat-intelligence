# SENTINEL

**AI-Powered Web Threat Detection & Digital Trust Intelligence Platform**

SENTINEL is a unified threat investigation and digital trust platform built with FastAPI, SQLite, and a browser-based Security Operations Center (SOC) dashboard. Submissions—URLs, domains, emails, SMS/chat messages, or owned websites—flow through a single **Investigation Orchestrator** that executes six analysis engines, persists normalized indicators in SQLite, correlates related infrastructure into threat campaigns, and produces cryptographically verifiable forensic reports.

---

## Core Capabilities

| Engine | What It Does |
|---|---|
| **1. URL & Domain Intelligence** | RFC 8785 URL canonicalization, boundary-aware brand impersonation detection, homoglyph/typosquatting analysis (confusable skeletons + Damerau-Levenshtein), punycode & mixed-script checks, DNS lookups (`A`/`AAAA`/`NS`/`MX`/`TXT`/`CNAME`), RDAP domain age, SSRF IP-pinning guards, redirect tracing, and multi-feed threat checks (`LocalBlocklist`, `OpenPhish`, `PhishTank`, `URLhaus`, `Google Safe Browsing`, `VirusTotal`) with offline snapshot fallback. |
| **2. TLS Certificate & PKI Analytics** | Dual-mode TLS handshake inspection, validity & chain checks, hostname mismatch and self-signed detection, SHA-256 / SPKI fingerprints, and Certificate Transparency (`crt.sh`) sibling-domain & SAN discovery. |
| **3. Multilingual Scam DNA (`Sentinel-ML`)** | Zero-paid-API on-device NLP and lexical analysis supporting English, Hindi, Bengali, and Malayalam; deterministic extraction of E.164 phone numbers, UPI IDs, emails, URLs, and IFSC codes; MinHash template clustering; and prompt-injection containment (plus optional `GeminiLLMProvider` integration when configured). |
| **4. Threat Correlation & Scam Radar** | Inverted-index graph construction over normalized indicators with inverse-document-frequency uniqueness weighting ($u = 1 / \log_2(2 + df)$), CDN/CA noise caps, campaign clustering without weak-link chaining, and 3-sigma surge detection. |
| **5. Attack Surface & DNS Monitoring** | Passive security posture grading (`A`–`F`) across HTTP security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`), TLS versions, and DNS auth records (`SPF`, `DMARC`, `CAA`, `DNSSEC`) with copy-paste remediations and domain monitoring subscriptions. |
| **6. Tamper-Evident Forensic Reporting** | RFC 8785 canonical JSON serialization, salted SHA-256 report commitments, version chaining persisted in SQLite, independent JSON proof-bundle export, `LocalLedger` verification, and an optional EVM smart contract (`contracts/ReportRegistry.sol`). |

---

## Security & Architecture Design

- **Deterministic Verification First**: AI analysis explains social-engineering tactics and extracts signals, while deterministic evidence governs `"confirmed malicious"` risk classifications.
- **Explicit Degraded States**: External feeds without live API keys or network reachability report `"unavailable"` on cache misses rather than false `"clean"` verdicts; unbroadcast chain commits report `"simulated_unbroadcast"`.
- **Authentication & RBAC**: HMAC-SHA256 JWT tokens, PBKDF2-SHA256 (`100,000` iterations) password hashing, and role enforcement (`admin`, `analyst`, `viewer`) across investigation, monitoring, reporting, and user-management routes.
- **Thread-Safe Storage**: Reentrant locking (`threading.RLock`) with explicit SQLite transactions (`BEGIN` / `COMMIT` / `ROLLBACK`) and WAL journaling.

---

## Web Dashboard & API

The FastAPI server serves the unified SOC web UI at `/` and interactive OpenAPI documentation at `/docs` and `/redoc`, covering:

- Universal Threat Intake (URL & multilingual message triage)
- SOC Command Center & Investigation Audit Trail (CSV/JSON export)
- URL Intelligence, DNS/RDAP Dossiers & Certificate/PKI Views
- Scam DNA Visualizer, Interactive Correlation Graph & Campaign Clusters
- 3-Sigma Emerging Threat Radar & Domain Attack Surface Grading
- Forensic Report Proof Audit, Registry Explorer & Admin/RBAC Settings

---

## Correlation Benchmark

Evaluated against a synthetic benchmark of 40 investigations spanning 8 campaigns and 10 shared-infrastructure distractors (`backend/app/evaluation.py`):

| Metric | Result |
|---|---|
| Precision | **100.0%** |
| Recall | **76.9%** |
| F1 Score | **0.869** |
| Cluster Purity | **100.0%** |
| False Positives | **0** |

Run locally from `backend/`:

```bash
python -m app.evaluation
```

---

## Getting Started (Local)

### 1. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp ../.env.example .env
```

Set strong values for `SENTINEL_JWT_SECRET`, `SENTINEL_ADMIN_PASSWORD`, and `SENTINEL_ANALYST_PASSWORD` before exposing the service publicly. SENTINEL works out of the box with zero paid API keys using on-device `Sentinel-ML` and open feeds/caches.

### 3. Run the Server

```bash
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
```

Open `http://127.0.0.1:8000` in your browser.

---

## Testing & Health Checks

Run the full backend test suite (`103 passed, 15 subtests passed`):

```bash
pytest backend/tests -v
```

Probe a running instance:

```bash
python scripts/healthcheck.py http://127.0.0.1:8000/health
```

---

## Deployment

- **Docker Compose (with Nginx reverse proxy)**:
  ```bash
  docker compose up --build -d
  ```
  Wait for `/health` and access via `http://localhost` (terminate TLS in front of Nginx for internet-facing deployments).
- **Cloud Containers (Railway / Render)**:
  Use the root [Dockerfile](Dockerfile) or [render.yaml](render.yaml). Mount persistent storage at `/app/data` (`SENTINEL_DB_PATH=/app/data/sentinel.db`) and keep Uvicorn at `--workers 1` / single replica while using SQLite persistence.

---

## Project Layout

```text
.
├── backend/
│   ├── app/
│   │   ├── core/          # SSRF guards, URL/phone normalizers, safe HTTP
│   │   ├── db/            # Transactional SQLite storage engine
│   │   ├── services/      # Feeds, TLS, crt.sh, DNS/RDAP, AI, correlation, reports
│   │   ├── auth.py        # JWT + PBKDF2 authentication and RBAC
│   │   ├── main.py        # FastAPI application and REST routes
│   │   └── orchestrator.py
│   ├── data/              # Local threat intelligence caches & SQLite DB path
│   ├── static/            # Single-page SOC dashboard
│   ├── tests/             # Unit, API, benchmark, AI, and production safety tests
│   └── requirements.txt
├── contracts/             # ReportRegistry.sol EVM registry contract
├── nginx/                 # Reverse proxy & rate-limit configuration
├── scripts/               # Deployment & healthcheck scripts
├── Dockerfile
├── docker-compose.yml
└── render.yaml
```
