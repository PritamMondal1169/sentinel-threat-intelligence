# SENTINEL – AI-Powered Web Threat Detection & Digital Trust Intelligence Network

> **Enterprise Production Implementation** · Compliant with PRD Version 1.0

SENTINEL is one unified threat intelligence and digital trust platform, not six isolated tools. Users submit URLs, domains, emails, SMS text or websites they own. Each submission passes through a single **Investigation Orchestrator** that executes the six modules, writes normalised indicators into a persistent SQLite store, and feeds a central **Scam DNA Engine**. The engine compares multi-dimensional fingerprints against past investigations, builds an interactive **Threat Intelligence Graph**, and clusters evidence into *potential campaigns* with explainable confidence scores. Finished reports are canonicalised (RFC 8785), hashed (salted SHA-256) and committed to an EVM testnet (`ReportRegistry.sol`) so that anyone can independently verify that a report was not altered.

---

## Architecture Principles

- **Deterministic checks decide; AI assists.** The LLM extracts and explains social engineering tactics, but never decides "confirmed malicious".
- **Similarity is evidence of a possible relationship, never proof of a common attacker.**
- **Blockchain proves integrity and ordering, not threat truth.**
- **Every external API sits behind an adapter with a fallback**, guaranteeing the system and offline operations never break.
- **Enterprise Role-Based Access Control (RBAC).** Hardened JWT tokens with PBKDF2 password hashing safeguard SOC actions, user provisioning, and on-chain commitments.

---

## The Six Completed Modules

| # | Module | Status | Capabilities |
|---|---|---|---|
| **1** | **Intelligent URL & Website Analysis** | **Complete** | Canonicalisation (RFC 8785), boundary-aware brand impersonation recognition across global banking, cloud, crypto, and shipping targets; homoglyphs/typosquatting via confusable skeletons and Damerau-Levenshtein; punycode/mixed-script detection; DNS records (A/AAAA/NS/MX/TXT/CNAME); RDAP domain age; SSRF guard with pinned IP connect; safe redirect hops; 6 multi-tier feeds (Local blocklist, OpenPhish, Google Safe Browsing, abuse.ch URLhaus, PhishTank, VirusTotal) with offline snapshots; and Adaptive URL DNA feature vectors. |
| **2** | **TLS Certificate & Web Trust Analysis** | **Complete** | Double-handshake inspection (verified for error analysis, unverified for DER parsing), expiry, hostname mismatch, self-signed detection, chain invalidity, SHA-256 and SPKI hashes, crt.sh Certificate Transparency integration (sibling certs & co-listed SANs), and persistent Digital Trust Timeline. |
| **3** | **AI-Powered Scam & Message Analysis** | **Complete** | Deterministic indicator extraction (E.164 phones, UPI IDs, emails, URLs, IFSC), script detection across English, Hindi, Bengali, Malayalam, multilingual lexicons, MinHash template fingerprinting, prompt injection containment, Google Gemini API provider (`GeminiLLMProvider`) with temperature 0, strict schema validation, and verbatim evidence verification. |
| **4** | **Intelligent Threat Correlation (Flagship)** | **Complete** | Normalised indicator store, uniqueness weighting ($u = 1 / \log_2(2+df)$ with CDN/CA caps), pairwise confidence ($C = (1-\prod(1-e)) \times T \times I$), campaign clustering without weak-link chaining, Emerging Scam Radar (surge alerts, 3-sigma anomaly detection, baseline tracking), and interactive Threat Graph. |
| **5** | **Website Security Assessment & Monitoring** | **Complete** | Passive audit of HTTP/HTTPS headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Secure cookies), TLS protocol version checks, DNS security records (SPF, DMARC, CAA, DNSSEC), risk-based remediation code snippets, posture diffs, and continuous monitoring subscriptions. |
| **6** | **Decentralized Threat Intelligence** | **Complete** | Canonical JSON serialisation (RFC 8785 subset), salted SHA-256 commitments, version chaining, `ReportRegistry.sol` EVM smart contract, Web3 client (`EVMChainClient`) with `LocalLedger` fallback, independent verification bundle export, and community threat reputation scoring. |

---

## 14-Screen Enterprise SOC Dashboard (PRD Section 23)

The web dashboard is served directly by FastAPI at `/` and implements all 14 screens specified in the PRD:
1. **Universal Threat Intake:** Unified input for URLs or messages with enterprise scenario loaders.
2. **Security Operations Center (Command Center):** Real-time SOC dashboard, risk breakdowns, category distributions, and triage feeds.
3. **URL & Web Intelligence:** Structural flags, DNS table, redirect hops, feed badges, and risk driver charts.
4. **Certificate & PKI Analytics:** Validity bars, chain inspector, mismatch warnings, and CT log sibling domains.
5. **Scam DNA & Message Engine:** Multilingual badge (EN, HI, BN, ML), highlighted evidence, extracted chips, precautions.
6. **Threat Correlation Graph:** Interactive node-link canvas (zoom, pan, drag, confidence threshold slider, edge filtering, and detail inspection drawer).
7. **Threat Campaign Intelligence:** Clustered threat campaigns, independent submitters, member IDs, shared indicator types.
8. **Emerging Threat Radar:** 3-sigma anomaly alerts, domain surges, reused UPI destinations, and baseline tracking.
9. **Attack Surface & DNS Assessment:** Security grade (A-F), categorized findings with copy-paste remediation snippets.
10. **Domain Profile Explorer:** Full domain dossier, DNS records, CT log history, and related past investigations.
11. **Decentralized Threat Registry:** On-chain committed reports, transaction hashes, and block numbers.
12. **Forensic Threat Report:** Formatted canonical JSON, salt commitment, and JSON proof bundle export.
13. **Cryptographic Proof Audit:** Real-time hash recalculation and standalone proof bundle download.
14. **Investigation Audit Trail:** Filterable historical database with CSV/JSON export.
15. **System Settings & Adapters:** Live adapter monitor, masked API keys, and **Enterprise User & RBAC Management Console** (user provisioning and password updates).

---

## Benchmarks & Evaluation (PRD Section 25)

The correlation engine was evaluated on a synthetic ground-truth benchmark of 40 investigations across 8 distinct fraud campaigns plus 10 hard distractors (shared Cloudflare CDN IPs, shared Let's Encrypt CAs):

```bash
python -m sentinel.backend.app.evaluation
```

| Metric | Target (PRD §25) | Achieved Result |
|---|---|---|
| **Precision** | $\ge 90.0\%$ | **100.0%** |
| **Recall** | $\ge 70.0\%$ | **76.9%** |
| **F1 Score** | — | **0.869** |
| **Cluster Purity** | — | **100.0%** |
| **False Positives** | 0 | **0** |

---

## Getting Started

### 1. Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp .env.example .env
```
*(SENTINEL runs out of the box with zero configuration! Set `SENTINEL_OFFLINE=false` for live public feeds, and optionally add `GEMINI_API_KEY` for LLM analysis.)*

### 3. Run the Dashboard
```bash
cd backend
uvicorn app.main:app --port 8000
```
Open **[http://localhost:8000](http://localhost:8000)** in your browser.

### 4. Default Enterprise Credentials
- **Administrator**: `admin` / `changeme123` *(Full access to user provisioning, settings, and on-chain anchoring)*
- **Security Analyst**: `analyst` / `analyst123` *(Investigation triage, graph exploration, and report generation)*

### 5. Run the Full Test Suite
```bash
pytest backend/tests -v
```
*All 79 unit, integration, and security benchmark tests run in ~1.5 seconds.*

---

## Docker & Cloud Deployment

### Local Docker Compose
```bash
docker compose up --build -d
```
Access the service via Nginx reverse proxy at `http://localhost:80`.

### 1-Click Cloud Deployment (Render / Railway)
The project includes `render.yaml` configured for instant deployment with persistent disk storage (`/app/backend/data`), automatic TLS, and production worker pools.
