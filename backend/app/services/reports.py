"""Module 6: canonical reports, salted SHA-256 commitments, tamper detection, version chain,
and third-party verification bundles.
"""
import hashlib
import json
import os
import time
from typing import Optional, Protocol


def canonical_json(obj) -> bytes:
    """Sorted keys, no whitespace, UTF-8. Floats are rejected (use strings or ints)
    so canonical serialization is deterministic across platforms and languages (RFC 8785 subset).
    """
    def check(o):
        if isinstance(o, float):
            raise ValueError("floats not allowed in canonical reports; use strings or integers")
        if isinstance(o, dict):
            for v in o.values():
                check(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                check(v)

    check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def commitment(report: dict, salt: bytes) -> str:
    """Salted SHA-256 commitment of the canonical JSON report."""
    return "0x" + hashlib.sha256(salt + canonical_json(report)).hexdigest()


def new_salt() -> bytes:
    """16 bytes of cryptographically secure random salt."""
    return os.urandom(16)


class ChainClient(Protocol):
    def commit(self, report_id: str, content_hash: str, category: int) -> dict: ...
    def get_version(self, report_id: str, version: int) -> Optional[dict]: ...


class LocalLedger:
    """Append-only cryptographic ledger simulating the smart contract storage with identical semantics."""
    def __init__(self):
        self.h: dict[str, list[dict]] = {}

    def commit(self, report_id: str, content_hash: str, category: int = 1) -> dict:
        hist = self.h.setdefault(report_id, [])
        prev = hist[-1]["content_hash"] if hist else "0x" + "00" * 32
        tx_hash = "0x" + hashlib.sha256(f"{report_id}:{len(hist)}:{content_hash}:{time.time()}".encode()).hexdigest()
        rec = {
            "version": len(hist) + 1,
            "content_hash": content_hash,
            "prev_hash": prev,
            "category": category,
            "timestamp": int(time.time()),
            "tx_hash": tx_hash,
            "network": "local-ledger-simulation",
            "block": 5821900 + len(hist)
        }
        hist.append(rec)
        return rec

    def get_version(self, report_id: str, version: int) -> Optional[dict]:
        hist = self.h.get(report_id, [])
        return hist[version - 1] if 1 <= version <= len(hist) else None

    def get_all_versions(self, report_id: str) -> list[dict]:
        return list(self.h.get(report_id, []))


def verify(report: dict, salt: bytes, chain: ChainClient, report_id: str, version: int) -> dict:
    """Recomputes salted SHA-256 hash and compares with the on-chain / ledger commitment."""
    try:
        computed = commitment(report, salt)
    except Exception as e:
        return {
            "status": "ERROR",
            "error": f"Failed to compute canonical hash: {e}",
            "version": version
        }

    try:
        rec = chain.get_version(report_id, version)
    except Exception as e:
        return {
            "status": "CHAIN_UNAVAILABLE",
            "computed_hash": computed,
            "version": version,
            "error": str(e)
        }

    if rec is None:
        return {
            "status": "NOT_COMMITTED",
            "computed_hash": computed,
            "version": version,
            "message": f"No on-chain commitment recorded for report {report_id} v{version}."
        }

    status = "MATCH" if rec["content_hash"].lower() == computed.lower() else "MODIFIED"
    return {
        "status": status,
        "version": version,
        "computed_hash": computed,
        "onchain_hash": rec["content_hash"],
        "prev_hash": rec.get("prev_hash"),
        "tx_hash": rec.get("tx_hash"),
        "network": rec.get("network", "ethereum"),
        "block": rec.get("block", 0),
        "timestamp": rec.get("timestamp"),
        "verified_at": int(time.time()),
        "integrity_confirmed": status == "MATCH"
    }


def compute_community_reputation(investigation: dict, peer_investigations: list[dict]) -> dict:
    """PRD Section 22: Community threat reputation based on independent corroboration.
    Weighted sum of distinct submitters sharing high-specificity indicators.
    """
    my_inds = set(investigation.get("indicators", {}).keys())
    high_spec_types = {"payment_id", "phone", "email", "spki", "cert"}
    
    distinct_submitters = set()
    corroborating_invs = []
    
    for peer in peer_investigations:
        if peer.get("id") == investigation.get("id"):
            continue
        peer_inds = set(peer.get("indicators", {}).keys())
        shared_high = {k for k in (my_inds & peer_inds) if k[0] in high_spec_types}
        if shared_high:
            sub = peer.get("submitter", "anon")
            distinct_submitters.add(sub)
            corroborating_invs.append({
                "investigation_id": peer["id"],
                "submitter": sub,
                "shared": [f"{t}:{v}" for t, v in shared_high]
            })

    # Reputation score 0-100: starts at 50 (neutral), rises with independent corroboration up to 100
    corroboration_count = min(len(distinct_submitters), 5)
    trusted_feed_hit = (investigation.get("risk", {}).get("class") == "confirmed_malicious")
    
    score = 50 + (corroboration_count * 8) + (10 if trusted_feed_hit else 0)
    score = min(100, score)
    
    return {
        "reputation_score": score,
        "independent_corroborators": len(distinct_submitters),
        "corroboration_evidence": corroborating_invs[:5],
        "status": "high_confidence" if score >= 75 else "moderate" if score >= 50 else "unverified"
    }
