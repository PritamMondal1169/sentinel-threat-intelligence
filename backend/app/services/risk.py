"""Transparent, deterministic risk engine. The LLM can only influence the 'message' dimension (capped)."""
import statistics

WEIGHTS = {"threat_intel": .35, "url": .15, "ai_ml": .15, "tls": .10, "message": .15, "security": .05, "correlation": .20}


def assess(dims: dict, trusted_hits: int = 0, independent_sources: int = 0, allowlisted: bool = False) -> dict:
    """dims: {name: (score 0-100, confidence 0-1)}; omitted dimensions do not apply."""
    used = {k: v for k, v in dims.items() if k in WEIGHTS}
    if allowlisted and "url" in used:
        used["url"] = (used["url"][0] / 2, used["url"][1])
    if "security" in used:
        used["security"] = (min(used["security"][0], 10), used["security"][1])  # hygiene never means malice

    url_score = used.get("url", (0, 0))[0]
    ai_score = used.get("ai_ml", (0, 0))[0]

    num = sum(WEIGHTS[k] * c * s for k, (s, c) in used.items())
    den = sum(WEIGHTS[k] * c for k, (s, c) in used.items())
    applicable = sum(WEIGHTS[k] for k in used) or 1.0
    coverage = round(den / applicable, 3)
    score = round(num / den, 1) if den else 0.0

    # Ensure affirmative zero-day URL heuristics & AI lexical/semantic signals are not diluted
    # by valid TLS certs or unlisted feed caches. AI alone never sets 'confirmed_malicious'.
    if not allowlisted and trusted_hits == 0:
        if url_score >= 25:
            score = round(max(score, url_score * 0.92), 1)
        if ai_score >= 48:
            score = round(max(score, ai_score * 0.85), 1)

    spread = statistics.pstdev([s for s, _ in used.values()]) if len(used) > 1 else 0.0
    confidence = round(coverage * (1 - spread / 100), 3)

    if coverage < .40 and trusted_hits == 0 and url_score < 28 and ai_score < 48:
        cls = "inconclusive"
    elif score >= 55:
        cls = "high_risk"
    elif score >= 25:
        cls = "suspicious"
    else:
        cls = "low_risk"

    if trusted_hits >= 1 and cls in ("low_risk", "suspicious", "inconclusive"):
        cls = "high_risk"
    if (trusted_hits >= 1 or independent_sources >= 2) and score >= 55:
        cls = "confirmed_malicious"

    drivers = sorted(({"dimension": k, "score": s, "confidence": c, "contribution": round(WEIGHTS[k] * c * s / den, 1) if den else 0}
                      for k, (s, c) in used.items()), key=lambda d: -d["contribution"])
    return {"class": cls, "score": score, "coverage": coverage, "confidence": confidence, "drivers": drivers}
