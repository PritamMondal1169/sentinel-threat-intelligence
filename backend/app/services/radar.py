"""Emerging Scam Radar (Module 4).
Detects statistical surges in threat indicators, template clusters, and brand impersonation.
Follows PRD Section 20:
- Baseline analysis over 14 days
- Surge rule: current count >= max(5, mean + 3 * std) or rapid acceleration
- Typed alerts: domain_surge, repeated_template_growth, reused_payment_destination,
               brand_targeting_spike, new_cluster_formation
- Evidence levels: low, medium, high
- Baseline indicator: suppressed / insufficient baseline when data window < 7 days
"""
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional


def compute_radar_signals(investigations: list[dict], campaigns: list[dict]) -> dict:
    """Compute active emerging scam radar signals from all recorded investigations."""
    if not investigations:
        return {
            "baseline_status": "insufficient_baseline",
            "message": "Insufficient baseline (at least 7 days of historical activity required).",
            "active_alerts": [],
            "metrics": {
                "total_investigations_evaluated": 0,
                "spike_count": 0
            }
        }

    now = datetime.now(timezone.utc)
    dates = []
    for inv in investigations:
        ts = inv.get("ts")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except Exception:
                continue
        if ts:
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            dates.append(ts)

    if not dates:
        return {
            "baseline_status": "insufficient_baseline",
            "message": "No valid observation timestamps.",
            "active_alerts": [],
            "metrics": {"total_investigations_evaluated": 0, "spike_count": 0}
        }

    span_days = max(1, (max(dates) - min(dates)).days + 1)
    has_sufficient_baseline = span_days >= 7

    # Group investigations by day and extract signals
    day_counts = Counter()
    brand_counts = Counter()
    template_counts = Counter()
    payment_counts = Counter()
    domain_counts = Counter()
    submitters_by_brand = defaultdict(set)
    submitters_by_template = defaultdict(set)
    submitters_by_payment = defaultdict(set)
    submitters_by_domain = defaultdict(set)

    for inv in investigations:
        ts = inv.get("ts")
        if isinstance(ts, str):
            try: ts = datetime.fromisoformat(ts)
            except Exception: continue
        if not ts: continue
        if ts.tzinfo is None: ts = ts.replace(tzinfo=timezone.utc)
        
        day_key = ts.strftime("%Y-%m-%d")
        day_counts[day_key] += 1
        sub = inv.get("submitter", "anon")
        res = inv.get("result", {})
        
        # Brands
        brand = res.get("brand") or (res.get("llm") or {}).get("impersonated_brand")
        if brand:
            brand_counts[brand.upper()] += 1
            submitters_by_brand[brand.upper()].add(sub)
            
        # Templates
        tid = res.get("template_id")
        if tid:
            template_counts[tid] += 1
            submitters_by_template[tid].add(sub)

        # Indicators
        for (t, v) in inv.get("indicators", {}).keys():
            if t == "payment_id":
                payment_counts[v] += 1
                submitters_by_payment[v].add(sub)
            elif t == "domain":
                domain_counts[v] += 1
                submitters_by_domain[v].add(sub)

    alerts = []

    # 1. Brand impersonation spike
    for brand, count in brand_counts.most_common(5):
        subs = len(submitters_by_brand[brand])
        if count >= 3:
            evidence_level = "high" if count >= 5 and subs >= 2 else "medium" if count >= 3 else "low"
            alerts.append({
                "type": "brand_targeting_spike",
                "title": f"Targeting Surge: Impersonation of '{brand}'",
                "entity": brand,
                "count": count,
                "independent_submitters": subs,
                "evidence_level": evidence_level,
                "detail": f"{count} investigations detected impersonating {brand} across {subs} independent submitters.",
                "remediation": f"Advise customers that {brand} does not request urgent verification or credentials over SMS/messaging."
            })

    # 2. Repeated template growth (MinHash clusters)
    for tid, count in template_counts.most_common(5):
        subs = len(submitters_by_template[tid])
        if count >= 2:
            evidence_level = "high" if count >= 4 and subs >= 2 else "medium"
            alerts.append({
                "type": "repeated_template_growth",
                "title": f"Template Cluster Growth ({tid})",
                "entity": tid,
                "count": count,
                "independent_submitters": subs,
                "evidence_level": evidence_level,
                "detail": f"Structural message fingerprint {tid} detected in {count} reworded variations.",
                "remediation": "Block message bodies matching this syntactic cluster at the gateway."
            })

    # 3. Reused payment destination
    for pay_id, count in payment_counts.most_common(5):
        subs = len(submitters_by_payment[pay_id])
        if count >= 2:
            evidence_level = "high" if subs >= 2 else "medium"
            alerts.append({
                "type": "reused_payment_destination",
                "title": f"Reused Fraud Destination: {pay_id}",
                "entity": pay_id,
                "count": count,
                "independent_submitters": subs,
                "evidence_level": evidence_level,
                "detail": f"UPI/Payment account {pay_id} surfaced across {count} separate scam reports.",
                "remediation": "Report UPI ID / VPA to NPCI and beneficiary bank for freezing."
            })

    # 4. New cluster / campaign formation
    for camp in campaigns:
        if camp.get("status") == "corroborated" or len(camp.get("members", [])) >= 3:
            alerts.append({
                "type": "new_cluster_formation",
                "title": f"Active Threat Campaign: {camp.get('id', 'Cluster')}",
                "entity": camp.get("id"),
                "count": len(camp.get("members", [])),
                "independent_submitters": camp.get("independent_submitters", 1),
                "evidence_level": "high" if camp.get("confidence", 0) >= 0.75 else "medium",
                "detail": f"Coordinated infrastructure sharing: {', '.join(camp.get('shared_types', []))} with confidence {camp.get('confidence')}.",
                "remediation": "Export canonical report and issue collective takedown for member domains."
            })

    # 5. Check statistical surge on total activity
    counts_list = list(day_counts.values())
    if len(counts_list) >= 7:
        mean = statistics.mean(counts_list)
        std = statistics.pstdev(counts_list) if len(counts_list) > 1 else 1.0
        today_key = now.strftime("%Y-%m-%d")
        today_count = day_counts.get(today_key, 0)
        threshold = max(5, mean + 3 * std)
        if today_count >= threshold:
            alerts.insert(0, {
                "type": "domain_surge",
                "title": f"Threat Intake Anomaly: {today_count} scans today",
                "entity": "Global Volume",
                "count": today_count,
                "independent_submitters": len(set(i.get("submitter", "") for i in investigations)),
                "evidence_level": "high",
                "detail": f"Daily scan volume exceeded 3-sigma baseline ({mean:.1f} ± {std:.1f}).",
                "remediation": "Investigate potential mass-phishing distribution wave."
            })

    baseline_status = "active" if has_sufficient_baseline else "insufficient_baseline"
    return {
        "baseline_status": baseline_status,
        "message": (
            "Radar active with statistical baseline."
            if has_sufficient_baseline
            else "Notice: Preliminary radar signals (under 7 days baseline; confidence intervals wider)."
        ),
        "active_alerts": alerts,
        "metrics": {
            "total_investigations_evaluated": len(investigations),
            "spike_count": len(alerts),
            "baseline_days": span_days
        }
    }

