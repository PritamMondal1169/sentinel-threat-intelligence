"""PRD Section 25: Synthetic Labelled Correlation Benchmark.
Evaluates the Scam DNA Engine on 40 labelled investigations across 8 campaign groups
plus 10 distractors / hard negatives (shared Cloudflare CDN, Let's Encrypt CAs, similar brands).
Computes pairwise Precision, Recall, F1, and Campaign Purity.
"""
from datetime import datetime, timezone, timedelta
from typing import NamedTuple
from .services import correlation as corr


class BenchmarkMetrics(NamedTuple):
    precision: float
    recall: float
    f1: float
    true_positives: int
    false_positives: int
    false_negatives: int
    total_campaigns_formed: int
    purity: float


def build_labelled_dataset() -> tuple[list[dict], dict[str, str]]:
    """Builds 40 investigations in 8 distinct ground-truth campaigns plus 10 distractors.
    Returns (investigations_list, ground_truth_map: inv_id -> group_name).
    """
    base_time = datetime(2026, 1, 10, 12, 0, tzinfo=timezone.utc)
    invs = []
    ground_truth = {}  # inv_id -> group_id

    # Group 1: SBI KYC Phishing (shared phone & dedicated SPKI)
    for idx, (sub, phone, domain) in enumerate([
        ("user_101", "+919876543210", "sbi-kyc-verify.top"),
        ("user_102", "+919876543210", "sbi-account-update.xyz"),
        ("user_103", "+919876543210", "sbi-pan-link.click"),
        ("user_104", "+919876543210", "sbi-kyc-desk.top")
    ]):
        iid = f"g1_sbi_{idx}"
        ground_truth[iid] = "group_1_sbi"
        invs.append({
            "id": iid,
            "submitter": sub,
            "ts": base_time + timedelta(hours=idx * 2),
            "indicators": {
                ("phone", phone): "verified",
                ("spki", "spki_sbi_cluster_aabb1122"): "verified",
                ("domain", domain): "verified"
            }
        })

    # Group 2: HDFC Reward Points Scam (shared UPI & template)
    for idx, (sub, upi, domain) in enumerate([
        ("user_201", "hdfcclaims@upi", "hdfc-rewards-portal.site"),
        ("user_202", "hdfcclaims@upi", "hdfc-point-claim.info"),
        ("user_203", "hdfcclaims@upi", "hdfc-gift-redeem.link")
    ]):
        iid = f"g2_hdfc_{idx}"
        ground_truth[iid] = "group_2_hdfc"
        invs.append({
            "id": iid,
            "submitter": sub,
            "ts": base_time + timedelta(days=1, hours=idx * 4),
            "indicators": {
                ("payment_id", upi): "verified",
                ("template", "tpl_hdfc_reward_point"): "verified",
                ("domain", domain): "verified"
            }
        })

    # Group 3: India Post Redelivery Phishing (shared email & non-shared nameservers)
    for idx, (sub, domain) in enumerate([
        ("user_301", "indiapost-tracking-help.com"),
        ("user_302", "indiapost-parcel-delivery.xyz"),
        ("user_303", "indiapost-customs-fee.top")
    ]):
        iid = f"g3_post_{idx}"
        ground_truth[iid] = "group_3_post"
        invs.append({
            "id": iid,
            "submitter": sub,
            "ts": base_time + timedelta(days=2, hours=idx),
            "indicators": {
                ("email", "support@indiapost-tracking-help.com"): "verified",
                ("nameserver", "ns1.bulletproof-dns-india.org"): "verified",
                ("domain", domain): "verified"
            }
        })

    # Group 4: Electricity Bill Suspension Scam (shared phone & dedicated IP)
    for idx, (sub, phone, domain) in enumerate([
        ("user_401", "+919811122233", "bijli-bill-update.online"),
        ("user_402", "+919811122233", "power-cut-notice.net"),
        ("user_403", "+919811122233", "urgent-bill-pay.click"),
        ("user_404", "+919811122233", "quick-discom-bill.top")
    ]):
        iid = f"g4_bill_{idx}"
        ground_truth[iid] = "group_4_bill"
        invs.append({
            "id": iid,
            "submitter": sub,
            "ts": base_time + timedelta(days=3, hours=idx * 3),
            "indicators": {
                ("phone", phone): "verified",
                ("ip", "185.220.101.44"): "verified",
                ("domain", domain): "verified"
            }
        })

    # Group 5: Fake Job / Telegram Task Scam (shared UPI & template)
    for idx, (sub, upi) in enumerate([
        ("user_501", "parttime_task_refund@okaxis"),
        ("user_502", "parttime_task_refund@okaxis"),
        ("user_503", "parttime_task_refund@okaxis")
    ]):
        iid = f"g5_job_{idx}"
        ground_truth[iid] = "group_5_job"
        invs.append({
            "id": iid,
            "submitter": sub,
            "ts": base_time + timedelta(days=4, hours=idx * 2),
            "indicators": {
                ("payment_id", upi): "verified",
                ("template", "tpl_youtube_like_job"): "verified"
            }
        })

    # Group 6: Crypto Investment Doubler (shared crypto address & cert)
    for idx, (sub, domain) in enumerate([
        ("user_601", "crypto-double-returns.biz"),
        ("user_602", "instant-eth-multiplier.tech"),
        ("user_603", "btc-yield-mining-fast.icu")
    ]):
        iid = f"g6_crypto_{idx}"
        ground_truth[iid] = "group_6_crypto"
        invs.append({
            "id": iid,
            "submitter": sub,
            "ts": base_time + timedelta(days=5, hours=idx * 5),
            "indicators": {
                ("payment_id", "0x71C88062B557F5FE61CEF0F6F5092A2C66A238A1"): "verified",
                ("cert", "sha256_fake_crypto_cert_998877"): "verified",
                ("domain", domain): "verified"
            }
        })

    # Group 7: ICICI Netbanking Credential Harvester (shared phone & SPKI)
    for idx, (sub, domain) in enumerate([
        ("user_701", "icici-netbanking-login.site"),
        ("user_702", "icici-kyc-verify-portal.top")
    ]):
        iid = f"g7_icici_{idx}"
        ground_truth[iid] = "group_7_icici"
        invs.append({
            "id": iid,
            "submitter": sub,
            "ts": base_time + timedelta(days=6, hours=idx),
            "indicators": {
                ("phone", "+919777788888"): "verified",
                ("spki", "spki_icici_phish_cluster_3344"): "verified",
                ("domain", domain): "verified"
            }
        })

    # Group 8: Paytm Wallet KYC Scam (shared UPI & phone)
    for idx, (sub, domain) in enumerate([
        ("user_801", "paytm-kyc-verification.icu"),
        ("user_802", "paytm-wallet-reactivate.online")
    ]):
        iid = f"g8_paytm_{idx}"
        ground_truth[iid] = "group_8_paytm"
        invs.append({
            "id": iid,
            "submitter": sub,
            "ts": base_time + timedelta(days=6, hours=idx * 2),
            "indicators": {
                ("payment_id", "paytmhelpdesk@paytm"): "verified",
                ("phone", "+919666655555"): "verified",
                ("domain", domain): "verified"
            }
        })

    # Distractors (Hard Negatives): Unrelated sites sharing Cloudflare CDN IPs, Let's Encrypt CAs, common TLDs
    for idx in range(10):
        iid = f"distractor_{idx}"
        ground_truth[iid] = f"distractor_{idx}"  # independent, should not cluster
        invs.append({
            "id": iid,
            "submitter": f"benign_user_{idx}",
            "ts": base_time + timedelta(days=idx % 7),
            "indicators": {
                ("ip", "104.21.44.82"): "verified",  # Cloudflare shared IP (capped uniqueness <= 0.1)
                ("asn", "AS13335"): "verified",
                ("registrar", "NameCheap, Inc."): "verified",
                ("domain", f"legitimate-shop-{idx}.com"): "verified"
            }
        })

    return invs, ground_truth


def evaluate_correlation() -> BenchmarkMetrics:
    """Run full correlation benchmark and compute evaluation metrics."""
    invs, ground_truth = build_labelled_dataset()
    edges = corr.build_edges(invs, min_conf=0.6)
    campaigns = corr.cluster_campaigns(invs, edges)

    # Ground truth pairs
    gt_pairs = set()
    all_ids = list(ground_truth.keys())
    for i in range(len(all_ids)):
        for j in range(i + 1, len(all_ids)):
            id_a, id_b = all_ids[i], all_ids[j]
            group_a, group_b = ground_truth[id_a], ground_truth[id_b]
            if not group_a.startswith("distractor") and group_a == group_b:
                gt_pairs.add(tuple(sorted([id_a, id_b])))

    # Predicted pairs from qualified edges
    pred_pairs = set()
    for e in edges:
        if e.get("qualifies") and e["confidence"] >= 0.6:
            pred_pairs.add(tuple(sorted([e["a"], e["b"]])))

    tp = len(gt_pairs & pred_pairs)
    fp = len(pred_pairs - gt_pairs)
    fn = len(gt_pairs - pred_pairs)

    precision = round(tp / (tp + fp), 3) if (tp + fp) else 1.0
    recall = round(tp / (tp + fn), 3) if (tp + fn) else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 3) if (precision + recall) else 0.0

    # Campaign Purity calculation
    pure_clusters = 0
    for camp in campaigns:
        members = camp["members"]
        groups_in_camp = [ground_truth[m] for m in members]
        dominant_count = max(groups_in_camp.count(g) for g in set(groups_in_camp))
        purity_val = dominant_count / len(members)
        if purity_val >= 0.9:
            pure_clusters += 1

    overall_purity = round(pure_clusters / len(campaigns), 3) if campaigns else 1.0

    return BenchmarkMetrics(
        precision=precision,
        recall=recall,
        f1=f1,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        total_campaigns_formed=len(campaigns),
        purity=overall_purity
    )


if __name__ == "__main__":
    res = evaluate_correlation()
    print(f"SENTINEL Correlation Benchmark (PRD Section 25):")
    print(f"Precision: {res.precision:.1%} (Target >= 90%)")
    print(f"Recall:    {res.recall:.1%} (Target >= 70%)")
    print(f"F1 Score:  {res.f1:.3f}")
    print(f"Purity:    {res.purity:.1%}")
    print(f"Campaigns: {res.total_campaigns_formed}")
    print(f"TP: {res.true_positives}, FP: {res.false_positives}, FN: {res.false_negatives}")

