"""Module 4: Scam DNA matching, explainable relationship confidence, campaign clustering."""
import math
from collections import Counter
from datetime import datetime

BASE_WEIGHT = {"payment_id": .90, "phone": .85, "email": .80, "spki": .80, "cert": .80, "url": .65, "san_set": .60,
               "ip": .45, "template": .65, "nameserver": .40, "domain": .30, "asn": .05, "registrar": .05}
HIGH_SPECIFICITY = {"payment_id", "phone", "email", "spki", "cert", "url"}
# indicators on shared infrastructure can never prove much on their own
SHARED_INFRA = {("ip", p) for p in ("104.21.", "172.67.", "188.114.", "13.", "52.", "34.", "35.")}
QUALITY = {"verified": 1.0, "feed": .7, "llm": .3}


def is_shared_infra(typ: str, val: str) -> bool:
    return typ == "ip" and any(val.startswith(p) for _, p in SHARED_INFRA) or typ in ("asn", "registrar")


def uniqueness(typ: str, val: str, df: int) -> float:
    u = 1 / math.log2(2 + max(df - 2, 0))      # df excludes the two investigations being compared
    return min(u, .1) if is_shared_infra(typ, val) else u


def _temporal(a: datetime, b: datetime) -> float:
    days = abs((a - b).days)
    return 1.0 if days <= 7 else max(.6, 1 - .0044 * days)


def pair_confidence(a: dict, b: dict, df: Counter) -> dict:
    """a, b: {'id','ts','submitter','indicators': {(type,value): quality}}. Returns confidence + evidence."""
    shared, miss = [], 1.0
    for key in set(a["indicators"]) & set(b["indicators"]):
        typ, val = key
        q = min(QUALITY.get(a["indicators"][key], .7), QUALITY.get(b["indicators"][key], .7))
        u = uniqueness(typ, val, df[key])
        e = BASE_WEIGHT.get(typ, .1) * u * q
        shared.append({"type": typ, "value": val, "uniqueness": round(u, 3), "evidence_strength": round(e, 3)})
        miss *= 1 - e
    if not shared:
        return {"confidence": 0.0, "shared": []}
    indep = 1.0 if a["submitter"] != b["submitter"] else .8
    if a.get("input_hash") and a.get("input_hash") == b.get("input_hash"):
        indep = .5
    conf = (1 - miss) * _temporal(a["ts"], b["ts"]) * indep
    return {"confidence": round(conf, 3), "shared": sorted(shared, key=lambda s: -s["evidence_strength"])}


def _qualifies(shared: list[dict]) -> bool:
    strong = any(s["type"] in HIGH_SPECIFICITY and s["uniqueness"] >= .5 for s in shared)
    return strong or len({s["type"] for s in shared if s["uniqueness"] >= .3}) >= 2


def label(c: float) -> str:
    return "strong" if c >= .8 else "moderate" if c >= .6 else "weak" if c >= .4 else "none"


def build_edges(invs: list[dict], min_conf: float = .4) -> list[dict]:
    df = Counter(k for i in invs for k in i["indicators"])
    edges = []
    for x in range(len(invs)):
        for y in range(x + 1, len(invs)):
            r = pair_confidence(invs[x], invs[y], df)
            if r["confidence"] >= min_conf:
                edges.append({"a": invs[x]["id"], "b": invs[y]["id"], "relationship_type": "shares_indicator",
                              "confidence": r["confidence"], "label": label(r["confidence"]), "shared": r["shared"],
                              "qualifies": _qualifies(r["shared"]),
                              "discovered_at": max(invs[x]["ts"], invs[y]["ts"]).isoformat(),
                              "evidence_source": "sentinel-correlation-v1"})
    return edges


def _components(nodes, edges):
    parent = {n: n for n in nodes}
    def find(n):
        while parent[n] != n:
            parent[n] = parent[parent[n]]
            n = parent[n]
        return n
    for e in edges:
        parent[find(e["a"])] = find(e["b"])
    groups = {}
    for n in nodes:
        groups.setdefault(find(n), set()).add(n)
    return list(groups.values())


def cluster_campaigns(invs: list[dict], edges: list[dict]) -> list[dict]:
    """Cluster on strong, qualified edges; weak edges may only attach a lone node to one cluster (no chaining)."""
    ids = [i["id"] for i in invs]
    strong = [e for e in edges if e["qualifies"] and e["confidence"] >= .75]
    groups = [g for g in _components(ids, strong) if len(g) > 1]
    member = {n: gi for gi, g in enumerate(groups) for n in g}
    for e in sorted((e for e in edges if e["qualifies"] and .6 <= e["confidence"] < .75), key=lambda e: -e["confidence"]):
        a, b = e["a"], e["b"]
        if (a in member) != (b in member):
            lone, anchor = (b, a) if a in member else (a, b)
            groups[member[anchor]].add(lone)
            member[lone] = member[anchor]
    out = []
    for g in groups:
        inner = [e for e in edges if e["a"] in g and e["b"] in g and e["qualifies"]]
        subs = {i["submitter"] for i in invs if i["id"] in g}
        mean = sum(e["confidence"] for e in inner) / len(inner) if inner else 0
        out.append({"members": sorted(g), "confidence": round(mean, 3), "independent_submitters": len(subs),
                    "status": "potential", "relationships": inner,
                    "shared_types": sorted({s["type"] for e in inner for s in e["shared"]})})
    return sorted(out, key=lambda c: -c["confidence"])
