"""Module 3: deterministic extraction + multilingual rules; LLM is an optional, validated add-on."""
import hashlib
import re
import unicodedata
from typing import Optional, Protocol

from ..core.normalize import norm_email, norm_phone, norm_upi

URL_RE = re.compile(r"(?i)\b((?:https?://|www\.)[^\s<>\"'\)\]]+|(?:[a-z0-9-]+\.)+(?:com|in|net|org|xyz|top|link|click|co|info|site|online|icu)(?:/[^\s<>\"'\)\]]*)?)")
EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b")
UPI_RE = re.compile(r"(?i)(?<![\w.])[a-z0-9._-]{2,}@[a-z]{2,12}\b(?!\.[a-z])")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\s-]{8,15}\d)(?!\d)")
IFSC_RE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
INJECTION_RE = re.compile(r"(?i)(ignore (all |any )?(previous|prior) instructions|system prompt|you are now|mark (this|it) as (safe|legit))")

# keyword lexicons: English, romanised Hinglish, Hindi, Bengali, Malayalam
LEX = {
    "urgency": ["urgent", "immediately", "within 24 hours", "last chance", "expires today", "turant", "abhi",
                "तुरंत", "अभी", "आज ही", "অবিলম্বে", "এখনই", "আজই", "ഉടൻ", "ഉടനെ", "ഇന്ന് തന്നെ"],
    "threat": ["blocked", "suspended", "closed", "deactivated", "legal action", "band ho", "बंद", "ब्लॉक",
               "बंद हो", "বন্ধ", "ব্লক", "ব্লক হয়ে", "ബ്ലോക്ക്", "അടച്ചു", "നിർത്തലാക്കും"],
    "reward": ["won", "prize", "lottery", "cashback", "reward", "gift", "refund", "इनाम", "जीता", "लॉटरी",
               "পুরস্কার", "জিতেছেন", "লটারি", "സമ്മാനം", "ലോട്ടറി", "ക്യാഷ്ബാക്ക്"],
    "credential": ["otp", "pin", "cvv", "password", "passcode", "ओटीपी", "पिन", "पासवर्ड", "ওটিপি", "পিন", "পাসওয়ার্ড",
                   "ഒടിപി", "പിൻ", "പാസ്\u200cവേഡ്"],
    "kyc": ["kyc", "pan card", "aadhaar", "aadhar", "केवाईसी", "आधार", "কেওয়াইসি", "আধার", "കെവൈസി", "ആധാർ"],
    "payment": ["upi", "pay now", "transfer", "collect request", "processing fee", "registration fee", "send money",
                "पैसे भेज", "ফি জমা", "টাকা পাঠান", "പണം അയയ്ക്ക"],
    "delivery": ["parcel", "package", "delivery", "courier", "customs", "india post", "पार्सल", "পার্সেল", "പാഴ്സൽ"],
    "job": ["work from home", "part time job", "earn daily", "task", "telegram group", "घर बैठे", "বাড়ি থেকে আয়"],
    "investment": ["crypto", "bitcoin", "guaranteed returns", "double your money", "trading signal"],
}
CATEGORY_RULES = [  # (category, required dimension sets) evaluated in order
    ("kyc_bank_phishing", {"kyc"}), ("kyc_bank_phishing", {"threat", "credential"}),
    ("lottery_prize", {"reward"}), ("delivery_scam", {"delivery"}), ("job_task_scam", {"job"}),
    ("investment_scam", {"investment"}), ("upi_payment_request", {"payment"}),
]
AUTHORITY = ["sbi", "hdfc", "icici", "axis", "paytm", "rbi", "income tax", "amazon", "flipkart", "india post", "police", "trai", "customs"]


class LLMProvider(Protocol):
    def analyse(self, text: str, language: str) -> Optional[dict]: ...


class NullProvider:
    def analyse(self, text, language):
        return None


def detect_script(text: str) -> str:
    counts = {"devanagari": 0, "bengali": 0, "malayalam": 0, "latin": 0}
    for c in text:
        o = ord(c)
        if 0x0900 <= o <= 0x097F: counts["devanagari"] += 1
        elif 0x0980 <= o <= 0x09FF: counts["bengali"] += 1
        elif 0x0D00 <= o <= 0x0D7F: counts["malayalam"] += 1
        elif c.isascii() and c.isalpha(): counts["latin"] += 1
    top = max(counts, key=counts.get)
    return {"devanagari": "hi", "bengali": "bn", "malayalam": "ml", "latin": "en"}[top] if counts[top] else "unknown"


def extract_indicators(text: str) -> dict:
    urls = sorted({u.rstrip(".,;") for u in URL_RE.findall(text)})
    emails = {norm_email(e) for e in EMAIL_RE.findall(text)}
    email_hosts = {e.split("@")[1] for e in emails}
    upis = {norm_upi(u) for u in UPI_RE.findall(text) if norm_upi(u) not in emails and u.split("@")[1].lower() not in email_hosts}
    phones = {p for p in (norm_phone(m) for m in PHONE_RE.findall(text)) if p}
    domains = set()
    for u in urls:
        host = re.sub(r"(?i)^https?://", "", u).split("/")[0].split(":")[0].lower().removeprefix("www.")
        if host: domains.add(host)
    return {"urls": urls, "domains": sorted(domains), "emails": sorted(emails), "upi_ids": sorted(upis),
            "phones": sorted(phones), "ifsc": sorted(set(IFSC_RE.findall(text)))}


def rule_scan(text: str) -> dict:
    low = unicodedata.normalize("NFKC", text).lower()
    hits = {dim: sorted({w for w in words if w in low}) for dim, words in LEX.items()}
    hits = {k: v for k, v in hits.items() if v}
    authority = sorted(a for a in AUTHORITY if re.search(rf"\b{re.escape(a)}\b", low))
    weights = {"urgency": 14, "threat": 16, "reward": 14, "credential": 28, "kyc": 14, "payment": 14,
               "delivery": 6, "job": 10, "investment": 12}
    score = sum(weights[k] for k in hits) + (10 if authority else 0)
    category = "unclear"
    for cat, need in CATEGORY_RULES:
        if need <= set(hits):
            category = cat
            break
    return {"hits": hits, "authority": authority, "score": min(score, 100), "category": category}


def _norm_for_fp(text: str) -> str:
    t = unicodedata.normalize("NFKC", text).lower()
    t = URL_RE.sub(" <url> ", t)
    t = EMAIL_RE.sub(" <email> ", t)
    t = PHONE_RE.sub(" <phone> ", t)
    t = re.sub(r"\d+", "<n>", t)
    return re.sub(r"\s+", " ", t).strip()


def minhash(text: str, perms: int = 64) -> list[int]:
    words = _norm_for_fp(text).split()
    shingles = {" ".join(words[i:i + 3]) for i in range(max(len(words) - 2, 1))} or {""}
    return [min(int.from_bytes(hashlib.blake2b(f"{i}|{s}".encode(), digest_size=8).digest(), "big") for s in shingles)
            for i in range(perms)]


def minhash_similarity(a: list[int], b: list[int]) -> float:
    return sum(x == y for x, y in zip(a, b)) / len(a)


def analyse_message(text: str, provider: Optional[LLMProvider] = None) -> dict:
    text = text[:10000]
    lang = detect_script(text)
    ind = extract_indicators(text)
    rules = rule_scan(text)
    flags = []
    injection = bool(INJECTION_RE.search(text))
    if injection:
        flags.append("prompt_injection_attempt")
    score = rules["score"] + (15 if ind["urls"] else 0) + (8 if injection else 0)
    llm = None
    if provider is not None:
        try:
            out = provider.analyse(text, lang)
        except Exception:  # provider failure must never break the investigation
            out = None
        if out:
            # LLM output is advisory: keep only evidence quotes that really occur in the text, cap influence
            ev = [q for q in out.get("evidence", []) if isinstance(q, str) and q in text]
            llm = {"category": out.get("category"), "confidence": float(out.get("confidence", 0) or 0),
                   "evidence": ev, "precautions": out.get("precautions", [])[:6]}
            score += min(int(20 * llm["confidence"]), 20)
    if rules["category"] == "unclear" and llm and llm.get("category"):
        category = llm["category"]
    else:
        category = rules["category"]
    precautions = ["Do not click links or call numbers in the message; use the official app or website.",
                   "Never share OTP, PIN, CVV or passwords; real organisations do not ask for them."]
    if ind["upi_ids"]:
        precautions.append("Do not approve unexpected UPI collect requests.")
    return {"language": lang, "category": category, "indicators": ind, "patterns": rules["hits"],
            "authority_mentions": rules["authority"], "flags": flags, "score": min(score, 100),
            "llm": llm, "minhash": minhash(text), "precautions": precautions,
            "limitations": ["Rule-based and keyword-driven; Hindi, Bengali and Malayalam lexicons are small and need native-speaker review.",
                            "A high score indicates suspicious patterns, not proof of fraud."]}
