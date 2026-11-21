"""Scam / phishing classifier = ML text model (TF-IDF + Logistic Regression)
combined with explainable heuristic rules (URL, urgency, credential requests, brand spoofing)."""
import hashlib
import re
from functools import lru_cache
from urllib.parse import urlparse

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from .seed_data import SAMPLES

URL_RE = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>\"']+|\b(?:[a-z0-9-]+\.)+(?:xyz|top|click|icu|live|site|online|link|ly|gl|cc|tk|ml)(?:/[^\s]*)?"
)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
OTP_RE = re.compile(r"(?i)(otp|code|pin)(\s*(?:is|:|-)?\s*)\d{4,8}")
LONGNUM_RE = re.compile(r"(?<!\d)\d{9,18}(?!\d)")

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at"}
BAD_TLDS = {"xyz", "top", "click", "icu", "live", "site", "online", "link", "cc", "tk", "ml", "ga", "cf", "gq", "work", "support"}

BRANDS = {  # brand keyword -> official domains
    "sbi": ["sbi.co.in", "onlinesbi.sbi"], "hdfc": ["hdfcbank.com"], "icici": ["icicibank.com"],
    "axis": ["axisbank.com"], "paytm": ["paytm.com"], "phonepe": ["phonepe.com"],
    "amazon": ["amazon.in", "amazon.com"], "flipkart": ["flipkart.com"], "google": ["google.com"],
    "microsoft": ["microsoft.com"], "netflix": ["netflix.com"], "paypal": ["paypal.com"],
    "apple": ["apple.com"], "irctc": ["irctc.co.in"], "fedex": ["fedex.com"],
    "income tax": ["incometax.gov.in"], "aadhaar": ["uidai.gov.in"], "india post": ["indiapost.gov.in"],
}

CATEGORY_RULES = {
    "Bank / KYC fraud": r"kyc|account (?:will be )?(?:blocked|suspended|frozen)|net ?banking|\bpan\b|aadhaar|sim will be blocked|credit card",
    "OTP / UPI fraud": r"\botp\b|\bupi\b|collect request|\bcvv\b|\bpin\b|6 digit code",
    "Lottery / prize": r"won\b|lottery|lucky|prize|congratulations|gift card|scholarship|free iphone",
    "Delivery / parcel": r"parcel|package|courier|customs|delivery|fedex|india post",
    "Job / task scam": r"part[- ]time|work from home|earn .{0,20}(?:day|daily|task)|data entry|telegram|registration fee",
    "Investment / crypto": r"crypto|bitcoin|\bbtc\b|returns|trading|double your|profit|invest",
    "Tech support": r"virus|infected|tech support|microsoft support|toll free",
    "Credential phishing": r"verify your|sign[- ]?in|password|login|security alert|apple id|paypal|account (?:is )?limited",
    "Utility / tax fraud": r"electricity|disconnected|income tax|refund|e-?challan|fastag|court action",
    "Impersonation / romance": r"new number|stuck abroad|soldier|help me transfer|hi mum|hi mom|dear friend",
}

SIGNALS = [  # (name, regex, weight, human reason)
    ("urgency", r"urgent|immediately|within \d+ ?(?:hours|hrs|minutes|mins)|expire|suspend|blocked|deactivat|final notice|last warning|act now|today only|tonight|arrest",
     0.18, "Creates artificial urgency or threatens account blocking"),
    ("credentials", r"\botp\b.{0,40}(?:share|send|enter)|(?:share|send|enter|confirm|submit).{0,30}(?:\botp\b|\bpin\b|cvv|password|card number|aadhaar|\bpan\b|bank details)|upi pin",
     0.28, "Asks for sensitive credentials (OTP / PIN / CVV / password / ID)"),
    ("money_lure", r"\bwon\b|lottery|prize|cashback|refund|reward|gift card|lucky|guaranteed|double your|\d+% returns|per day|daily earn|earn rs",
     0.16, "Offers money / prizes / guaranteed returns"),
    ("advance_fee", r"(?:processing|registration|customs|clearance) (?:fee|charges)|pay rs|send 0\.\d+ btc",
     0.22, "Requests an upfront fee before delivering the promise"),
    ("off_platform", r"telegram|whatsapp (?:group|me)|call (?:this|toll|now)|call officer|contact claim agent",
     0.12, "Pushes the victim to an off-platform channel or unknown phone number"),
    ("apk", r"\.apk|install this", 0.2, "Asks to install an unknown app / APK"),
]
SAFE_CUES = r"do not share|never share|never ask|will never ask|stay safe"

LABEL_THRESHOLDS = (0.40, 0.65)  # suspicious >= 0.40, scam >= 0.65


# ---------- privacy helpers ----------
def redact(text: str) -> str:
    text = EMAIL_RE.sub("[email]", text)
    text = OTP_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[code]", text)
    text = PHONE_RE.sub("[phone]", text)
    return LONGNUM_RE.sub("[number]", text)


def fingerprint(text: str) -> str:
    """Hash of a normalised message: near-identical scam texts share a fingerprint (campaign)."""
    norm = re.sub(r"\d+", "#", text.lower())
    norm = re.sub(r"\s+", " ", norm).strip()
    return hashlib.sha256(norm.encode()).hexdigest()


def extract_urls(text: str):
    urls = [u.rstrip(".,);") for u in URL_RE.findall(text)]
    return list(dict.fromkeys(urls))[:5]


def domain_of(url: str) -> str:
    u = url if "://" in url else "http://" + url
    return (urlparse(u).hostname or "").lower().removeprefix("www.")


# ---------- ML model ----------
@lru_cache(maxsize=1)
def _model():
    texts, labels = zip(*SAMPLES)
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, stop_words="english")
    X = vec.fit_transform(texts)
    clf = LogisticRegression(C=4.0, max_iter=1000, class_weight="balanced").fit(X, labels)
    return vec, clf


MODEL_VERSION = f"tfidf-lr-v1-n{len(SAMPLES)}"


def ml_score(text: str):
    vec, clf = _model()
    x = vec.transform([text])
    prob = float(clf.predict_proba(x)[0][1])
    terms = vec.get_feature_names_out()
    contrib = x.multiply(clf.coef_[0]).tocoo()
    top = sorted(zip(contrib.col, contrib.data), key=lambda t: -t[1])[:3]
    words = [terms[i] for i, v in top if v > 0.05]
    return prob, words


# ---------- heuristics ----------
def url_findings(urls, text):
    score, reasons = 0.0, []
    low = text.lower()
    for u in urls:
        d = domain_of(u)
        if not d:
            continue
        tld = d.rsplit(".", 1)[-1]
        if d in SHORTENERS:
            score += 0.2; reasons.append(f"Shortened link hides the real destination ({d})")
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", d):
            score += 0.3; reasons.append("Link points to a raw IP address")
        if tld in BAD_TLDS:
            score += 0.2; reasons.append(f"Link uses a high-risk domain ending (.{tld})")
        if "xn--" in d:
            score += 0.25; reasons.append("Link uses punycode (look-alike characters)")
        if d.count("-") >= 2 or d.count(".") >= 3:
            score += 0.1; reasons.append("Link domain has many hyphens / sub-domains")
        if u.lower().startswith("http://"):
            score += 0.06; reasons.append("Link is not HTTPS")
        for brand, official in BRANDS.items():
            if brand in low or brand.replace(" ", "") in d:
                if not any(d == o or d.endswith("." + o) for o in official) and brand.replace(" ", "") in (d + low):
                    if brand.replace(" ", "") in d or brand in low:
                        score += 0.3
                        reasons.append(f"Mentions '{brand}' but link domain {d} is not official")
                        break
    if urls:
        score += 0.05
    return score, reasons


def categorize(text: str):
    best, hits = "Generic scam", 0
    for cat, rx in CATEGORY_RULES.items():
        n = len(re.findall(rx, text, flags=re.I))
        if n > hits:
            best, hits = cat, n
    return best


def classify(text: str) -> dict:
    urls = extract_urls(text)
    prob, words = ml_score(text)
    h, reasons = 0.0, []
    low = text.lower()
    for _, rx, w, why in SIGNALS:
        if re.search(rx, low):
            h += w; reasons.append(why)
    uscore, ureasons = url_findings(urls, text)
    h += uscore; reasons += ureasons
    if re.search(SAFE_CUES, low) and not urls:
        h -= 0.25
        reasons.append("Contains standard anti-fraud advice and no links (typical of genuine alerts)")
    h = max(0.0, min(1.0, h))
    score = round(0.5 * prob + 0.5 * min(1.0, h * 1.35), 3)
    if prob > 0.5 and words:
        reasons.append("Language model flagged wording: " + ", ".join(f"'{w}'" for w in words))
    label = "scam" if score >= LABEL_THRESHOLDS[1] else "suspicious" if score >= LABEL_THRESHOLDS[0] else "safe"
    category = categorize(text) if label != "safe" else "Likely legitimate"
    if label == "safe" and not reasons:
        reasons.append("No scam indicators found")
    return {
        "score": score, "label": label, "category": category, "reasons": reasons[:8],
        "urls": urls, "domains": [d for d in (domain_of(u) for u in urls) if d],
        "model_version": MODEL_VERSION,
    }
