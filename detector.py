import re

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
URGENT_WORDS = (
    "urgent", "immediately", "suspended", "verify", "action required", 
    "expires", "avoid suspension", "today", "unauthorized", "alert"
)
CREDENTIAL_WORDS = (
    "password", "bank details", "sign in", "login", "direct deposit", 
    "account", "credentials", "credit card", "ssn", "social security"
)
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly")

def analyze(sender="", subject="", body=""):
    sender_str = sender or ""
    subject_str = subject or ""
    body_str = body or ""
    
    text = f"{sender_str} {subject_str} {body_str}".lower()
    score = 0.05
    reasons = []

    urls = URL_PATTERN.findall(text)
    if urls:
        suspicious_links = [
            u for u in urls 
            if any(shortener in u.lower() for shortener in SHORTENERS) or u.lower().startswith('http://')
        ]
        if suspicious_links:
            score += 0.38
            reasons.append("Insecure HTTP or shortened link detected")

        if any(re.search(r"(paypa[l1]|bank|secure|verify|login|account|security|wallet|support).{0,25}(verify|secure|login|update|reset|auth)", u, re.IGNORECASE) for u in urls):
            score += 0.28
            reasons.append("Brand or account credential wording in URL")

    urgent_hits = [w for w in URGENT_WORDS if w in text]
    if urgent_hits:
        score += min(0.24, 0.08 + 0.04 * (len(urgent_hits) - 1))
        reasons.append(f"Urgent or threatening language ({', '.join(urgent_hits[:3])})")

    credential_hits = [w for w in CREDENTIAL_WORDS if w in text]
    if credential_hits:
        score += 0.19
        reasons.append(f"Requests sensitive information ({', '.join(credential_hits[:3])})")

    sender_lower = sender_str.lower()
    if re.search(r"@[^ ]+\.(example|test|top|xyz|tk|ml|ga|cf)\b", sender_lower) and any(x in sender_lower for x in ("paypa", "bank", "helpdesk", "support", "security", "admin")):
        score += 0.15
        reasons.append("Sender identity/domain mismatch or spoofing indicator")

    score = round(min(score, 0.99), 2)
    verdict = "phishing" if score >= 0.55 else "legitimate"
    
    reason_summary = "; ".join(reasons) if reasons else "No strong phishing indicators found"
    
    return {
        "score": score,
        "verdict": verdict,
        "reason": reason_summary,
        "reasons": reasons if reasons else ["Clean message headers & body"],
        "urls": urls
    }
