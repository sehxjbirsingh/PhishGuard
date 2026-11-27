import os
import re
import csv
from pathlib import Path

# Machine Learning via Scikit-Learn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

# Module-level model state
_VECTORIZER = None
_MODEL = None
_METRICS = {}
_PHISHTANK_URLS = set()
_PHISHTANK_DOMAINS = set()
_TOP_FEATURES = []

def extract_domain(url):
    try:
        clean = re.sub(r"^https?://", "", url.lower())
        return clean.split("/")[0].split(":")[0]
    except Exception:
        return ""

def load_phishtank_feed():
    phishtank_path = Path(__file__).resolve().parent / "data" / "phishtank_dataset.csv"
    urls = set()
    domains = set()
    records = []

    if phishtank_path.exists():
        try:
            with open(phishtank_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    url = (row.get('url') or '').strip()
                    target = (row.get('target') or '').strip()
                    if url:
                        urls.add(url.lower())
                        dom = extract_domain(url)
                        if dom:
                            domains.add(dom)
                        # Add synthetic sample to reinforce URL knowledge in text corpus
                        records.append((f"security-alert@{dom}", f"URGENT: Suspicious activity on {target} account", f"Please verify your credentials immediately at {url} to avoid suspension.", 1))
        except Exception:
            pass

    return urls, domains, records

def train_supervised_model():
    global _VECTORIZER, _MODEL, _METRICS, _PHISHTANK_URLS, _PHISHTANK_DOMAINS, _TOP_FEATURES

    # 1. Load PhishTank threat intelligence
    _PHISHTANK_URLS, _PHISHTANK_DOMAINS, phishtank_samples = load_phishtank_feed()

    # 2. Load benchmark labeled email dataset
    dataset_path = Path(__file__).resolve().parent / "data" / "training_emails.csv"
    X_raw = []
    y_raw = []

    if dataset_path.exists():
        try:
            with open(dataset_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    sender = row.get('sender', '')
                    subject = row.get('subject', '')
                    body = row.get('body', '')
                    label_str = row.get('label', '0')
                    try:
                        label = int(label_str)
                    except ValueError:
                        label = 1 if 'phish' in label_str.lower() or '1' in label_str else 0
                    
                    combined_text = f"{sender} {subject} {body}".lower()
                    X_raw.append(combined_text)
                    y_raw.append(label)
        except Exception:
            pass

    # Add PhishTank augmented records
    for sender, subj, body, lbl in phishtank_samples:
        X_raw.append(f"{sender} {subj} {body}".lower())
        y_raw.append(lbl)

    if not X_raw:
        # Fallback safeguard in case files missing
        X_raw = ["billing@paypal-verify.xyz urgent verify password http://login.xyz", "friend@company.com meeting notes for sprint 12"]
        y_raw = [1, 0]

    # 3. Supervised Pipeline: TF-IDF Vectorizer + Logistic Regression Classifier
    _VECTORIZER = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=4000,
        sublinear_tf=True,
        token_pattern=r"(?u)\b[\w\.\-]{2,}\b"
    )

    X_vectors = _VECTORIZER.fit_transform(X_raw)

    # Train-test split for evaluation benchmarks
    X_train, X_test, y_train, y_test = train_test_split(
        X_vectors, y_raw, test_size=0.25, random_state=42, stratify=y_raw
    )

    _MODEL = LogisticRegression(C=2.5, max_iter=1000, random_state=42)
    _MODEL.fit(X_train, y_train)

    # Calculate supervised performance metrics
    y_pred = _MODEL.predict(X_test)
    y_prob = _MODEL.predict_proba(X_test)[:, 1]

    acc = round(accuracy_score(y_test, y_pred) * 100, 1)
    prec = round(precision_score(y_test, y_pred, zero_division=0) * 100, 1)
    rec = round(recall_score(y_test, y_pred, zero_division=0) * 100, 1)
    f1 = round(f1_score(y_test, y_pred, zero_division=0) * 100, 1)

    cm = confusion_matrix(y_test, y_pred)
    tn = int(cm[0][0]) if len(cm) > 0 else 0
    fp = int(cm[0][1]) if len(cm) > 0 else 0
    fn = int(cm[1][0]) if len(cm) > 1 else 0
    tp = int(cm[1][1]) if len(cm) > 1 else 0

    # Extract top learned supervised feature coefficients
    feature_names = _VECTORIZER.get_feature_names_out()
    coefs = _MODEL.coef_[0]
    top_indices = coefs.argsort()[::-1][:20]
    _TOP_FEATURES = [(feature_names[i], round(float(coefs[i]), 3)) for i in top_indices]

    _METRICS = {
        "algorithm": "Supervised Learning: TF-IDF Vectorizer + Logistic Regression (L2)",
        "dataset": "PhishTank Threat Feed + Benchmark Email Corpus",
        "total_samples": len(X_raw),
        "train_samples": X_train.shape[0],
        "test_samples": X_test.shape[0],
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "top_features": _TOP_FEATURES
    }

# Initialize model on startup
train_supervised_model()

def get_model_metrics():
    return _METRICS

def analyze(sender="", subject="", body=""):
    """
    Evaluates incoming live email using the Supervised Machine Learning Model
    trained on PhishTank and the labeled benchmark dataset.
    """
    global _VECTORIZER, _MODEL, _PHISHTANK_URLS, _PHISHTANK_DOMAINS
    if _MODEL is None or _VECTORIZER is None:
        train_supervised_model()

    sender_str = sender or ""
    subject_str = subject or ""
    body_str = body or ""
    combined_text = f"{sender_str} {subject_str} {body_str}".lower()

    # 1. Supervised Machine Learning Prediction via TF-IDF + Logistic Regression
    X_vec = _VECTORIZER.transform([combined_text])
    probabilities = _MODEL.predict_proba(X_vec)[0]
    # probabilities[1] is the supervised probability of phishing
    raw_prob = float(probabilities[1])

    # 2. Check for explicit PhishTank Verified Feed URLs
    urls = URL_PATTERN.findall(combined_text)
    matched_phishtank = []
    for u in urls:
        u_lower = u.lower()
        dom = extract_domain(u_lower)
        if u_lower in _PHISHTANK_URLS or dom in _PHISHTANK_DOMAINS:
            matched_phishtank.append(u)

    # 3. Supervised Model Explainability: Extract top contributing words in this email
    feature_names = _VECTORIZER.get_feature_names_out()
    feature_indices = X_vec.nonzero()[1]
    word_weights = []
    for idx in feature_indices:
        w = _MODEL.coef_[0][idx]
        if w > 0.15:
            word_weights.append((feature_names[idx], round(float(w), 2)))

    word_weights.sort(key=lambda x: x[1], reverse=True)
    top_words = [item[0] for item in word_weights[:4]]

    # If PhishTank verified match found, adjust probability to reflect threat intelligence
    if matched_phishtank:
        raw_prob = max(raw_prob, 0.98)

    # Final calibrated probability (0.00 to 0.99)
    prob_score = round(min(max(raw_prob, 0.02), 0.99), 2)
    verdict = "phishing" if prob_score >= 0.55 else "legitimate"

    # Build human-readable audit reasons from the supervised features
    reasons = []
    if matched_phishtank:
        reasons.append(f"PhishTank Feed Match: Verified malicious URL identified ({matched_phishtank[0]})")
    if top_words:
        reasons.append(f"Supervised ML Features: [{', '.join(top_words)}]")
    if prob_score >= 0.55 and not reasons:
        reasons.append(f"High TF-IDF Threat Probability ({int(prob_score*100)}%) learned from dataset")
    if prob_score < 0.35 and not reasons:
        reasons.append("Supervised Model: Legitimate Communication Profile")

    reason_summary = "; ".join(reasons) if reasons else "Supervised Model: Clean email features"

    return {
        "score": prob_score,
        "verdict": verdict,
        "reason": reason_summary,
        "reasons": reasons,
        "urls": urls,
        "ml_features": word_weights[:5],
        "phishtank_matches": matched_phishtank,
        "model_type": "Supervised TF-IDF + Logistic Regression (PhishTank)"
    }
