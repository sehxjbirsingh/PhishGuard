# 🛡️ PhishGuard - Autonomous Phishing Detection & Quarantine Gateway

PhishGuard is a high-performance email and URL security defense system built with Python and Flask. It inspects incoming messages, evaluates heuristic indicators (shortened links, credential harvesting patterns, urgent language, sender domain mismatch), automatically quarantines high-risk emails, and provides security analysts with a clean, multi-page web application.

---

## 🌐 Multi-Page Architecture (Zero Screen Clutter, No Scrollbars)

The application is cleanly partitioned into dedicated webpages with all browser and element scrollbars completely hidden:

1. **Executive Dashboard (`/`):**
   - High-level security metrics: Total Analyzed, Quarantined Threats, Pending Review, Delivered Safe, Analyst Audits, and Fleet Risk Index.
   - Quick navigation cards to the dedicated workstation pages.
   - Recent 5 intercepted incidents summary.
2. **Email Threat Scanner (`/scan`):**
   - Dedicated workstation for screening emails and URLs.
   - 1-click test scenarios (*PayPal Phishing*, *Mailbox Storage Scam*, *Payroll Fraud*, *Safe Bank Alert*, *Lunch Invite*).
   - Instant "Live Preview Check" via `POST /api/analyze` (computes risk score without database writes).
   - "Scan & Quarantine" button with direct flow into the threat queue.
3. **Quarantine Queue & Message Repository (`/quarantine`):**
   - Dedicated full-width table view of all intercepted and processed messages.
   - Real-time search across senders, subjects, and threat reasons.
   - Status filters: `All`, `Quarantined`, `Needs Review`, `Delivered`.
   - Inspection modal with Analyst Dispositions (*Quarantine as Phishing* / *Deliver as Legitimate*).
4. **Model Evaluation & Confusion Matrix (`/evaluation`):**
   - Heuristic accuracy benchmark against ground-truth labels.
   - Confusion Matrix (TP, TN, FP, FN) with Accuracy, Precision, Recall, and F1-Score.
   - Drag-and-drop CSV dataset importer with downloadable sample CSV template.
5. **REST API Explorer (`/api-docs`):**
   - Developer documentation with endpoint definitions, curl samples, and a live test execution button.

---

## 🚀 How to Run the Website

### 1. Requirements
```bash
pip install flask
```

### 2. Start the Server
```bash
python app.py
```
*(or `python run.py`)*

### 3. Open in Browser
- **Dashboard:** [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
- **Email Scanner:** [http://127.0.0.1:5000/scan](http://127.0.0.1:5000/scan)
- **Quarantine Queue:** [http://127.0.0.1:5000/quarantine](http://127.0.0.1:5000/quarantine)
- **Model Evaluation:** [http://127.0.0.1:5000/evaluation](http://127.0.0.1:5000/evaluation)
- **API Explorer:** [http://127.0.0.1:5000/api-docs](http://127.0.0.1:5000/api-docs)

---

## 🧪 Run Automated Tests
```bash
python test_app.py
```
*(Runs 14 automated unit/integration tests across all routes and API endpoints)*
