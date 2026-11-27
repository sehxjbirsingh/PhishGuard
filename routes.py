import csv
import io
import re
import imaplib
import email
from email.header import decode_header
from flask import (
    Blueprint, render_template, request, redirect, url_for, 
    flash, jsonify, Response, session
)

try:
    from .db import get_db, seed_demo
    from .detector import analyze
except ImportError:
    from db import get_db, seed_demo
    from detector import analyze

bp = Blueprint('main', __name__)

def decode_mime_words(s):
    if not s:
        return ""
    try:
        decoded_fragments = decode_header(s)
        res = []
        for frag, encoding in decoded_fragments:
            if isinstance(frag, bytes):
                try:
                    res.append(frag.decode(encoding or 'utf-8', errors='ignore'))
                except Exception:
                    res.append(frag.decode('latin1', errors='ignore'))
            else:
                res.append(str(frag))
        return "".join(res)
    except Exception:
        return str(s)

def get_email_body(msg):
    body = ""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdisp = str(part.get("Content-Disposition", ""))
                if ctype == "text/plain" and "attachment" not in cdisp:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode('utf-8', errors='ignore')
                elif ctype == "text/html" and not body and "attachment" not in cdisp:
                    payload = part.get_payload(decode=True)
                    if payload:
                        clean_text = re.sub(r'<[^>]+>', ' ', payload.decode('utf-8', errors='ignore'))
                        body = clean_text
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode('utf-8', errors='ignore')
    except Exception:
        pass
    return body.strip()

def fetch_live_gmail(email_address, app_password, max_emails=5):
    clean_password = (app_password or '').replace(' ', '')
    mail = imaplib.IMAP4_SSL("imap.gmail.com", 993, timeout=12)
    mail.login(email_address, clean_password)
    mail.select("INBOX")
    
    status, messages = mail.search(None, "ALL")
    if status != "OK" or not messages or not messages[0]:
        mail.logout()
        return []
        
    email_ids = messages[0].split()
    recent_ids = email_ids[-max_emails:]
    results = []
    
    for eid in reversed(recent_ids):
        res, data = mail.fetch(eid, "(RFC822)")
        if res != "OK" or not data:
            continue
        for response_part in data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                sender = decode_mime_words(msg.get("From", "unknown@gmail.com"))
                subject = decode_mime_words(msg.get("Subject", "Incoming Message"))
                body = get_email_body(msg)
                if not body:
                    body = subject or "No body content"
                results.append({
                    "sender": sender,
                    "subject": subject,
                    "body": body,
                    "date": msg.get("Date", "")
                })
                break
    mail.logout()
    return results

# Before request guard: require login for application views
@bp.before_request
def require_login():
    public_endpoints = ('main.login', 'static', 'main.api_analyze', 'main.api_messages')
    if request.endpoint and not request.endpoint.startswith('static'):
        if request.endpoint not in public_endpoints and not session.get('user'):
            return redirect(url_for('main.login'))

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip() or 'Security_Analyst'
        password = request.form.get('password', '').strip()
        gmail_address = request.form.get('gmail_address', '').strip()
        gmail_app_password = request.form.get('gmail_app_password', '').strip()

        session['user'] = username
        if gmail_address:
            session['gmail'] = gmail_address
            session['gmail_password'] = gmail_app_password
            flash(f'Signed in as {username}. Gmail connected: {gmail_address}', 'success')
        else:
            flash(f'Signed in successfully as {username}.', 'success')
        return redirect(url_for('main.dashboard'))

    if session.get('user'):
        return redirect(url_for('main.dashboard'))
    return render_template('login.html')

@bp.get('/logout')
def logout():
    session.clear()
    flash('Signed out successfully.', 'info')
    return redirect(url_for('main.login'))

@bp.post('/connect-gmail')
def connect_gmail():
    gmail_address = request.form.get('gmail_address', '').strip()
    gmail_app_password = request.form.get('gmail_app_password', '').strip()

    if not gmail_address:
        flash('Please provide a valid Gmail address.', 'error')
        return redirect(request.referrer or url_for('main.dashboard'))

    session['gmail'] = gmail_address
    session['gmail_password'] = gmail_app_password
    flash(f'Gmail inbox connected: {gmail_address}. Ready to sync live messages.', 'success')
    return redirect(request.referrer or url_for('main.dashboard'))

@bp.post('/sync-gmail')
def sync_gmail():
    gmail_address = session.get('gmail')
    gmail_password = session.get('gmail_password')
    force_demo = request.form.get('demo') == '1'

    live_messages = []
    sync_mode = "Live IMAP"

    # Try connecting to live Gmail via IMAP if credentials provided
    if gmail_address and gmail_password and not force_demo:
        try:
            live_messages = fetch_live_gmail(gmail_address, gmail_password, max_emails=5)
        except Exception as exc:
            err_msg = str(exc)
            if "AUTHENTICATIONFAILED" in err_msg or "Invalid credentials" in err_msg:
                flash("Gmail authentication failed: Please use a 16-character Google App Password (myaccount.google.com/apppasswords). Falling back to simulated live incoming stream.", "warning")
            else:
                flash(f"Live Gmail connection issue ({err_msg}). Falling back to simulated live incoming feed.", "warning")
            live_messages = []

    # If no IMAP credentials or connection failed, provide realistic live stream simulation
    if not live_messages:
        sync_mode = "Live Feed Simulator"
        live_messages = [
            {
                "sender": f"security-alert@{session.get('gmail', 'gmail.com').split('@')[0]}-auth.xyz",
                "subject": "Action required: Suspicious sign-in detected on your Gmail account",
                "body": "We detected an unauthorized sign-in from an unknown device. Verify your credentials immediately at http://gmail-auth-verify.top/login to avoid suspension. Enter your password.",
                "date": "Just now"
            },
            {
                "sender": "no-reply@accounts.google.example",
                "subject": "Security notice: 2-Step Verification turned on",
                "body": "2-Step Verification is active for your Google Account. If you made this change, no action is needed. Review activity at https://myaccount.google.example/security.",
                "date": "Just now"
            },
            {
                "sender": "it-support@internal-team.example",
                "subject": "Urgent: Direct deposit payroll mismatch notification",
                "body": "Your bank details require verification before salary release today. Please submit your account details and password at http://bit.ly/pay-verify.",
                "date": "Just now"
            }
        ]

    db = get_db()
    count = 0
    threats_found = 0

    for item in live_messages:
        s_sender = item['sender']
        s_subject = item['subject']
        s_body = item['body']
        
        a = analyze(s_sender, s_subject, s_body)
        status = 'quarantined' if a['verdict'] == 'phishing' else ('review' if a['score'] >= 0.35 else 'delivered')
        if a['verdict'] == 'phishing':
            threats_found += 1

        db.execute(
            'INSERT INTO messages (sender, subject, body, score, verdict, reason, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (s_sender, s_subject, s_body, a['score'], a['verdict'], a['reason'], status)
        )
        count += 1

    db.commit()
    flash(f"Live Sync Complete ({sync_mode}): Screened {count} incoming emails. Intercepted {threats_found} threats into quarantine.", "success")
    return redirect(url_for('main.quarantine_page'))

def get_stats():
    db = get_db()
    raw_rows = db.execute('SELECT * FROM messages ORDER BY id DESC').fetchall()
    rows = [dict(r) for r in raw_rows]
    total = len(rows)
    quarantined = sum(1 for r in rows if r['status'] == 'quarantined')
    review = sum(1 for r in rows if r['status'] == 'review')
    delivered = sum(1 for r in rows if r['status'] == 'delivered')
    overridden = sum(1 for r in rows if r['reviewed_verdict'] is not None)
    avg_score = round(sum(r['score'] for r in rows) / total * 100, 1) if total else 0.0

    return {
        "rows": rows,
        "stats": {
            "total": total,
            "quarantined": quarantined,
            "review": review,
            "delivered": delivered,
            "overridden": overridden,
            "avg_score": avg_score
        }
    }

# 1. Executive Dashboard Page
@bp.get('/')
def dashboard():
    data = get_stats()
    recent_alerts = data["rows"][:5]
    return render_template('dashboard.html', stats=data["stats"], recent_alerts=recent_alerts)

# 2. Dedicated Scanner Page
@bp.get('/scan')
def scanner_page():
    return render_template('scanner.html')

# 3. Dedicated Quarantine & Threat Queue Page
@bp.get('/quarantine')
def quarantine_page():
    data = get_stats()
    return render_template('quarantine.html', messages=data["rows"], stats=data["stats"])

# Form submission for scanning
@bp.post('/messages')
def add_message():
    is_json = request.is_json
    data = request.get_json(silent=True) or request.form

    sender = data.get('sender', '').strip()
    subject = data.get('subject', '').strip()
    body = data.get('body', '').strip()

    if not sender or not subject or not body:
        msg = 'Please fill in sender, subject, and message body.'
        if is_json:
            return jsonify({'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('main.scanner_page'))

    a = analyze(sender, subject, body)
    status = 'quarantined' if a['verdict'] == 'phishing' else ('review' if a['score'] >= 0.35 else 'delivered')

    db = get_db()
    cur = db.execute(
        'INSERT INTO messages (sender, subject, body, score, verdict, reason, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (sender, subject, body, a['score'], a['verdict'], a['reason'], status)
    )
    db.commit()
    inserted_id = cur.lastrowid

    verdict_display = 'Phishing Threat Quarantined' if a['verdict'] == 'phishing' else ('Flagged for Review' if status == 'review' else 'Legitimate - Safe to Deliver')
    risk_pct = int(round(a['score'] * 100))
    flash_msg = f"Scan complete: {verdict_display} ({risk_pct}% risk score)."

    if is_json:
        return jsonify({
            'success': True,
            'id': inserted_id,
            'status': status,
            'score': a['score'],
            'verdict': a['verdict'],
            'reason': a['reason'],
            'reasons': a.get('reasons', []),
            'message': flash_msg
        })

    category = 'error' if a['verdict'] == 'phishing' else ('warning' if status == 'review' else 'success')
    flash(flash_msg, category)
    return redirect(url_for('main.quarantine_page'))

@bp.post('/api/analyze')
def api_analyze():
    data = request.get_json(silent=True) or request.form
    sender = data.get('sender', '').strip()
    subject = data.get('subject', '').strip()
    body = data.get('body', '').strip()

    if not sender and not subject and not body:
        return jsonify({'error': 'Please provide email text to analyze.'}), 400

    result = analyze(sender, subject, body)
    status = 'quarantined' if result['verdict'] == 'phishing' else ('review' if result['score'] >= 0.35 else 'delivered')
    result['status'] = status
    return jsonify(result)

@bp.post('/review/<int:message_id>')
def review(message_id):
    decision = request.form.get('decision')
    db = get_db()
    if decision not in ('phishing', 'legitimate'):
        flash('Choose a valid reviewer decision (phishing or legitimate).', 'error')
    else:
        status = 'quarantined' if decision == 'phishing' else 'delivered'
        db.execute(
            'UPDATE messages SET reviewed_verdict=?, status=? WHERE id=?',
            (decision, status, message_id)
        )
        db.commit()
        flash(f'Message #{message_id} reviewed and updated to {status.upper()}.', 'success')
    
    referrer = request.referrer
    if referrer and ('/quarantine' in referrer or '/messages' in referrer):
        return redirect(referrer)
    return redirect(url_for('main.quarantine_page'))

@bp.post('/messages/<int:message_id>/delete')
def delete_message(message_id):
    db = get_db()
    db.execute('DELETE FROM messages WHERE id=?', (message_id,))
    db.commit()
    flash(f'Message #{message_id} deleted successfully.', 'info')
    
    referrer = request.referrer
    if referrer and ('/quarantine' in referrer or '/messages' in referrer):
        return redirect(referrer)
    return redirect(url_for('main.quarantine_page'))

@bp.post('/reset-demo')
def reset_demo():
    seed_demo(force=True)
    flash('Database restored to default demo messages.', 'info')
    return redirect(url_for('main.dashboard'))

@bp.get('/api/messages')
def api_messages():
    rows = get_db().execute(
        'SELECT id, sender, subject, score, verdict, status, reason, received_at, reviewed_verdict FROM messages ORDER BY id DESC'
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@bp.get('/api/messages/<int:message_id>')
def api_message_detail(message_id):
    row = get_db().execute('SELECT * FROM messages WHERE id=?', (message_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Message not found'}), 404
    return jsonify(dict(row))

# 4. Dedicated Model Evaluation Page
@bp.get('/evaluation')
def evaluation():
    db = get_db()
    raw_rows = db.execute('SELECT id, sender, subject, score, verdict, status, label, received_at FROM messages WHERE label IS NOT NULL ORDER BY id DESC').fetchall()
    rows = [dict(r) for r in raw_rows]
    
    tp = sum(1 for r in rows if r['label'] == 1 and r['verdict'] == 'phishing')
    tn = sum(1 for r in rows if r['label'] == 0 and r['verdict'] == 'legitimate')
    fp = sum(1 for r in rows if r['label'] == 0 and r['verdict'] == 'phishing')
    fn = sum(1 for r in rows if r['label'] == 1 and r['verdict'] == 'legitimate')
    total = len(rows)

    accuracy = round((tp + tn) / total * 100, 1) if total else 0.0
    precision = round(tp / (tp + fp) * 100, 1) if (tp + fp) else 0.0
    recall = round(tp / (tp + fn) * 100, 1) if (tp + fn) else 0.0
    f1 = round(2 * (precision * recall) / (precision + recall), 1) if (precision + recall) else 0.0

    return render_template(
        'evaluation.html',
        rows=rows,
        tp=tp,
        tn=tn,
        fp=fp,
        fn=fn,
        total=total,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1=f1
    )

@bp.get('/evaluation/sample-csv')
def download_sample_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['sender', 'subject', 'body', 'label'])
    writer.writerow(['security@secure-update-paypal.xyz', 'Security notice: Update account credentials', 'Please sign in immediately at http://paypal.login-auth.top/verify to prevent suspension.', '1'])
    writer.writerow(['support@internal-company.com', 'Quarterly All-Hands Meeting', 'The slides and recording for Q4 all-hands are posted on the intranet at https://intranet.company.com/q4.', '0'])
    writer.writerow(['payroll@company-paycheck.info', 'Urgent: direct deposit account mismatch', 'Action required today: Verify your bank details and password at http://bit.ly/pay-verify to receive payroll.', '1'])
    writer.writerow(['team-lead@company.com', 'Code review requested for pull request #42', 'Hey team, please review the PR when you have a free moment: https://github.com/company/repo/pull/42', '0'])
    
    csv_data = output.getvalue()
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=phishguard_sample_dataset.csv"}
    )

@bp.post('/evaluation/import')
def import_csv():
    file = request.files.get('file')
    if not file or file.filename == '':
        flash('Please select a valid CSV file to upload.', 'error')
        return redirect(url_for('main.evaluation'))
    
    try:
        content = file.stream.read().decode('utf-8-sig')
        reader = csv.DictReader(io.StringIO(content))
        db = get_db()
        count = 0
        
        for row in reader:
            sender = row.get('sender', 'dataset@example.com').strip()
            subject = row.get('subject', 'Imported Email/URL').strip()
            body = (row.get('body') or row.get('url') or '').strip()
            
            raw_label = row.get('label') or row.get('phish_id') or row.get('phishing') or '0'
            label = 1 if str(raw_label).strip().lower() in ('1', 'true', 'yes', 'phish', 'phishing') else 0
            
            if not body:
                continue
                
            a = analyze(sender, subject, body)
            status = 'quarantined' if a['verdict'] == 'phishing' else 'delivered'
            
            db.execute(
                'INSERT INTO messages (sender, subject, body, score, verdict, reason, status, label) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (sender, subject, body, a['score'], a['verdict'], a['reason'], status, label)
            )
            count += 1
            
        db.commit()
        flash(f'Successfully imported and evaluated {count} labeled records from CSV.', 'success')
    except Exception as exc:
        flash(f'Could not import CSV: {exc}', 'error')
        
    return redirect(url_for('main.evaluation'))
