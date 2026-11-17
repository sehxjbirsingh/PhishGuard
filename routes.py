import csv
import io
from flask import (
    Blueprint, render_template, request, redirect, url_for, 
    flash, jsonify, Response
)

try:
    from .db import get_db, seed_demo
    from .detector import analyze
except ImportError:
    from db import get_db, seed_demo
    from detector import analyze

bp = Blueprint('main', __name__)

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
    # Recent high-risk or newest 5 alerts for the executive view
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
    redirect_target = data.get('redirect_to', 'main.quarantine_page')

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
    
    # If the user clicked from scanner page, redirect to quarantine page to see the new entry
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

# 5. Dedicated API Docs / Explorer Page
@bp.get('/api-docs')
def api_docs():
    return render_template('api_docs.html')
