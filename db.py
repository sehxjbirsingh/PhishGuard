import sqlite3
from pathlib import Path
from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    received_at TEXT DEFAULT CURRENT_TIMESTAMP,
    score REAL NOT NULL,
    verdict TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'quarantined',
    label INTEGER,
    reviewed_verdict TEXT
);
"""

DEMO = [
    ("billing@paypaI-security.example", "Action required: account suspended", "Verify your account immediately at http://paypal-verify.example/login to avoid suspension. Enter your password.", 1),
    ("it-helpdesk@company.example", "Mailbox storage notice", "Your mailbox is nearly full. Sign in at http://mailbox-reset.example to increase storage today.", 1),
    ("hr@company.example", "Updated direct deposit form", "Please review the attached payroll form and submit your bank details before end of day.", 1),
    ("alerts@bank.example", "New sign-in detected", "A sign-in was detected. If this was not you, visit https://bank.example/security using your saved bookmark.", 0),
    ("maya@company.example", "Lunch tomorrow?", "Are you free to grab lunch tomorrow around noon?", 0),
    ("news@library.example", "Your weekly reading list", "This week's staff picks are ready. Browse the catalogue at https://library.example/books.", 0),
]

def get_db():
    if 'db' not in g:
        path = Path(current_app.instance_path)
        path.mkdir(parents=True, exist_ok=True)
        db_file = path / current_app.config['DATABASE']
        g.db = sqlite3.connect(str(db_file))
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(_=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA)
        db.commit()

def seed_demo(force=False):
    db = get_db()
    if not force:
        count = db.execute('SELECT COUNT(*) FROM messages').fetchone()[0]
        if count > 0:
            return
    else:
        db.execute('DELETE FROM messages')
        db.commit()

    try:
        from .detector import analyze
    except ImportError:
        from detector import analyze

    for sender, subject, body, label in DEMO:
        a = analyze(sender, subject, body)
        db.execute(
            'INSERT INTO messages (sender, subject, body, score, verdict, reason, status, label) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (sender, subject, body, a['score'], a['verdict'], a['reason'], 'quarantined' if a['verdict'] == 'phishing' else 'delivered', label)
        )
    db.commit()
