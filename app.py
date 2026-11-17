"""
PhishGuard - Email & URL Phishing Detection Gateway
Main Application Entry Point
"""
import sys
from pathlib import Path

# Ensure the project directory is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from __init__ import create_app

app = create_app()

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  🛡️  PhishGuard Web Application Running!")
    print("  📍 Local URL: http://127.0.0.1:5000")
    print("  📊 Dashboard: http://127.0.0.1:5000/")
    print("  🔍 Scanner: http://127.0.0.1:5000/scan")
    print("  🛡️  Quarantine Queue: http://127.0.0.1:5000/quarantine")
    print("  📈 Model Evaluation: http://127.0.0.1:5000/evaluation")
    print("  🔌 REST API Docs: http://127.0.0.1:5000/api-docs")
    print("="*60 + "\n")
    app.run(host='127.0.0.1', port=5000, debug=False)
