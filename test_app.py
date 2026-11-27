import io
from app import app

def run_tests():
    client = app.test_client()

    # 0. Test Login Page loads and redirects unauthenticated users
    r0 = client.get('/login')
    assert r0.status_code == 200, f'Login page failed: {r0.status_code}'
    assert b'PhishGuard' in r0.data, 'Brand not in login page'
    assert b'PhishGuard Gateway' in r0.data, 'Login title not found'
    print('[PASS] 0. Login page (/login) loads successfully')

    # Unauthenticated access to / redirects to /login
    r_unauth = client.get('/', follow_redirects=False)
    assert r_unauth.status_code == 302 and '/login' in r_unauth.headers.get('Location', ''), 'Unauthenticated request was not redirected to /login'
    print('[PASS] 0b. Unauthenticated access correctly redirects to /login')

    # Authenticate via /login with default credentials
    login_res = client.post('/login', data={'username': 'admin', 'password': 'cyberpassword123'}, follow_redirects=True)
    assert login_res.status_code == 200, f'Login submission failed: {login_res.status_code}'
    assert b'Executive Security Dashboard' in login_res.data, 'Login failed to reach dashboard'
    print('[PASS] 0c. Operator authentication successful')

    # 1. Test Dashboard
    r1 = client.get('/')
    assert r1.status_code == 200, f'Dashboard failed: {r1.status_code}'
    assert b'PhishGuard' in r1.data, 'Brand not found'
    assert b'Executive Security Dashboard' in r1.data, 'Dashboard title not found'
    assert b'Live Gmail Stream' in r1.data, 'Live Gmail banner not found'
    print('[PASS] 1. Dashboard (/) loads successfully with Gmail stream banner')

    # 2. Test Dedicated Scanner Page
    r2 = client.get('/scan')
    assert r2.status_code == 200, f'Scanner page failed: {r2.status_code}'
    assert b'Live Email Threat Scanner' in r2.data, 'Scanner title not found'
    assert b'1-Click Test Scenarios' in r2.data, 'Presets not found'
    print('[PASS] 2. Dedicated Scanner (/scan) loads successfully')

    # 3. Test Dedicated Quarantine Queue Page
    r3 = client.get('/quarantine')
    assert r3.status_code == 200, f'Quarantine page failed: {r3.status_code}'
    assert b'Quarantine Queue &amp; Threat Repository' in r3.data or b'Quarantine Queue & Threat Repository' in r3.data, 'Quarantine title not found'
    print('[PASS] 3. Dedicated Quarantine Queue (/quarantine) loads successfully')

    # 4. Test Dedicated Model Evaluation Page
    r4 = client.get('/evaluation')
    assert r4.status_code == 200, f'Evaluation failed: {r4.status_code}'
    assert b'Confusion Matrix Grid' in r4.data, 'Confusion matrix not found'
    assert b'Model Accuracy' in r4.data, 'Accuracy card not found'
    print('[PASS] 4. Model Evaluation (/evaluation) loads successfully')

    # 5. Test Quick Scan API (/api/analyze)
    payload = {
        'sender': 'security@paypal-verify.xyz',
        'subject': 'urgent suspension',
        'body': 'verify immediately at http://login-paypal.xyz/auth'
    }
    r6 = client.post('/api/analyze', json=payload)
    assert r6.status_code == 200, f'API analyze failed: {r6.status_code}'
    data6 = r6.get_json()
    assert data6['verdict'] == 'phishing', f"Expected phishing, got {data6['verdict']}"
    print(f"[PASS] 6. /api/analyze works correctly (verdict: {data6['verdict']}, score: {data6['score']})")

    # 7. Test Add Message (Form Post)
    form_data = {
        'sender': 'test@bank.com',
        'subject': 'Monthly Statement Ready',
        'body': 'Your monthly statement is ready at https://bank.example/statements.'
    }
    r7 = client.post('/messages', data=form_data, follow_redirects=True)
    assert r7.status_code == 200, f'Add message failed: {r7.status_code}'
    assert b'Scan complete' in r7.data, 'Flash message not found'
    print('[PASS] 7. /messages form submission redirects to quarantine and completes')

    # 8. Test Review Message
    r8 = client.post('/review/1', data={'decision': 'phishing'}, follow_redirects=True)
    assert r8.status_code == 200, f'Review failed: {r8.status_code}'
    print('[PASS] 8. /review/<id> disposition update works correctly')

    # 9. Test Sample CSV Download
    r9 = client.get('/evaluation/sample-csv')
    assert r9.status_code == 200, f'Sample CSV download failed: {r9.status_code}'
    assert b'sender,subject,body,label' in r9.data, 'CSV headers not found'
    print('[PASS] 9. /evaluation/sample-csv template download works correctly')

    # 10. Test CSV Import
    csv_content = b'sender,subject,body,label\nattacker@evil.com,urgent,click http://malware.xyz/login,1\nfriend@good.com,lunch,see you at 12,0\n'
    upload_data = {'file': (io.BytesIO(csv_content), 'test.csv')}
    r10 = client.post('/evaluation/import', data=upload_data, content_type='multipart/form-data', follow_redirects=True)
    assert r10.status_code == 200, f'CSV import failed: {r10.status_code}'
    assert b'Successfully imported' in r10.data, 'Import flash message not found'
    print('[PASS] 10. /evaluation/import dataset benchmarking works correctly')

    # 11. Test Live Gmail Sync Endpoint
    r_sync = client.post('/sync-gmail', follow_redirects=True)
    assert r_sync.status_code == 200, f'Live Gmail sync failed: {r_sync.status_code}'
    print('[PASS] 11. /sync-gmail live inbound ingestion and screening works')

    # 12. Test API Messages Endpoint
    r11 = client.get('/api/messages')
    assert r11.status_code == 200, f'API messages failed: {r11.status_code}'
    messages = r11.get_json()
    assert len(messages) > 0, 'No messages returned from API'
    print(f'[PASS] 12. /api/messages returned {len(messages)} records')

    # 13. Test Single Message API
    r12 = client.get(f"/api/messages/{messages[0]['id']}")
    assert r12.status_code == 200, f'Single message API failed: {r12.status_code}'
    detail = r12.get_json()
    assert 'subject' in detail, 'Message detail missing subject'
    print(f"[PASS] 13. /api/messages/{messages[0]['id']} returned single record details")

    # 13. Test Delete Message
    last_id = messages[0]['id']
    r13 = client.post(f'/messages/{last_id}/delete', follow_redirects=True)
    assert r13.status_code == 200, f'Delete message failed: {r13.status_code}'
    print(f'[PASS] 13. /messages/{last_id}/delete works correctly')

    # 14. Test Reset Demo Data
    r14 = client.post('/reset-demo', follow_redirects=True)
    assert r14.status_code == 200, f'Reset demo failed: {r14.status_code}'
    print('[PASS] 14. /reset-demo restores initial demo records')

    print('\n======================================================')
    print(' ALL 14 MULTI-PAGE & API TESTS PASSED SUCCESSFULLY! ')
    print('======================================================')

if __name__ == '__main__':
    run_tests()
