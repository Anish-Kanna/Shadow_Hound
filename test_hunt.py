import requests, time

# Login
r = requests.post('http://localhost:8000/api/v1/auth/login',
    json={'email':'admin@ps281.dev','password':'Admin@PS281Change!'})
token = r.json()['access_token']
print('Login OK')

# Create hunt
r2 = requests.post('http://localhost:8000/api/v1/hunts', json={
    'title':'Live Demo - Lateral Movement',
    'trigger_type':'analyst_request',
    'trigger_context':{'description':'Suspicious PowerShell with EncodedCommand on DC01'}
}, headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}, timeout=120)
print(f'Create status: {r2.status_code}')
hunt = r2.json()
hunt_id = hunt['id']
print(f'Hunt ID: {hunt_id}')

# Wait for background processing
print('Waiting 40 seconds for Gemini AI to process...')
time.sleep(40)

# Check status
r3 = requests.get(f'http://localhost:8000/api/v1/hunts/{hunt_id}',
    headers={'Authorization': f'Bearer {token}'})
data = r3.json()
status = data.get('status', 'unknown')
hyps = data.get('hypotheses', [])
queries = data.get('queries', [])
print(f'Status: {status}')
print(f'Hypotheses: {len(hyps)}')
print(f'Queries: {len(queries)}')
if hyps:
    for h in hyps:
        print(f'  - {h.get("description","")} | MITRE: {h.get("mitre_techniques",[])}')
if queries:
    for q in queries:
        print(f'  - [{q.get("query_language","")}] {q.get("data_source","")} | Status: {q.get("status","")}')
