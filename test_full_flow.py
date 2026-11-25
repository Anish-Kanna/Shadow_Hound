import requests, time

r = requests.post('http://localhost:8000/api/v1/auth/login', json={'email':'admin@ps281.dev','password':'Admin@PS281Change!'})
token = r.json()['access_token']
headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

r2 = requests.post('http://localhost:8000/api/v1/hunts', json={
    'title': 'Full Execution & Report Test',
    'trigger_type': 'analyst_request',
    'trigger_context': {'description': 'Suspicious PowerShell execution'}
}, headers=headers)
hunt_id = r2.json()['id']
print(f'Hunt created: {hunt_id}')

print('Waiting 10 seconds for query planning...')
time.sleep(10)

r3 = requests.get(f'http://localhost:8000/api/v1/hunts/{hunt_id}', headers=headers)
d = r3.json()
print(f'Status: {d.get("status")}')
queries = d.get('queries', [])
print(f'Queries count: {len(queries)}')

if queries:
    for q in queries:
        q_id = q['id']
        print(f'Approving query {q_id} ({q["query_language"]})...')
        r4 = requests.post(f'http://localhost:8000/api/v1/hunts/{hunt_id}/queries/{q_id}/approve', json={}, headers=headers)
        print(f'Approve status: {r4.status_code}')

    print('Waiting 10 seconds for execution, evidence aggregation, and report generation...')
    time.sleep(10)

    r5 = requests.get(f'http://localhost:8000/api/v1/hunts/{hunt_id}', headers=headers)
    d5 = r5.json()
    print(f'Final Hunt Status: {d5.get("status")}')
    print(f'Final Verdict: {d5.get("verdict")}')
    print(f'Evidence Count: {len(d5.get("evidence", []))}')
