import requests
r = requests.post('http://localhost:8000/api/v1/auth/login',
    json={'email':'admin@ps281.dev','password':'Admin@PS281Change!'})
token = r.json()['access_token']
r3 = requests.get('http://localhost:8000/api/v1/hunts/46b31122-1921-4045-98b2-24c07407b53f',
    headers={'Authorization': f'Bearer {token}'})
d = r3.json()
print(f"Status: {d['status']}")
print(f"Hypotheses: {len(d.get('hypotheses', []))}")
print(f"Queries: {len(d.get('queries', []))}")
for q in d.get('queries', []):
    print(f"  [{q['query_language']}] {q['data_source']} - {q['status']}")
