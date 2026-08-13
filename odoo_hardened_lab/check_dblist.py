import xmlrpc.client
s = xmlrpc.client.ServerProxy("http://localhost:8069/xmlrpc/2/db")
try:
    result = s.list()
    print("DB LIST:", result)
except Exception as e:
    print("DB LIST FAILED:", e)
