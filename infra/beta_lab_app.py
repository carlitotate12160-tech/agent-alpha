import os
from flask import Flask, request, make_response

app = Flask(__name__)

# Config: vuln vs hardened (from environment variable)
IS_VULN = os.environ.get('VULN', 'false').lower() == 'true'
VULN_CREDENTIALS = {"admin": "admin"}  # vuln: admin/admin works
HARDENED_CREDENTIALS = {}  # hardened: no default creds work

# Session storage (in-memory for simplicity)
sessions = {}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # Return login form with password input
        return '''
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
<form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
</form>
</body>
</html>
'''
    
    # POST: check credentials
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Check against credentials (configured per container)
    allowed_creds = VULN_CREDENTIALS if IS_VULN else HARDENED_CREDENTIALS
    
    if username in allowed_creds and allowed_creds[username] == password:
        # Success: set session cookie
        session_id = f"session_{username}"
        sessions[session_id] = {"username": username}
        response = make_response("<html>admin dashboard, welcome administrator</html>")
        response.set_cookie('session', session_id, httponly=True, path='/')
        return response
    else:
        # Failed: return login form again
        return '''
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
<form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
</form>
<p>Invalid credentials</p>
</body>
</html>
''', 401

@app.route('/dashboard')
def dashboard():
    session_cookie = request.cookies.get('session')
    if session_cookie and session_cookie in sessions:
        return f"<html>Welcome {sessions[session_cookie]['username']}</html>"
    return "Unauthorized", 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
