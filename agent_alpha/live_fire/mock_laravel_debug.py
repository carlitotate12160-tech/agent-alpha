#!/usr/bin/env python3
"""Mock Laravel debug page for DB chain field-prove.

Serves a single page at /trigger-error that mimics a Laravel Whoops debug page
leaking DB_USERNAME + DB_PASSWORD (and other env noise) in the HTML table format
that `iter_env_leaks` expects.

Run on Oracle:
    python3 agent_alpha/live_fire/mock_laravel_debug.py 8080 &
"""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

_DEBUG_BODY = """<!DOCTYPE html>
<html>
<head><title>Whoops! There was an error.</title></head>
<body>
<div class="exception">Illuminate\\Database\\QueryException</div>
<h2>Environment Variables</h2>
<table>
<tr><td>DB_USERNAME</td><td>testuser</td></tr>
<tr><td>DB_PASSWORD</td><td>testpass</td></tr>
<tr><td>DB_HOST</td><td>10.0.0.19</td></tr>
<tr><td>DB_PORT</td><td>3306</td></tr>
<tr><td>DB_DATABASE</td><td>clientdb</td></tr>
<tr><td>APP_KEY</td><td>base64:dGhpcy1pcy1hLXRlc3Qta2V5</td></tr>
<tr><td>APP_DEBUG</td><td>true</td></tr>
<tr><td>REDIS_PASSWORD</td><td>redis123</td></tr>
<tr><td>MAIL_PASSWORD</td><td>mail123</td></tr>
</table>
<footer>Laravel v10.3.1 (PHP v8.2.4)</footer>
</body>
</html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/trigger-error":
            body = _DEBUG_BODY.encode()
            self.send_response(500)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/login":
            body = b"<html><body><form action='/login' method='POST'><input name='username'/><input name='password'/><button>Login</button></form></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass  # silence


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(("0.0.0.0", port), _Handler)  # nosec B104 — mock debug page, bind-all is intentional for field-prove
    print(f"Mock Laravel debug page on http://0.0.0.0:{port}/trigger-error")
    server.serve_forever()


if __name__ == "__main__":
    main()
