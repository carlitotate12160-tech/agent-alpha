#!/usr/bin/env python3
"""Recon niagamas.com from local."""
import httpx

target = "niagamas.com"
r = httpx.get(f"https://{target}/", follow_redirects=True, timeout=20, verify=False)
print(f"Status: {r.status_code}, Size: {len(r.text)}")
print(f"Server: {r.headers.get('server', '')}")
print(f"CF-Ray: {r.headers.get('cf-ray', '')}")

body = r.text.lower()
techs = []
if "wp-content" in body or "wp-includes" in body:
    techs.append("WordPress")
if "wp-json" in body:
    techs.append("WP REST API")
if "cloudways" in body:
    techs.append("Cloudways")
if "<frame" in body or "<iframe" in body:
    techs.append("Frameset/iframe")
print(f"Tech: {techs}")
print(f"\nBody preview:\n{r.text[:500]}")

# Check WP endpoints
for path in ["/wp-json/", "/readme.html", "/wp-login.php", "/wp-json/wp/v2/users"]:
    try:
        r2 = httpx.get(f"https://{target}{path}", follow_redirects=True, timeout=15, verify=False)
        print(f"\n{path}: {r2.status_code}, {len(r2.text)} bytes")
    except Exception as e:
        print(f"\n{path}: error - {e}")
