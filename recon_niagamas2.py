#!/usr/bin/env python3
"""Recon niagamas.com — try HTTP and HTTPS."""
import httpx
import socket

target = "niagamas.com"

# DNS
try:
    ips = socket.getaddrinfo(target, None)
    resolved = list({ip[4][0] for ip in ips})
    print(f"DNS resolve: {resolved}")
except Exception as e:
    print(f"DNS error: {e}")

# Try HTTP
for scheme in ["https", "http"]:
    try:
        r = httpx.get(f"{scheme}://{target}/", follow_redirects=True, timeout=20, verify=False)
        print(f"\n{scheme.upper()} Status: {r.status_code}")
        print(f"Final URL: {r.url}")
        print(f"Body size: {len(r.text)} bytes")
        print("\nHeaders:")
        for k, v in r.headers.items():
            print(f"  {k}: {v}")
        
        cf = r.headers.get("server", "")
        cf_ray = r.headers.get("cf-ray", "")
        if "cloudflare" in cf.lower() or cf_ray:
            print(">>> CLOUDFLARE DETECTED")
        else:
            print(">>> No Cloudflare")
        
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
        print(f"Tech hints: {techs}")
        print(f"\nBody preview:\n{r.text[:500]}")
        break
    except Exception as e:
        print(f"\n{scheme.upper()} error: {e}")

# Check WP endpoints
for path in ["/wp-json/", "/readme.html", "/wp-login.php"]:
    for scheme in ["https", "http"]:
        try:
            r = httpx.get(f"{scheme}://{target}{path}", follow_redirects=True, timeout=15, verify=False)
            print(f"{path} ({scheme}): {r.status_code}, {len(r.text)} bytes")
            break
        except Exception:
            continue
