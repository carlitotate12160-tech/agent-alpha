#!/usr/bin/env python3
"""Recon niagamas.com — check tech stack, WAF, headers."""
import httpx
import socket

target = "niagamas.com"

# 1. DNS resolve
try:
    ips = socket.getaddrinfo(target, None)
    resolved = list({ip[4][0] for ip in ips})
    print(f"DNS resolve: {resolved}")
except Exception as e:
    print(f"DNS error: {e}")

# 2. HTTP headers
try:
    r = httpx.get(f"https://{target}/", follow_redirects=True, timeout=15, verify=False)
    print(f"\nHTTP Status: {r.status_code}")
    print(f"Final URL: {r.url}")
    print(f"Body size: {len(r.text)} bytes")
    print("\nHeaders:")
    for k, v in r.headers.items():
        print(f"  {k}: {v}")
    
    cf = r.headers.get("server", "")
    cf_ray = r.headers.get("cf-ray", "")
    print(f"\nServer: {cf}")
    print(f"CF-Ray: {cf_ray}")
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
    if "woocommerce" in body:
        techs.append("WooCommerce")
    if "joomla" in body:
        techs.append("Joomla")
    if "drupal" in body:
        techs.append("Drupal")
    if "laravel" in body:
        techs.append("Laravel")
    if "<frame" in body or "<iframe" in body:
        techs.append("Frameset/iframe")
    if "cloudways" in body:
        techs.append("Cloudways")
    print(f"\nTech hints: {techs}")
    
    print(f"\nBody preview (first 500 chars):\n{r.text[:500]}")
    
except Exception as e:
    print(f"HTTP error: {e}")

# 3. Check wp-json
try:
    r2 = httpx.get(f"https://{target}/wp-json/", timeout=15, verify=False)
    print(f"\n/wp-json/ status: {r2.status_code}, size: {len(r2.text)} bytes")
except Exception as e:
    print(f"\n/wp-json/ error: {e}")

# 4. Check readme.html
try:
    r3 = httpx.get(f"https://{target}/readme.html", timeout=15, verify=False)
    print(f"/readme.html status: {r3.status_code}, size: {len(r3.text)} bytes")
except Exception as e:
    print(f"/readme.html error: {e}")
