#!/usr/bin/env python3
"""Recon gamota.com — check tech stack, WAF, headers."""
import httpx
import socket

target = "gamota.com"

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
    
    # Check for Cloudflare
    cf = r.headers.get("server", "")
    cf_ray = r.headers.get("cf-ray", "")
    print(f"\nServer: {cf}")
    print(f"CF-Ray: {cf_ray}")
    if "cloudflare" in cf.lower() or cf_ray:
        print(">>> CLOUDFLARE DETECTED")
    else:
        print(">>> No Cloudflare")
    
    # Check tech hints in body
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
    if "react" in body:
        techs.append("React")
    if "next.js" in body or "__next" in body:
        techs.append("Next.js")
    if "angular" in body:
        techs.append("Angular")
    if "vue" in body:
        techs.append("Vue")
    if "<frame" in body or "<iframe" in body:
        techs.append("Frameset/iframe")
    print(f"\nTech hints: {techs}")
    
    # Show first 500 chars of body
    print(f"\nBody preview (first 500 chars):\n{r.text[:500]}")
    
except Exception as e:
    print(f"HTTP error: {e}")

# 3. Check crt.sh for subdomains
try:
    r2 = httpx.get(f"https://crt.sh/?q=%.{target}&output=json", timeout=30, verify=False)
    if r2.status_code == 200:
        import json
        data = r2.json()
        subs = set()
        for entry in data:
            name = entry.get("name_value", "")
            for n in name.split("\n"):
                n = n.strip().lstrip("*.")
                if n and target in n:
                    subs.add(n)
        print(f"\ncrt.sh subdomains ({len(subs)}):")
        for s in sorted(subs)[:20]:
            print(f"  {s}")
    else:
        print(f"\ncrt.sh status: {r2.status_code}")
except Exception as e:
    print(f"\ncrt.sh error: {e}")
