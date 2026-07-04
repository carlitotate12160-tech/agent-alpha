{
	admin off
}

# ── DuckDNS DNS-01 ACME ──────────────────────────────────────────────
# acme_dns will be set via environment variable DUCKDNS_API_TOKEN

# ── WP vuln — proxy to nginx backend on 8443 ─────────────────────────
wp-vuln.agentalpha.duckdns.org {
	tls {
		dns duckdns {env.DUCKDNS_API_TOKEN}
	}
	reverse_proxy https://127.0.0.1:8443 {
		header_up Host "vuln.wp.lab"
		header_up X-Forwarded-Proto https
		transport http {
			tls_insecure_skip_verify
		}
	}
}

# ── WP hardened — proxy to nginx backend on 8443 ─────────────────────
wp-hardened.agentalpha.duckdns.org {
	tls {
		dns duckdns {env.DUCKDNS_API_TOKEN}
	}
	reverse_proxy https://127.0.0.1:8443 {
		header_up Host "hardened.wp.lab"
		header_up X-Forwarded-Proto https
		transport http {
			tls_insecure_skip_verify
		}
	}
}

# ── SPA vuln — serve secret-bearing JS bundle ────────────────────────
spa-vuln.agentalpha.duckdns.org {
	tls {
		dns duckdns {env.DUCKDNS_API_TOKEN}
	}
	root * /home/ubuntu/agent-alpha/js_lab
	file_server
	@js path *.js
	header @js Content-Type "application/javascript; charset=utf-8"
}

# ── SPA hardened — serve benign JS bundle ────────────────────────────
spa-hardened.agentalpha.duckdns.org {
	tls {
		dns duckdns {env.DUCKDNS_API_TOKEN}
	}
	root * /home/ubuntu/agent-alpha/js_lab/hardened
	file_server
	@js path *.js
	header @js Content-Type "application/javascript; charset=utf-8"
}

# ── Laravel vuln — proxy to Laravel container on 9081 ────────────────
laravel-vuln.agentalpha.duckdns.org {
	tls {
		dns duckdns {env.DUCKDNS_API_TOKEN}
	}
	reverse_proxy 127.0.0.1:9081
}

# ── Laravel hardened — proxy to Laravel container on 9082 ────────────
laravel-hardened.agentalpha.duckdns.org {
	tls {
		dns duckdns {env.DUCKDNS_API_TOKEN}
	}
	reverse_proxy 127.0.0.1:9082
}
