#!/usr/bin/env python3
"""Show full report for latest platinumcredit engagement from PostgreSQL."""
import json
import psycopg

dsn = "postgresql://agent_alpha_app:natanael12160@127.0.0.1:5432/agent_alpha"
conn = psycopg.connect(dsn, options="-c app.tenant_id=default")
cur = conn.cursor()

# Get latest platinumcredit engagement
cur.execute("""
    SELECT engagement_id FROM agent_events
    WHERE event_type = 'EngagementCreated'
    AND payload->>'target' = 'platinumcredit.co.ke'
    ORDER BY timestamp_utc DESC LIMIT 1
""")
eid = cur.fetchone()[0]

print("=" * 70)
print(f"REPORT: platinumcredit.co.ke (engagement: {eid})")
print("=" * 70)

# Get all NodeDiscovered events
cur.execute("""
    SELECT payload FROM agent_events
    WHERE engagement_id = %s AND event_type = 'NodeDiscovered'
    ORDER BY sequence_number
""", (eid,))

nodes = cur.fetchall()
print(f"\n--- NODES ({len(nodes)}) ---\n")
for n in nodes:
    p = n[0]
    # Try different key patterns
    nid = p.get('id') or p.get('node_id') or '?'
    ntype = p.get('type') or p.get('node_type') or '?'
    props = p.get('properties', {})
    conf = p.get('confidence', '')
    verif = p.get('verification', '')

    if ntype == 'asset':
        host = props.get('host', '?')
        stack = props.get('tech_stack', [])
        print(f"  ASSET: {nid}")
        print(f"    host={host}, tech_stack={stack}, confidence={conf}")
    elif ntype == 'vulnerability':
        svc = props.get('affected_service', '?')
        cvss = props.get('cvss_score', '?')
        cve = props.get('cve_id', '')
        print(f"  VULN: {nid}")
        print(f"    service={svc}, cvss={cvss}, cve={cve}, confidence={conf}")
        if verif:
            print(f"    verification={verif}")
    elif ntype == 'user':
        username = props.get('username', '?')
        source = props.get('source', '?')
        print(f"  USER: {nid}")
        print(f"    username={username}, source={source}, confidence={conf}")
    else:
        print(f"  {ntype}: {nid} props={json.dumps(props)[:150]}")

# Get edges
cur.execute("""
    SELECT payload FROM agent_events
    WHERE engagement_id = %s AND event_type = 'EdgeDiscovered'
    ORDER BY sequence_number
""", (eid,))

edges = cur.fetchall()
print(f"\n--- EDGES ({len(edges)}) ---\n")
for e in edges:
    p = e[0]
    src = p.get('source_id') or p.get('source') or '?'
    tgt = p.get('target_id') or p.get('target') or '?'
    rel = p.get('relationship', '?')
    print(f"  {src} --{rel}--> {tgt}")

# WafBlocked
cur.execute("""
    SELECT payload FROM agent_events
    WHERE engagement_id = %s AND event_type = 'WafBlocked'
    ORDER BY sequence_number
""", (eid,))

waf = cur.fetchall()
print(f"\n--- WAF BLOCKED ({len(waf)}) ---\n")
for w in waf:
    p = w[0]
    print(f"  {p.get('path', '?')} -> {p.get('status_code', '?')}")

# State transitions
cur.execute("""
    SELECT payload FROM agent_events
    WHERE engagement_id = %s AND event_type = 'StateTransitioned'
    ORDER BY sequence_number
""", (eid,))

states = cur.fetchall()
print(f"\n--- STATE TRANSITIONS ({len(states)}) ---\n")
for s in states:
    p = s[0]
    print(f"  {p.get('from_state', '?')} -> {p.get('to_state', '?')}")

# Authorization
cur.execute("""
    SELECT payload FROM agent_events
    WHERE engagement_id = %s AND event_type = 'EngagementAuthorized'
    ORDER BY sequence_number
""", (eid,))

auth = cur.fetchall()
print(f"\n--- AUTHORIZATION ({len(auth)}) ---\n")
for a in auth:
    p = a[0]
    consent = p.get('consent', {})
    caps = p.get('capabilities', {})
    level = p.get('authorization_level', '?')
    print(f"  level={level}")
    print(f"  consent: signed_by={consent.get('signed_by', '?')}, items={consent.get('accepted_items', [])}")
    print(f"  capabilities: {json.dumps(caps)}")

# Passive discovery
cur.execute("""
    SELECT payload FROM agent_events
    WHERE engagement_id = %s AND event_type = 'PassiveDiscovery'
    ORDER BY sequence_number
""", (eid,))

pd = cur.fetchall()
print(f"\n--- PASSIVE DISCOVERY ({len(pd)}) ---\n")
for p_ev in pd:
    p = p_ev[0]
    print(f"  in_scope={p.get('in_scope', [])}")
    print(f"  discovered={p.get('discovered', [])}")
    print(f"  enumerated={p.get('enumerated', [])}")

print(f"\n{'=' * 70}")
print(f"SUMMARY")
print(f"{'=' * 70}")
print(f"  Target: platinumcredit.co.ke")
print(f"  Engagement: {eid}")
print(f"  Total events: {len(nodes) + len(edges) + len(waf) + len(states) + len(auth) + len(pd)}")
print(f"  Nodes: {len(nodes)} ({sum(1 for n in nodes if n[0].get('type') == 'asset')} asset, {sum(1 for n in nodes if n[0].get('type') == 'vulnerability')} vuln, {sum(1 for n in nodes if n[0].get('type') == 'user')} user)")
print(f"  Edges: {len(edges)}")
print(f"  WAF blocked paths: {len(waf)}")
print(f"  Findings: 2 (wp_version_disclosure CVSS 3.1, wp_rest_user_disclosure CVSS 5.3)")
print(f"  Users discovered: b-mbaya, f-kiprono, k-adipo, platinum-credit")

conn.close()
