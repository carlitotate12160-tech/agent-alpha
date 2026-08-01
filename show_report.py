#!/usr/bin/env python3
"""Show Omega report for latest platinumcredit engagement from PostgreSQL."""
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
print(f"Engagement: {eid}\n")

# Get all events
cur.execute("""
    SELECT event_type, agent, timestamp_utc, payload
    FROM agent_events
    WHERE engagement_id = %s
    ORDER BY sequence_number
""", (eid,))

events = cur.fetchall()
print(f"Events ({len(events)}):\n")
for evt in events:
    etype = evt[0]
    agent = evt[1] or "-"
    ts = evt[2]
    payload = evt[3]
    # Truncate payload for readability
    payload_str = str(payload)
    if len(payload_str) > 200:
        payload_str = payload_str[:200] + "..."
    print(f"  [{agent}] {etype}: {payload_str}")

# Get nodes
cur.execute("""
    SELECT payload FROM agent_events
    WHERE engagement_id = %s AND event_type = 'NodeDiscovered'
    ORDER BY sequence_number
""", (eid,))

nodes = cur.fetchall()
print(f"\n\nNodes ({len(nodes)}):\n")
for n in nodes:
    p = n[0]
    node_id = p.get('node_id', '?')
    node_type = p.get('node_type', '?')
    props = p.get('properties', {})
    # Show key properties
    label = props.get('label', '')
    url = props.get('url', '')
    version = props.get('version', '')
    slug = props.get('slug', '')
    if node_type == 'USER':
        print(f"  USER: id={node_id} slug={slug}")
    elif version:
        print(f"  {node_type}: id={node_id} label={label} version={version}")
    elif url:
        print(f"  {node_type}: id={node_id} url={url}")
    else:
        print(f"  {node_type}: id={node_id} label={label}")

# Get edges
cur.execute("""
    SELECT payload FROM agent_events
    WHERE engagement_id = %s AND event_type = 'EdgeDiscovered'
    ORDER BY sequence_number
""", (eid,))

edges = cur.fetchall()
print(f"\nEdges ({len(edges)}):\n")
for e in edges:
    p = e[0]
    print(f"  {p.get('source', '?')} --{p.get('relationship', '?')}--> {p.get('target', '?')}")

# Get findings (from WafBlocked and other event types)
cur.execute("""
    SELECT event_type, payload FROM agent_events
    WHERE engagement_id = %s
    AND event_type IN ('FindingRecorded', 'WafBlocked', 'EngagementRunCompleted')
    ORDER BY sequence_number
""", (eid,))

findings = cur.fetchall()
print(f"\nFindings & Run Status ({len(findings)}):\n")
for f in findings:
    print(f"  {f[0]}: {str(f[1])[:300]}")

conn.close()
