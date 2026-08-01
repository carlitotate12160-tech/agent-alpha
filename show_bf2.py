#!/usr/bin/env python3
"""Show events for eng_fc97fe14 (latest bernofarm)."""
import psycopg

conn = psycopg.connect(
    "postgresql://agent_alpha_app:natanael12160@127.0.0.1:5432/agent_alpha",
    options="-c app.tenant_id=default",
)
cur = conn.cursor()

eid = "eng_fc97fe14"
print(f"Engagement: {eid}\n")

# Event breakdown
cur.execute("""
    SELECT event_type, COUNT(*) as cnt
    FROM agent_events
    WHERE engagement_id = %s
    GROUP BY event_type
    ORDER BY event_type
""", (eid,))
rows = cur.fetchall()
print("Event breakdown:")
for r in rows:
    print(f"  {r[0]}: {r[1]}")

if not rows:
    print("  (no events found)")

# Nodes
cur.execute("""
    SELECT payload FROM agent_events
    WHERE engagement_id = %s AND event_type = 'NodeDiscovered'
    ORDER BY sequence_number
""", (eid,))
nodes = cur.fetchall()
print(f"\nNodes ({len(nodes)}):")
for n in nodes:
    p = n[0]
    nid = p.get('id', '?')
    ntype = p.get('type', '?')
    props = p.get('properties', {})
    print(f"  {ntype}: {nid} host={props.get('host','')} stack={props.get('tech_stack','')}")

# WafBlocked
cur.execute("""
    SELECT payload FROM agent_events
    WHERE engagement_id = %s AND event_type = 'WafBlocked'
    ORDER BY sequence_number
""", (eid,))
waf = cur.fetchall()
print(f"\nWAF blocked ({len(waf)}):")
for w in waf:
    p = w[0]
    print(f"  {p.get('path', '?')} -> {p.get('status_code', '?')}")

# Origin direct attempts
cur.execute("""
    SELECT payload FROM agent_events
    WHERE engagement_id = %s AND event_type = 'OriginDirectAttempt'
    ORDER BY sequence_number
""", (eid,))
origins = cur.fetchall()
print(f"\nOrigin direct attempts ({len(origins)}):")
for o in origins:
    p = o[0]
    print(f"  {p.get('host', '?')} via {p.get('origin_ip', '?')}")

# All bernofarm engagements
cur.execute("""
    SELECT engagement_id, timestamp_utc
    FROM agent_events
    WHERE event_type = 'EngagementCreated'
    AND payload->>'target' = 'bernofarm.com'
    ORDER BY timestamp_utc DESC LIMIT 5
""")
print("\nRecent bernofarm engagements:")
for r in cur.fetchall():
    print(f"  {r[0]} | {r[1]}")

conn.close()
