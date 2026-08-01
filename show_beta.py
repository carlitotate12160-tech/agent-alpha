#!/usr/bin/env python3
"""Show Beta events for latest platinumcredit engagement."""
import json
import psycopg

dsn = "postgresql://agent_alpha_app:natanael12160@127.0.0.1:5432/agent_alpha"
conn = psycopg.connect(dsn, options="-c app.tenant_id=default")
cur = conn.cursor()

cur.execute("""
    SELECT engagement_id FROM agent_events
    WHERE event_type = 'EngagementCreated'
    AND payload->>'target' = 'platinumcredit.co.ke'
    ORDER BY timestamp_utc DESC LIMIT 1
""")
eid = cur.fetchone()[0]

print(f"Engagement: {eid}")
print("=" * 70)

# ALL events with agent='beta'
cur.execute("""
    SELECT event_type, agent, timestamp_utc, payload
    FROM agent_events
    WHERE engagement_id = %s AND agent = 'beta'
    ORDER BY sequence_number
""", (eid,))

beta_events = cur.fetchall()
print(f"\nBeta events ({len(beta_events)}):\n")
for evt in beta_events:
    etype = evt[0]
    ts = evt[2]
    p = evt[3]
    print(f"  [{etype}] {ts}")
    print(f"    {json.dumps(p, indent=2)[:500]}")
    print()

# Also check StateTransitioned for ACTIVE_APPROVED
cur.execute("""
    SELECT event_type, payload, timestamp_utc
    FROM agent_events
    WHERE engagement_id = %s AND event_type = 'StateTransitioned'
    ORDER BY sequence_number
""", (eid,))

states = cur.fetchall()
print(f"\nState transitions ({len(states)}):")
for s in states:
    p = s[1]
    print(f"  {p.get('from_state')} -> {p.get('to_state')}")

# Check for any EngagementRunCompleted
cur.execute("""
    SELECT event_type, agent, payload, timestamp_utc
    FROM agent_events
    WHERE engagement_id = %s
    AND event_type IN ('EngagementRunCompleted', 'EngagementRunStarted', 'EngagementRunRefused')
    ORDER BY sequence_number
""", (eid,))

runs = cur.fetchall()
print(f"\nRun events ({len(runs)}):")
for r in runs:
    print(f"  [{r[1] or 'CONDUCTOR'}] {r[0]}: {json.dumps(r[2])[:300]}")

conn.close()
