#!/usr/bin/env python3
"""Verify platinumcredit data in PostgreSQL with correct tenant_id."""
import psycopg

dsn = "postgresql://agent_alpha_app:natanael12160@127.0.0.1:5432/agent_alpha"
conn = psycopg.connect(dsn, options="-c app.tenant_id=default")
cur = conn.cursor()

# Total
cur.execute("SELECT COUNT(*) FROM agent_events")
print(f"Total events: {cur.fetchone()[0]}")

# Latest platinumcredit engagement
cur.execute("""
    SELECT engagement_id, timestamp_utc, payload->>'target' as target
    FROM agent_events
    WHERE event_type = 'EngagementCreated'
    AND payload->>'target' = 'platinumcredit.co.ke'
    ORDER BY timestamp_utc DESC LIMIT 5
""")
print("\nPlatinumcredit engagements:")
for r in cur.fetchall():
    print(f"  {r[0]} | {r[1]} | {r[2]}")

# Get latest eid
cur.execute("""
    SELECT engagement_id FROM agent_events
    WHERE event_type = 'EngagementCreated'
    AND payload->>'target' = 'platinumcredit.co.ke'
    ORDER BY timestamp_utc DESC LIMIT 1
""")
latest = cur.fetchone()
if latest:
    eid = latest[0]
    print(f"\nLatest engagement: {eid}")

    # Event breakdown
    cur.execute("""
        SELECT event_type, COUNT(*) as cnt
        FROM agent_events
        WHERE engagement_id = %s
        GROUP BY event_type
        ORDER BY event_type
    """, (eid,))
    print(f"\nEvent breakdown for {eid}:")
    for r in cur.fetchall():
        print(f"  {r[0]}: {r[1]}")

    # Findings
    cur.execute("""
        SELECT event_type, payload->>'vulnerability_id' as vid, payload
        FROM agent_events
        WHERE engagement_id = %s
        AND event_type = 'FindingRecorded'
        ORDER BY timestamp_utc
    """, (eid,))
    print(f"\nFindings for {eid}:")
    for r in cur.fetchall():
        print(f"  {r[0]} | {r[1]}")

    # Beta
    cur.execute("""
        SELECT event_type, payload
        FROM agent_events
        WHERE engagement_id = %s
        AND agent = 'beta'
        ORDER BY timestamp_utc
    """, (eid,))
    print(f"\nBeta events for {eid}:")
    for r in cur.fetchall():
        print(f"  {r[0]} | {str(r[1])[:120]}")

conn.close()
