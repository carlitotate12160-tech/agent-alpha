#!/usr/bin/env python3
"""Verify PostgreSQL data persistence."""
import psycopg

conn = psycopg.connect(
    "postgresql://agent_alpha_app:natanael12160@127.0.0.1:5432/agent_alpha"
)
cur = conn.cursor()

# Total events
cur.execute("SELECT COUNT(*) FROM agent_events")
total = cur.fetchone()[0]
print(f"Total events in PostgreSQL: {total}")

# Recent engagements
cur.execute("""
    SELECT engagement_id, event_type, payload->>'target' as target
    FROM agent_events
    WHERE event_type = 'EngagementCreated'
    ORDER BY timestamp_utc DESC
    LIMIT 10
""")
print("\nRecent engagements:")
for r in cur.fetchall():
    print(f"  {r[0]} | {r[1]} | target={r[2]}")

# Events for latest platinumcredit engagement
cur.execute("""
    SELECT engagement_id, event_type, COUNT(*) as cnt
    FROM agent_events
    WHERE engagement_id IN (
        SELECT engagement_id FROM agent_events
        WHERE payload->>'target' = 'platinumcredit.co.ke'
        AND event_type = 'EngagementCreated'
        ORDER BY timestamp_utc DESC LIMIT 1
    )
    GROUP BY engagement_id, event_type
    ORDER BY engagement_id, event_type
""")
print("\nEvents for latest platinumcredit.co.ke engagement:")
for r in cur.fetchall():
    print(f"  {r[0]} | {r[1]} | count={r[2]}")

# Check for graph nodes
cur.execute("""
    SELECT engagement_id, event_type, COUNT(*) as cnt
    FROM agent_events
    WHERE event_type IN ('NodePersisted', 'GraphUpdated', 'PassiveDiscovery')
    AND engagement_id IN (
        SELECT engagement_id FROM agent_events
        WHERE payload->>'target' = 'platinumcredit.co.ke'
        AND event_type = 'EngagementCreated'
    )
    GROUP BY engagement_id, event_type
    ORDER BY engagement_id, event_type
""")
print("\nGraph/node events for platinumcredit.co.ke:")
for r in cur.fetchall():
    print(f"  {r[0]} | {r[1]} | count={r[2]}")

conn.close()
