#!/usr/bin/env python3
"""Debug PostgreSQL connection and table state."""
import psycopg

dsn = "postgresql://agent_alpha_app:natanael12160@127.0.0.1:5432/agent_alpha"

# Connect WITHOUT tenant_id option (raw)
conn = psycopg.connect(dsn)
cur = conn.cursor()

# Check if table exists
cur.execute("""
    SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'agent_events'
""")
tables = cur.fetchall()
print(f"agent_events table exists: {len(tables) > 0}")

if tables:
    cur.execute("SELECT COUNT(*) FROM agent_events")
    print(f"Total rows: {cur.fetchone()[0]}")

    cur.execute("SELECT engagement_id, event_type, tenant_id FROM agent_events LIMIT 10")
    for r in cur.fetchall():
        print(f"  {r[0]} | {r[1]} | tenant={r[2]}")
else:
    # List all tables
    cur.execute("""
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public'
    """)
    print("Tables in public schema:")
    for r in cur.fetchall():
        print(f"  {r[0]}")

conn.close()

# Now connect WITH tenant_id option (like PostgresEventStore does)
print("\n--- With tenant_id option ---")
conn2 = psycopg.connect(dsn, options="-c app.tenant_id=default")
cur2 = conn2.cursor()

cur2.execute("""
    SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'agent_events'
""")
tables2 = cur2.fetchall()
print(f"agent_events table exists: {len(tables2) > 0}")

if tables2:
    cur2.execute("SELECT COUNT(*) FROM agent_events")
    print(f"Total rows: {cur2.fetchone()[0]}")

    cur2.execute("SELECT engagement_id, event_type, tenant_id FROM agent_events LIMIT 10")
    for r in cur2.fetchall():
        print(f"  {r[0]} | {r[1]} | tenant={r[2]}")

conn2.close()
