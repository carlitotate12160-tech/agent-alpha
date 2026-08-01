#!/usr/bin/env python3
"""Filter for PG/engagement/key lines only."""
import sys

lines = sys.stdin.readlines()
for l in lines:
    if any(k in l for k in ['[PG]', '[ENGAGEMENT]', '[AUTH]', '[ALPHA] Done', '[GRAPH]', '[BETA]', '[OMEGA]', '[FINDING]', 'ERROR', 'Traceback', 'PG]', 'report']):
        print(l, end='')
