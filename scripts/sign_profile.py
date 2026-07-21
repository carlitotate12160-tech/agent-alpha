#!/usr/bin/env python3
"""scripts/sign_profile.py — CLI to produce a signed EngagementProfile JSON.

Usage:
    python -m scripts.sign_profile \
        --engagement-id a1-fp \
        --client-id lab \
        --target alpha-ai.web.id \
        --authorized-origin 168.110.192.62 \
        > a1_profile.signed.json

Or write directly to a file:
    python -m scripts.sign_profile \
        --engagement-id a1-fp \
        --client-id lab \
        --target alpha-ai.web.id \
        --authorized-origin 168.110.192.62 \
        --output a1_profile.signed.json

The output is the JSON consumed by ``a1_validation_runner --profile <path>``.
The file contains the profile fields and a SHA-256 signature computed from the
canonical JSON representation — any post-signing mutation will fail
``load_signed_profile()`` verification.
"""

from __future__ import annotations

import argparse
import json
import sys

from agent_alpha.conductor.engagement_profile import (
    EngagementProfile,
    dump_signed_profile,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Produce a signed EngagementProfile JSON file for --profile"
    )
    parser.add_argument("--engagement-id", required=True, help="Engagement ID")
    parser.add_argument("--client-id", required=True, help="Client ID")
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="Target hostname (repeatable)",
    )
    parser.add_argument(
        "--authorized-origin",
        action="append",
        default=[],
        help="Authorized origin IP (repeatable)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output file path (default: stdout)",
    )
    args = parser.parse_args(argv)

    profile = EngagementProfile(
        engagement_id=args.engagement_id,
        client_id=args.client_id,
        targets=frozenset(args.target),
        authorized_origins=frozenset(args.authorized_origin),
    )

    envelope = dump_signed_profile(profile)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2)
            f.write("\n")
        print(f"Signed profile written to {args.output}", file=sys.stderr)
    else:
        json.dump(envelope, sys.stdout, indent=2)
        print(file=sys.stdout)  # trailing newline

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
