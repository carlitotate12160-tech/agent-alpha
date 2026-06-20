"""Temporary CI gate test: intentionally fails to verify branch protection.

This file exists only to prove that the quality-gate status check blocks
merges on failure. It will be removed immediately after verification.
"""

from __future__ import annotations


def test_ci_gate_intentionally_fails() -> None:
    assert False, "CI gate test: this failure is intentional"
