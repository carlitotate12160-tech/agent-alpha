"""PROTECTED — Proto contract tests (NEW frozen contract).

██████████████████████████████████████████████████████████
██ DO NOT MODIFY OR DELETE THIS FILE.                    ██
██ These tests are FROZEN contract assertions.          ██
██ If a test here fails, the IMPLEMENTATION is wrong,   ██
██ not the test.                                        ██
██████████████████████████████████████████████████████████

Frozen: 2026-06-16 (Phase 0 RESET — single canonical HandoffPayload,
no per-agent handoff variants). Requires `make proto` to have generated
agent_alpha/a2a/a2a_pb2.py first.
"""

import pytest

from agent_alpha.a2a import a2a_pb2


def test_engagement_state_values():
    assert a2a_pb2.CREATED == 0
    assert a2a_pb2.RECON_ONLY == 1
    assert a2a_pb2.ACTIVE_APPROVED == 2
    assert a2a_pb2.OFFENSIVE_APPROVED == 3
    assert a2a_pb2.EMERGENCY_STOP == 4


def test_phase_status_values():
    assert a2a_pb2.PENDING == 0
    assert a2a_pb2.RUNNING == 1
    assert a2a_pb2.COMPLETE == 2
    assert a2a_pb2.FAILED == 3
    assert a2a_pb2.BLOCKED == 4


def test_a2a_message_instantiates():
    msg = a2a_pb2.A2AMessage()
    assert msg.engagement_id == ""
    assert msg.confidence == 0.0
    assert not msg.requires_human


def test_handoff_payload_roundtrip():
    h = a2a_pb2.HandoffPayload(
        from_phase="alpha",
        to_phase="conductor",
        status=a2a_pb2.COMPLETE,
        findings_count=5,
        confidence=0.87,
    )
    serialized = h.SerializeToString()
    deserialized = a2a_pb2.HandoffPayload()
    deserialized.ParseFromString(serialized)
    assert deserialized.findings_count == 5
    assert deserialized.confidence == pytest.approx(0.87, abs=1e-5)


def test_auth_transition_sow_hash_optional():
    req = a2a_pb2.AuthTransitionRequest(
        engagement_id="eng_001",
        target_state=a2a_pb2.OFFENSIVE_APPROVED,
        requested_by="user_eko",
        # sow_hash omitted — must be valid
    )
    assert req.engagement_id == "eng_001"
    assert req.sow_hash == b""


def test_no_per_agent_handoff_types():
    # Lyndon failure #6 guard:
    # AlphaHandoff, GammaHandoff, DeltaHandoff must NOT exist
    assert not hasattr(a2a_pb2, "AlphaHandoff")
    assert not hasattr(a2a_pb2, "GammaHandoff")
    assert not hasattr(a2a_pb2, "DeltaHandoff")
    assert not hasattr(a2a_pb2, "ShellAccess")
