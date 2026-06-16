"""Phase 0 — Proto contract tests for a2a.proto.

TEST CONTRACT (5 tests):
  1. `make proto` (grpcio-tools) runs without error → a2a_pb2.py generated
  2. Generated a2a_pb2.py importable in Python 3.12
  3. EngagementState.EMERGENCY_STOP is accessible as int value 4
  4. A2AMessage() instantiates with all fields at zero-value defaults
  5. AuthTransitionRequest with sow_hash=None still valid (optional field)

Run on Oracle ARM64 only (Rule 10).
"""
import importlib
import subprocess
import sys
from pathlib import Path

import pytest

PROTO_DIR = Path(__file__).resolve().parents[2] / "proto"
PROTO_FILE = PROTO_DIR / "a2a.proto"


# ── Fixtures ───────────────────────────────────────────────


@pytest.fixture(scope="module")
def proto_gen(tmp_path_factory):
    """Compile a2a.proto → Python, return output dir. Runs once per module.

    Mirrors the `make proto` Python codegen step:
      python -m grpc_tools.protoc -I proto --python_out=. --grpc_python_out=. proto/a2a.proto
    """
    out = tmp_path_factory.mktemp("proto_gen")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "grpc_tools.protoc",
            f"--proto_path={PROTO_DIR}",
            f"--python_out={out}",
            f"--grpc_python_out={out}",
            str(PROTO_FILE),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"protoc failed:\n{result.stderr}"
    return out


@pytest.fixture(scope="module")
def pb2(proto_gen):
    """Return the compiled a2a_pb2 module."""
    sys.path.insert(0, str(proto_gen))
    mod = importlib.import_module("a2a_pb2")
    yield mod
    sys.path.remove(str(proto_gen))


# ── Test 1: `make proto` runs without error ────────────────


def test_proto_codegen_succeeds(proto_gen):
    """grpc_tools.protoc compiles proto → zero errors, generated files exist."""
    pb2_path = proto_gen / "a2a_pb2.py"
    grpc_path = proto_gen / "a2a_pb2_grpc.py"
    assert pb2_path.exists(), "a2a_pb2.py was not generated"
    assert pb2_path.stat().st_size > 0, "a2a_pb2.py is empty"
    assert grpc_path.exists(), "a2a_pb2_grpc.py was not generated"


# ── Test 2: generated module importable in Python 3.12 ─────


def test_pb2_importable(pb2):
    """Generated a2a_pb2 imports cleanly and exposes the core symbols."""
    assert sys.version_info[:2] == (3, 12), "Phase 0 targets Python 3.12"
    assert hasattr(pb2, "A2AMessage")
    assert hasattr(pb2, "AuthTransitionRequest")
    assert hasattr(pb2, "AuthTransitionResponse")
    assert hasattr(pb2, "EmergencyStopRequest")
    assert hasattr(pb2, "EngagementState")
    assert hasattr(pb2, "AgentRole")
    assert hasattr(pb2, "MessageType")


# ── Test 3: EngagementState.EMERGENCY_STOP == 4 ────────────


def test_engagement_state_emergency_stop_value(pb2):
    """EngagementState.EMERGENCY_STOP is the int value 4."""
    assert pb2.EMERGENCY_STOP == 4
    assert pb2.EngagementState.Value("EMERGENCY_STOP") == 4
    # zero-value default sanity check
    assert pb2.CREATED == 0
    assert pb2.EngagementState.Value("CREATED") == 0


# ── Test 4: A2AMessage zero-value defaults ─────────────────


def test_a2a_message_zero_value_defaults(pb2):
    """A2AMessage() instantiates with every field at its zero-value default."""
    msg = pb2.A2AMessage()
    assert msg.engagement_id == ""
    assert msg.from_agent == pb2.CONDUCTOR  # AgentRole zero value
    assert msg.to_agent == pb2.CONDUCTOR
    assert msg.message_type == pb2.HANDOFF_READY  # MessageType zero value
    assert msg.timestamp_utc == ""
    assert msg.payload == b""
    assert msg.confidence == 0.0
    assert msg.requires_human is False

    # round-trips to empty bytes since all fields are default
    assert msg.SerializeToString() == b""


# ── Test 5: AuthTransitionRequest optional sow_hash ────────


def test_auth_transition_request_optional_sow_hash(pb2):
    """AuthTransitionRequest is valid with sow_hash unset / None (optional field)."""
    # sow_hash=None in the ctor is treated as "not set" — must not raise
    req = pb2.AuthTransitionRequest(
        engagement_id="eng_test",
        target_state=pb2.RECON_ONLY,
        requested_by=pb2.CONDUCTOR,
        reason="begin recon",
        sow_hash=None,
    )
    assert req.HasField("sow_hash") is False
    assert req.sow_hash == ""  # default for unset optional string

    # round-trip preserves the unset state
    restored = pb2.AuthTransitionRequest()
    restored.ParseFromString(req.SerializeToString())
    assert restored.HasField("sow_hash") is False
    assert restored.engagement_id == "eng_test"
    assert restored.target_state == pb2.RECON_ONLY

    # explicitly setting sow_hash marks presence
    req.sow_hash = "sha256:abc123"
    assert req.HasField("sow_hash") is True
    assert req.sow_hash == "sha256:abc123"
