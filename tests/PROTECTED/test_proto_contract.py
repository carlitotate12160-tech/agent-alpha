"""PROTECTED — Proto contract tests.

██████████████████████████████████████████████████████████
██ DO NOT MODIFY OR DELETE THIS FILE.                    ██
██ These tests are FROZEN contract assertions.          ██
██ If a test here fails, the IMPLEMENTATION is wrong,   ██
██ not the test.                                        ██
██████████████████████████████████████████████████████████

Frozen: 2026-06-15 (Phase 0 proto contract validated on Oracle ARM64)
"""
import importlib
import subprocess
import sys
from pathlib import Path

import pytest

PROTO_DIR = Path(__file__).resolve().parents[2] / "proto"
PROTO_FILE = PROTO_DIR / "a2a.proto"


@pytest.fixture(scope="module")
def proto_gen(tmp_path_factory):  # type: ignore[no-untyped-def]
    """Compile a2a.proto → Python. Runs once per module."""
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
def pb2(proto_gen):  # type: ignore[no-untyped-def]
    """Return the compiled a2a_pb2 module."""
    sys.path.insert(0, str(proto_gen))
    mod = importlib.import_module("a2a_pb2")
    yield mod
    sys.path.remove(str(proto_gen))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONTRACT 1: protoc compiles with zero errors
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def test_protoc_compiles_clean(proto_gen):  # type: ignore[no-untyped-def]
    """a2a.proto MUST compile without errors."""
    pb2_path = proto_gen / "a2a_pb2.py"
    assert pb2_path.exists()
    assert pb2_path.stat().st_size > 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONTRACT 2: AlphaHandoff services roundtrip
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def test_alpha_handoff_services_roundtrip(pb2):  # type: ignore[no-untyped-def]
    """AlphaHandoff with services field must survive serialization."""
    original = pb2.AlphaHandoff(
        hosts=["10.0.0.1"],
        services=[
            pb2.Service(name="nginx", version="1.25.3", cves=["CVE-2024-1234"], cf_protected=True),
        ],
        cf_protected_hosts=["cdn.target.com"],
        status=pb2.COMPLETE,
        findings_count=1,
        next_recommended="beta",
    )
    data = original.SerializeToString()
    restored = pb2.AlphaHandoff()
    restored.ParseFromString(data)

    assert restored.services[0].name == "nginx"
    assert restored.services[0].cves == ["CVE-2024-1234"]
    assert restored.services[0].cf_protected is True
    assert list(restored.cf_protected_hosts) == ["cdn.target.com"]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONTRACT 3: GammaHandoff ShellAccess typed roundtrip
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def test_gamma_shell_access_roundtrip(pb2):  # type: ignore[no-untyped-def]
    """GammaHandoff.shell_access is ShellAccess message, not bool."""
    original = pb2.GammaHandoff(
        shell_access=pb2.ShellAccess(
            obtained=True,
            shell_type="webshell",
            user_context="www-data",
            transport="http",
        ),
        status=pb2.COMPLETE,
        findings_count=1,
    )
    data = original.SerializeToString()
    restored = pb2.GammaHandoff()
    restored.ParseFromString(data)

    assert restored.shell_access.obtained is True
    assert restored.shell_access.shell_type == "webshell"
    assert restored.shell_access.user_context == "www-data"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONTRACT 4: DeltaHandoff DatabaseAccess list roundtrip
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def test_delta_db_access_list_roundtrip(pb2):  # type: ignore[no-untyped-def]
    """DeltaHandoff.db_access is repeated DatabaseAccess."""
    original = pb2.DeltaHandoff(
        db_access=[
            pb2.DatabaseAccess(db_type="mysql", host="10.0.0.5", port=3306, dump_possible=True),
            pb2.DatabaseAccess(
                db_type="postgresql", host="10.0.0.6", port=5432, dump_possible=False,
            ),
        ],
        privilege_level="root",
        status=pb2.COMPLETE,
        findings_count=2,
    )
    data = original.SerializeToString()
    restored = pb2.DeltaHandoff()
    restored.ParseFromString(data)

    assert len(restored.db_access) == 2
    assert restored.db_access[0].db_type == "mysql"
    assert restored.db_access[0].dump_possible is True
    assert restored.db_access[1].db_type == "postgresql"
    assert restored.privilege_level == "root"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONTRACT 5: ProofArtifact no plaintext secret
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def test_proof_artifact_no_plaintext_secret(pb2):  # type: ignore[no-untyped-def]
    """Credential.secret_ref must be vault ref. ProofArtifact.storage_ref must be non-empty."""
    # Credential: secret_ref is vault reference
    cred = pb2.Credential(
        username="admin",
        secret_ref="vault:secret/ssh/admin",
        service="ssh",
        access_level="root",
    )
    assert cred.secret_ref.startswith("vault:")

    # ProofArtifact: storage_ref must be non-empty (never inline content)
    pa = pb2.ProofArtifact(
        artifact_id="pa-001",
        type="screenshot",
        storage_ref="s3://proofs/eng_test/screenshot.png",
        agent="gamma",
    )
    assert pa.storage_ref != ""
    assert "password" not in pa.SerializeToString().decode("utf-8", errors="replace")
