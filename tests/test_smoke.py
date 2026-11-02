"""
Smoke test: verify liboqs-python installs and exposes the required PQC algorithms.

Run with: make smoke
On failure: stop and report before proceeding to any other milestone.
"""
import json
import platform
import sys
from pathlib import Path


def _results_dir() -> Path:
    root = Path(__file__).parent.parent
    d = root / "results" / "raw"
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_liboqs_import():
    """liboqs-python must be importable."""
    import oqs  # noqa: F401


def test_mlkem_available():
    """At least one ML-KEM variant must be enabled (required for C2/C3)."""
    import oqs

    kems = oqs.get_enabled_kem_mechanisms()
    ml_kem = [k for k in kems if k.startswith("ML-KEM")]
    assert ml_kem, (
        f"No ML-KEM-* found in enabled KEMs.\nAll enabled: {kems}\n"
        "Install a newer liboqs build that includes ML-KEM."
    )
    assert "ML-KEM-768" in ml_kem, (
        f"ML-KEM-768 required for default hybrid suite (C3) but not found.\n"
        f"Available ML-KEM: {ml_kem}"
    )


def test_mldsa_available():
    """At least one ML-DSA variant must be enabled (required for C2/C3)."""
    import oqs

    sigs = oqs.get_enabled_sig_mechanisms()
    ml_dsa = [s for s in sigs if s.startswith("ML-DSA")]
    assert ml_dsa, (
        f"No ML-DSA-* found in enabled signatures.\nAll enabled: {sigs}\n"
        "Install a newer liboqs build that includes ML-DSA."
    )
    assert "ML-DSA-65" in ml_dsa, (
        f"ML-DSA-65 required for default hybrid suite (C3) but not found.\n"
        f"Available ML-DSA: {ml_dsa}"
    )


def test_cryptography_import():
    """cryptography package must be importable."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: F401
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401


def test_python_can_import():
    """python-can must be importable."""
    import can  # noqa: F401


def test_record_versions(capsys):
    """Print version table and write results/raw/smoke_versions.json."""
    import oqs
    import can
    import cryptography

    kems = oqs.get_enabled_kem_mechanisms()
    sigs = oqs.get_enabled_sig_mechanisms()

    record = {
        "python": sys.version,
        "os": platform.platform(),
        "cpu": platform.processor() or platform.machine(),
        "liboqs": oqs.oqs_version(),
        "liboqs_python": oqs.__version__ if hasattr(oqs, "__version__") else "unknown",
        "cryptography": cryptography.__version__,
        "python_can": can.__version__,
        "kem_count": len(kems),
        "sig_count": len(sigs),
        "kem_mechanisms": kems,
        "sig_mechanisms": sigs,
    }

    # Write JSON record (excluded from git via .gitignore pattern; small so committed is fine)
    out_path = _results_dir() / "smoke_versions.json"
    out_path.write_text(json.dumps(record, indent=2))

    # Print summary table to stdout (visible with pytest -v or -s)
    print("\n" + "=" * 60)
    print("  PQC Gateway — M0 smoke test version summary")
    print("=" * 60)
    print(f"  Python     : {sys.version.split()[0]}")
    print(f"  OS/CPU     : {platform.platform()} / {record['cpu']}")
    print(f"  liboqs     : {record['liboqs']}")
    print(f"  liboqs-py  : {record['liboqs_python']}")
    print(f"  cryptography: {record['cryptography']}")
    print(f"  python-can : {record['python_can']}")
    print(f"  KEMs ({len(kems):3d}) : {', '.join(kems)}")
    print(f"  SIGs ({len(sigs):3d}) : {', '.join(sigs)}")
    print("=" * 60)
    print(f"  Versions written to: {out_path}")
    print("=" * 60 + "\n")
