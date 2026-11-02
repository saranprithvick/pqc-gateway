"""
Smoke test: verify liboqs-python installs and exposes the required PQC algorithms.

Run with: make smoke
On failure: stop and report before proceeding to any other milestone.
"""
import json
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
    """Print version table and write results/raw/smoke_versions.json using shared env_metadata."""
    import oqs
    from pqcgw import env_metadata

    kems = oqs.get_enabled_kem_mechanisms()
    sigs = oqs.get_enabled_sig_mechanisms()

    meta = env_metadata.collect()
    record = {**meta, "kem_count": len(kems), "sig_count": len(sigs),
              "kem_mechanisms": kems, "sig_mechanisms": sigs}

    out_path = _results_dir() / "smoke_versions.json"
    out_path.write_text(json.dumps(record, indent=2))

    print("\n" + "=" * 60)
    print("  PQC Gateway — M0 smoke test version summary")
    print("=" * 60)
    print(f"  Python     : {meta['python'].split()[0]}")
    print(f"  OS/CPU     : {meta['os']} / {meta['cpu']}")
    print(f"  liboqs     : {meta['liboqs']}")
    print(f"  liboqs-py  : {meta['liboqs_python']}")
    print(f"  dylib path : {meta['liboqs_dylib']}")
    print(f"  liboqs bld : {meta['liboqs_build']}")
    print(f"  cryptography: {meta['cryptography']}")
    print(f"  python-can : {meta['python_can']}")
    print(f"  git commit : {meta['git_commit']}")
    print(f"  KEMs ({len(kems):3d}) : {', '.join(kems)}")
    print(f"  SIGs ({len(sigs):3d}) : {', '.join(sigs)}")
    print("=" * 60)
    print(f"  Versions written to: {out_path}")
    print("=" * 60 + "\n")
