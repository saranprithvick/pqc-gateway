"""Micro-benchmarks: per-operation timing for every enabled algorithm.

Measurements (§8):
  - KEM: keygen, encaps, decaps
  - Signature: keygen, sign, verify
  - KDF: extract, expand
  - AEAD: encrypt, decrypt — for payload sizes {8, 64, 256, 1024} bytes

Protocol:
  - ≥ 50 warm-up iterations discarded
  - ≥ 1000 timed iterations
  - gc.collect() before each timed section
  - time.perf_counter_ns() per iteration
  - Results: Stats (median/p95/p99/n) written to results/raw/micro_<alg>.csv
  - Log y-axis plots are deferred to scripts/make_plots.py

Usage:
    python -m pqcgw.bench.micro              # all algorithms
    python -m pqcgw.bench.micro --alg ml-kem-768  # specific algorithm
"""

from __future__ import annotations

import argparse
import csv as _csv
import gc
import os
import sys
import time
from pathlib import Path

# Ensure project root is on path when run as __main__
_HERE = Path(__file__).resolve().parents[3]
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE / "src"))

from pqcgw.bench.metrics import SmallNStats, Stats, collect_env, compute_stats, compute_small_n_stats, write_csv
from pqcgw.crypto.registry import load_suite

_RESULTS_DIR = Path(__file__).resolve().parents[3] / "results" / "raw"
_WARMUP = 50
_N_ITER = 1000
_PAYLOAD_SIZES = [8, 64, 256, 1024]  # bytes, for AEAD and KDF expand


def _time_loop(fn, n: int) -> list[int]:
    """Run fn() n times; return list of elapsed_ns per call."""
    out: list[int] = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        out.append(time.perf_counter_ns() - t0)
    return out


def _suite_path(name: str) -> Path:
    return Path(__file__).resolve().parents[3] / "configs" / "suites" / f"{name}.toml"


def bench_kem(suite_name: str, env: dict) -> None:
    suite = load_suite(_suite_path(suite_name))
    kem = suite.kem
    rows: list[dict] = []

    # keygen
    gc.collect()
    for _ in range(_WARMUP):
        kem.keygen()
    gc.collect()
    s = _time_loop(lambda: kem.keygen(), _N_ITER)
    st = compute_stats(s)
    rows.append({"alg": suite_name, "op": "kem_keygen", "payload_bytes": 0, **st.as_dict(), **env})

    # encaps / decaps (need a fixed pk for encaps, sk for decaps)
    pk, sk = kem.keygen()  # KEM.keygen() returns (pk, sk)
    ct, _ss = kem.encaps(pk)

    gc.collect()
    for _ in range(_WARMUP):
        kem.encaps(pk)
    gc.collect()
    s = _time_loop(lambda: kem.encaps(pk), _N_ITER)
    st = compute_stats(s)
    rows.append({"alg": suite_name, "op": "kem_encaps", "payload_bytes": 0, **st.as_dict(), **env})

    gc.collect()
    for _ in range(_WARMUP):
        kem.decaps(sk, ct)
    gc.collect()
    s = _time_loop(lambda: kem.decaps(sk, ct), _N_ITER)
    st = compute_stats(s)
    rows.append({"alg": suite_name, "op": "kem_decaps", "payload_bytes": 0, **st.as_dict(), **env})

    _write(f"micro_{suite_name}_kem", rows, env)
    for r in rows:
        _print_row(r)


def bench_sig(suite_name: str, env: dict) -> None:
    suite = load_suite(_suite_path(suite_name))
    sig = suite.signature
    rows: list[dict] = []
    msg = os.urandom(64)  # fixed message for all sign/verify iterations

    # keygen
    gc.collect()
    for _ in range(_WARMUP):
        sig.keygen()
    gc.collect()
    s = _time_loop(lambda: sig.keygen(), _N_ITER)
    st = compute_stats(s)
    rows.append({"alg": suite_name, "op": "sig_keygen", "payload_bytes": 0, **st.as_dict(), **env})

    # sign / verify
    pk, sk = sig.keygen()
    signature = sig.sign(sk, msg)

    gc.collect()
    for _ in range(_WARMUP):
        sig.sign(sk, msg)
    gc.collect()
    s = _time_loop(lambda: sig.sign(sk, msg), _N_ITER)
    st = compute_stats(s)
    rows.append({"alg": suite_name, "op": "sig_sign", "payload_bytes": len(msg), **st.as_dict(), **env})

    gc.collect()
    for _ in range(_WARMUP):
        sig.verify(pk, msg, signature)
    gc.collect()
    s = _time_loop(lambda: sig.verify(pk, msg, signature), _N_ITER)
    st = compute_stats(s)
    rows.append({"alg": suite_name, "op": "sig_verify", "payload_bytes": len(msg), **st.as_dict(), **env})

    _write(f"micro_{suite_name}_sig", rows, env)
    for r in rows:
        _print_row(r)


def bench_kdf(suite_name: str, env: dict) -> None:
    suite = load_suite(_suite_path(suite_name))
    kdf = suite.kdf
    rows: list[dict] = []

    salt = os.urandom(64)
    ikm = os.urandom(32)
    prk = kdf.extract(salt, ikm)
    info = b"bench-label"

    gc.collect()
    for _ in range(_WARMUP):
        kdf.extract(salt, ikm)
    gc.collect()
    s = _time_loop(lambda: kdf.extract(salt, ikm), _N_ITER)
    st = compute_stats(s)
    rows.append({"alg": suite_name, "op": "kdf_extract", "payload_bytes": len(ikm), **st.as_dict(), **env})

    for size in _PAYLOAD_SIZES:
        gc.collect()
        for _ in range(_WARMUP):
            kdf.expand(prk, info, size)
        gc.collect()
        s = _time_loop(lambda sz=size: kdf.expand(prk, info, sz), _N_ITER)
        st = compute_stats(s)
        rows.append({"alg": suite_name, "op": "kdf_expand", "payload_bytes": size, **st.as_dict(), **env})

    _write(f"micro_{suite_name}_kdf", rows, env)
    for r in rows:
        _print_row(r)


def bench_aead(suite_name: str, env: dict) -> None:
    suite = load_suite(_suite_path(suite_name))
    aead = suite.aead
    rows: list[dict] = []

    key = os.urandom(aead.key_len)
    nonce_base = os.urandom(aead.nonce_len)
    aad = os.urandom(16)

    for size in _PAYLOAD_SIZES:
        pt = os.urandom(size)
        # Pre-encrypt for decrypt bench
        ct = aead.encrypt(key, nonce_base, aad, pt)

        gc.collect()
        for _ in range(_WARMUP):
            aead.encrypt(key, nonce_base, aad, pt)
        gc.collect()
        s = _time_loop(lambda p=pt: aead.encrypt(key, nonce_base, aad, p), _N_ITER)
        st = compute_stats(s)
        rows.append({"alg": suite_name, "op": "aead_encrypt", "payload_bytes": size, **st.as_dict(), **env})

        gc.collect()
        for _ in range(_WARMUP):
            aead.decrypt(key, nonce_base, aad, ct)
        gc.collect()
        s = _time_loop(lambda c=ct: aead.decrypt(key, nonce_base, aad, c), _N_ITER)
        st = compute_stats(s)
        rows.append({"alg": suite_name, "op": "aead_decrypt", "payload_bytes": size, **st.as_dict(), **env})

    _write(f"micro_{suite_name}_aead", rows, env)
    for r in rows:
        _print_row(r)


def _safe_name(name: str) -> str:
    """Convert suite name (possibly with /path) to a safe filename component."""
    return name.replace("/", "_").replace("\\", "_")


def _write(name: str, rows: list[dict], env: dict) -> None:
    # name is passed as e.g. "micro_{suite_name}_{op}" — sanitize slashes in suite part.
    safe = _safe_name(name)
    path = _RESULTS_DIR / f"{safe}.csv"
    path.unlink(missing_ok=True)  # overwrite per bench run
    write_csv(path, rows, env)
    print(f"  → {path}")


def _print_row(r: dict) -> None:
    print(
        f"  {r['alg']:30s}  {r['op']:20s}  pl={r.get('payload_bytes', 0):5d}B  "
        f"median={r['median_ns']/1e6:.3f}ms  "
        f"p95={r['p95_ns']/1e6:.3f}ms  "
        f"p99={r['p99_ns']/1e6:.3f}ms  n={r['n']}"
    )


# Suites that exist as config files (benchmarks all 4 components).
_SUITE_NAMES = ["classical", "pqc", "hybrid"]

# Matrix suites: each maps a suite name to the ops to benchmark, covering
# algorithms not in the main 3 suites.  Experimental suites are always
# attempted and labelled in the alg name; failures are reported but not fatal.
# Format: (suite_name_relative_to_suites_dir, [ops], is_experimental)
_MATRIX_SELECTIVE: list[tuple[str, list[str], bool]] = [
    ("matrix/k-512",      ["kem"],          False),  # ML-KEM-512
    ("matrix/k-1024",     ["kem"],          False),  # ML-KEM-1024
    ("matrix/s-44",       ["sig"],          False),  # ML-DSA-44
    ("matrix/s-87",       ["sig"],          False),  # ML-DSA-87
    ("matrix/s-slh",      ["sig"],          False),  # SLH-DSA-SHA2-128f (large-sig stress)
    ("matrix/x-falcon512",["sig"],          True),   # Falcon-512 (experimental, pre-standard)
    ("matrix/x-hqc3",     ["kem"],          True),   # HQC-3 (experimental)
    ("matrix/d-384",      ["kdf"],          False),  # hkdf-sha384
    ("matrix/a-128",      ["aead"],         False),  # aes-128-gcm
    ("matrix/a-cha",      ["aead"],         False),  # chacha20-poly1305
]

_OP_FUNCS = {"kem": bench_kem, "sig": bench_sig, "kdf": bench_kdf, "aead": bench_aead}


def run_all(suite_names: list[str]) -> None:
    env = collect_env()
    suites_dir = Path(__file__).resolve().parents[3] / "configs" / "suites"

    # Primary suites: all 4 ops.
    all_names: list[str] = []
    for name in suite_names:
        path = suites_dir / f"{name}.toml"
        if not path.exists():
            print(f"  skipping {name}: {path} not found")
            continue
        print(f"\n=== {name} ===")
        for op in ("kem", "sig", "kdf", "aead"):
            try:
                _OP_FUNCS[op](name, env)
            except Exception as exc:
                print(f"  {op} bench failed: {exc}")
        all_names.append(name)

    # Matrix suites: selective ops for unique algorithms.
    for suite_rel, ops, experimental in _MATRIX_SELECTIVE:
        path = suites_dir / f"{suite_rel}.toml"
        if not path.exists():
            print(f"  skipping {suite_rel}: file not found")
            continue
        label = f"{suite_rel}" + (" [experimental]" if experimental else "")
        print(f"\n=== {label} ===")
        for op in ops:
            try:
                _OP_FUNCS[op](suite_rel, env)
            except Exception as exc:
                print(f"  {op} bench failed{'  [experimental — skipping]' if experimental else ''}: {exc}")
        all_names.append(suite_rel)

    consolidate_micro_csv(all_names, env)


def consolidate_micro_csv(suite_names: list[str], env: dict) -> None:
    """Read per-suite raw CSVs and write combined results/tables/micro.csv."""
    all_rows: list[dict] = []
    for name in suite_names:
        safe = _safe_name(name)
        for op_type in ("kem", "sig", "kdf", "aead"):
            path = _RESULTS_DIR / f"micro_{safe}_{op_type}.csv"
            if not path.exists():
                continue
            with open(path) as fh:
                lines = [l for l in fh if not l.startswith("#")]
            all_rows.extend(list(_csv.DictReader(lines)))
    if all_rows:
        tables_dir = Path(__file__).resolve().parents[3] / "results" / "tables"
        tables_dir.mkdir(parents=True, exist_ok=True)
        # Always overwrite the summary table (not append)
        out = tables_dir / "micro.csv"
        out.unlink(missing_ok=True)
        write_csv(out, all_rows, env)
        print(f"  → {out} ({len(all_rows)} rows)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Micro-benchmark crypto operations")
    parser.add_argument("--suite", nargs="*", default=_SUITE_NAMES,
                        help="Suite name(s) from configs/suites/<name>.toml")
    args = parser.parse_args()
    run_all(args.suite)
