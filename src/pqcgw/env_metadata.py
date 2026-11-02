"""
Shared environment metadata for all results files.

Every benchmark, end-to-end run, and smoke test calls collect() and
includes the returned dict in its results JSON/CSV so results are
self-describing and reproducible.

Keys:
  python         -- sys.version string
  os             -- platform.platform()
  cpu            -- platform.processor() or machine()
  liboqs         -- oqs.oqs_version() (the C library version)
  liboqs_python  -- installed wheel version from importlib.metadata
  liboqs_dylib   -- path of the loaded shared library
  liboqs_build   -- cmake options used when building the project-local .oqs/
                    (read from .oqs/lib/pkgconfig/liboqs.pc if present)
  cryptography   -- cryptography package version
  python_can     -- python-can package version
  git_commit     -- HEAD commit hash (or 'unknown')
"""

from __future__ import annotations

import importlib.metadata
import os
import platform
import subprocess
import sys
from pathlib import Path


# Relative path from this file to the project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _liboqs_dylib_path() -> str:
    try:
        import oqs.oqs as _inner
        lib = getattr(_inner, "_liboqs", None)
        return lib._name if lib else "unknown"
    except Exception:
        return "unknown"


def _liboqs_build_options() -> str:
    """Read cmake Cflags / version from the installed liboqs.pc if available."""
    pc = _PROJECT_ROOT / ".oqs" / "lib" / "pkgconfig" / "liboqs.pc"
    if not pc.exists():
        return "unknown (liboqs.pc not found)"
    lines = pc.read_text().splitlines()
    # Return the first few non-comment, non-blank lines as a summary
    info = [l for l in lines if l and not l.startswith("#")]
    return "; ".join(info[:6])


def _git_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, cwd=_PROJECT_ROOT, timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def collect() -> dict:
    """Return a metadata dict suitable for embedding in any results file."""
    import oqs
    import cryptography
    import can

    return {
        "python": sys.version,
        "os": platform.platform(),
        "cpu": platform.processor() or platform.machine(),
        "liboqs": oqs.oqs_version(),
        "liboqs_python": importlib.metadata.version("liboqs-python"),
        "liboqs_dylib": _liboqs_dylib_path(),
        "liboqs_build": _liboqs_build_options(),
        "cryptography": cryptography.__version__,
        "python_can": can.__version__,
        "git_commit": _git_commit(),
    }
