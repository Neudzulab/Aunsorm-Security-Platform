#!/usr/bin/env python3
"""Run cargo fuzz corpus minimization for all configured targets.

This script normalizes the directory layout used by the nightly fuzz CI
pipeline and emits a machine-readable summary alongside the minimized
corpora so that downstream jobs or humans can quickly inspect the
results.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict

TARGETS = (
    "fuzz_packet",
    "fuzz_session",
    "session_store_roundtrip",
)

CORPUS_ROOT = Path("fuzz") / "corpus"
MIN_ROOT = Path("fuzz") / "corpus-min"
SUMMARY_FILE = MIN_ROOT / "minimization-summary.json"


def compute_stats(path: Path) -> Dict[str, int]:
    files = 0
    size = 0
    if not path.exists():
        return {"files": 0, "bytes": 0}
    for entry in path.rglob("*"):
        if entry.is_file():
            files += 1
            size += entry.stat().st_size
    return {"files": files, "bytes": size}


def ensure_directory(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def main() -> int:
    MIN_ROOT.mkdir(parents=True, exist_ok=True)
    summary = []

    for target in TARGETS:
        src = CORPUS_ROOT / target
        dst = MIN_ROOT / target
        before = compute_stats(src)

        status = "skipped"
        if before["files"] == 0:
            print(f"[nightly-fuzz] Corpus for {target} is empty; skipping minimization", file=sys.stderr)
            dst.mkdir(parents=True, exist_ok=True)
        else:
            print(f"[nightly-fuzz] Minimizing corpus for {target} ({before['files']} files, {before['bytes']} bytes)")
            ensure_directory(dst)
            cmd = ["cargo", "fuzz", "cmin", target, str(src), str(dst)]
            subprocess.run(cmd, check=True)
            status = "minimized"

        after = compute_stats(dst)
        print(
            f"[nightly-fuzz] Result for {target}: {after['files']} files, {after['bytes']} bytes ({status})"
        )

        summary.append(
            {
                "target": target,
                "status": status,
                "source": str(src),
                "destination": str(dst),
                "before": before,
                "after": after,
            }
        )

    SUMMARY_FILE.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[nightly-fuzz] Wrote summary to {SUMMARY_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
