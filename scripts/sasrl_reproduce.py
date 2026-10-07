#!/usr/bin/env python3
"""Reproduce the paper's seven hard-cutoff blocks from the real zeros1 table.

This explicit large experiment is bounded at 100 million cosine evaluations.
It reads an existing local table, never downloads data, and emits summaries.
The full zero prefix, numerical precision and RH are supplier/model assumptions.
"""

import argparse
import hashlib
import io
import json
import math
from pathlib import Path

from sasrl_recovery import (
    MAX_INPUT_BYTES, MAX_ORDINATES, ZeroSpectrum, finite_number, hard_cutoff, score, summarize,
)

BLOCKS = ((400, 799), (800, 1199), (1600, 2099), (2500, 2999),
          (4800, 5299), (8800, 9299), (17850, 18149))
MAX_TOTAL_EVALUATIONS = 100_000_000
MAX_SWEEP_EVALUATIONS = 200_000_000
ODLYZKO_ZEROS1_SHA256 = "3436c916a7878261ac183fd7b9448c9a4736b8bbccf1356874a6ce1788541632"


def spectrum_from_odlyzko(raw: bytes) -> ZeroSpectrum:
    """Validate a bounded ASCII ordinate prefix without unbounded line lists."""
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("raw zero table exceeds the byte budget")
    values = []
    for line in io.StringIO(raw.decode("ascii")):
        if not line.strip():
            continue
        if len(values) >= MAX_ORDINATES:
            raise ValueError("raw zero table exceeds the ordinate budget")
        values.append(finite_number(float(line), "ordinate"))
    if not values:
        raise ValueError("zero table is empty")
    metadata = {"source": "Andrew Odlyzko zeros1: https://www-users.cse.umn.edu/~odlyzko/zeta_tables/zeros1",
                "complete_through": math.floor(values[-1]),
                "ordinate_error_bound": 3e-9, "ordinates": values}
    return ZeroSpectrum.from_bytes(json.dumps(metadata, allow_nan=False).encode())


def reproduce(path: Path) -> dict:
    with path.open("rb") as handle:
        raw = handle.read(MAX_INPUT_BYTES + 1)
    spectrum = verified_reproduction_spectrum(raw)
    evaluations = sum(len(spectrum.through(math.pi * n))
                      for start, stop in BLOCKS for n in range(start, stop + 1))
    if evaluations > MAX_TOTAL_EVALUATIONS:
        raise ValueError("large reproduction exceeds its explicit evaluation budget")
    blocks = []
    all_rows = []
    for start, stop in BLOCKS:
        rows = [score(n, hard_cutoff(n, spectrum)) for n in range(start, stop + 1)]
        composites = [row for row in rows if not row["is_prime"]]
        blocks.append({"start": start, "stop": stop, "summary": summarize(rows),
                       "composite_summary": summarize(composites),
                       "max_absolute_error": max(row["absolute_error"] for row in rows),
                       "min_correct_threshold_margin": min(abs(row["threshold_margin"]) for row in rows),
                       "misclassifications": [row for row in rows if not row["classification_correct"]]})
        all_rows.extend(rows)
    return {"schema_version": 1, "method": "conjectural_hard_cutoff",
            "cryptographic_use": False, "coverage_verified": False,
            "source": spectrum.source, "raw_table_sha256": hashlib.sha256(raw).hexdigest(),
            "table_ordinate_count": len(spectrum.ordinates),
            "declared_complete_through": spectrum.complete_through,
            "declared_ordinate_error_bound": spectrum.ordinate_error_bound,
            "evaluations": evaluations, "evaluation_budget": MAX_TOTAL_EVALUATIONS,
            "summary": summarize(all_rows), "blocks": blocks,
            "limitations": ["Reproduces empirical hard-cutoff evidence, not weighted theorem",
                            "Completeness and precision are supplier assertions",
                            "Finite classification success is not a security or asymptotic proof"]}


def verified_reproduction_spectrum(raw: bytes) -> ZeroSpectrum:
    """Pin the exact public table bytes used for manuscript reproduction.

    This is data reproducibility, not proof of the table's mathematical accuracy.
    Other datasets remain usable through sasrl_recovery.py's explicit metadata.
    """
    if hashlib.sha256(raw).hexdigest() != ODLYZKO_ZEROS1_SHA256:
        raise ValueError("table differs from the pinned Odlyzko zeros1 bytes; use the general recovery tool for other data")
    return spectrum_from_odlyzko(raw)


def reproduce_edge_sweep(path: Path) -> dict:
    """Reproduce the two reported sharp-edge scans with a separate work cap."""
    with path.open("rb") as handle:
        raw = handle.read(MAX_INPUT_BYTES + 1)
    spectrum = verified_reproduction_spectrum(raw)
    blocks = ((4800, 5299), (17850, 18149))
    offsets = (-0.02, -0.005, 0.0, 0.005, 0.02)
    evaluations = sum(len(spectrum.through((math.pi + offset) * n))
                      for start, stop in blocks for offset in offsets
                      for n in range(start, stop + 1))
    if evaluations > MAX_SWEEP_EVALUATIONS:
        raise ValueError("edge sweep exceeds its explicit evaluation budget")
    results = []
    for start, stop in blocks:
        scans = []
        for offset in offsets:
            rows = [score(n, hard_cutoff(n, spectrum, math.pi + offset))
                    for n in range(start, stop + 1)]
            composites = [row for row in rows if not row["is_prime"]]
            scans.append({"offset_from_pi": offset, "summary": summarize(rows),
                          "composite_summary": summarize(composites)})
        results.append({"start": start, "stop": stop, "scans": scans})
    return {"schema_version": 1, "method": "conjectural_hard_cutoff_edge_sweep",
            "cryptographic_use": False, "coverage_verified": False,
            "source": spectrum.source, "raw_table_sha256": hashlib.sha256(raw).hexdigest(),
            "evaluations": evaluations, "evaluation_budget": MAX_SWEEP_EVALUATIONS,
            "blocks": results,
            "limitations": ["Parameter scan reproduces finite empirical evidence only",
                            "Composite-only scores include higher prime powers"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("table", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--edge-sweep", action="store_true",
                        help="run both reported edge scans under a 200M evaluation cap")
    args = parser.parse_args()
    try:
        if args.table.resolve() == args.output.resolve():
            raise ValueError("output must not overwrite the source zero table")
        report = reproduce_edge_sweep(args.table) if args.edge_sweep else reproduce(args.table)
        args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        print(json.dumps(report.get("summary", {"evaluations": report["evaluations"]})))
    except (ValueError, OSError, OverflowError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
