#!/usr/bin/env python3
"""Prespecified five-point cutoff scan, including composite-only RMSE."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import platform

from validate import load_zeros, validate

OFFSETS = (-0.020, -0.005, 0.0, 0.005, 0.020)
BLOCKS = ((4800, 5299), (17850, 18149))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zeros", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        zeros, source = load_zeros(args.zeros)
        results = []
        for offset in OFFSETS:
            rows, summary = validate(BLOCKS, zeros, math.pi + offset,
                                     source["published_ordinate_error_bound"])
            for block in summary["blocks"]:
                errors = [row["error"] for row in rows
                          if block["start"] <= row["n"] <= block["end"] and not row["is_prime"]]
                block["composite_count"] = len(errors)
                block["composite_rmse"] = math.sqrt(math.fsum(x * x for x in errors) / len(errors))
            results.append({"offset": offset, "scale": math.pi + offset, **summary})
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    payload = {
        "experiment": "SASRL five-point hard-cutoff scan",
        "source": source, "python": platform.python_version(),
        "scan_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "validator_sha256": hashlib.sha256(Path(__file__).with_name("validate.py").read_bytes()).hexdigest(),
        "claim_scope": "finite prespecified grid, not a global minimum or proof",
        "runs": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(f"Wrote all {len(results)} cutoff scales to {args.output}")


if __name__ == "__main__":
    main()
