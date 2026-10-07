#!/usr/bin/env python3
"""Offline SASRL hard-cutoff experiment; NOT an RNG or a primality service.

Standard-library-only, with exact sieve ground truth and unfiltered row output.
The conjectural hard cutoff is distinct from the weighted Mellin theorem.
"""

import argparse
import bisect
import csv
import hashlib
import json
import math
from pathlib import Path
import platform
import sys

SOURCE_URL = "https://www-users.cse.umn.edu/~odlyzko/zeta_tables/zeros1"
OFFICIAL_SHA256 = "3436c916a7878261ac183fd7b9448c9a4736b8bbccf1356874a6ce1788541632"
PAPER_BLOCKS = ((400, 799), (800, 1199), (1600, 2099), (2500, 2999),
                (4800, 5299), (8800, 9299), (17850, 18149))


def load_zeros(path):
    """Require positive ordered finite ordinates; completeness is external."""
    raw = Path(path).read_bytes()
    try:
        values = tuple(float(token) for token in raw.decode("ascii").split())
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("zero data must be ASCII floating-point ordinates") from exc
    if not values or any(not math.isfinite(x) or x <= 0 for x in values):
        raise ValueError("zero data must contain positive finite ordinates")
    if any(a >= b for a, b in zip(values, values[1:])):
        raise ValueError("zero ordinates must be strictly increasing")
    digest = hashlib.sha256(raw).hexdigest()
    return values, {
        "sha256": digest,
        "count": len(values),
        "first": values[0],
        "last": values[-1],
        "matches_pinned_odlyzko_file": digest == OFFICIAL_SHA256,
        "source_url": SOURCE_URL if digest == OFFICIAL_SHA256 else None,
        "published_ordinate_error_bound": 3e-9 if digest == OFFICIAL_SHA256 else None,
    }


def arithmetic_truth(limit):
    """Exact Eratosthenes sieve, followed by prime-power von Mangoldt values."""
    if limit < 2:
        raise ValueError("limit must be at least 2")
    prime = bytearray(b"\x01") * (limit + 1)
    prime[0:2] = b"\x00\x00"
    for p in range(2, math.isqrt(limit) + 1):
        if prime[p]:
            start = p * p
            prime[start:limit + 1:p] = b"\x00" * ((limit - start) // p + 1)
    mangoldt = [0.0] * (limit + 1)
    for p in range(2, limit + 1):
        if prime[p]:
            power = p
            while power <= limit:
                mangoldt[power] = math.log(p)
                power *= p
    return prime, mangoldt


def estimate(n, zeros, cutoff_scale=math.pi):
    if n < 2:
        raise ValueError("n must be at least 2")
    if not math.isfinite(cutoff_scale) or cutoff_scale <= 0:
        raise ValueError("cutoff scale must be positive and finite")
    cutoff = cutoff_scale * n
    # A row at or above the last supplied ordinate cannot establish coverage.
    if not zeros or cutoff >= zeros[-1]:
        raise ValueError(f"zero table does not cover cutoff {cutoff:.12g} for n={n}")
    count = bisect.bisect_right(zeros, cutoff)
    log_n = math.log(n)
    value = 1.0 - 2.0 / math.sqrt(n) * math.fsum(
        math.cos(zeros[i] * log_n) for i in range(count)
    )
    return value, count


def validate(blocks, zeros, cutoff_scale=math.pi, ordinate_error=None):
    if not blocks or any(start < 2 or end < start for start, end in blocks):
        raise ValueError("blocks must be nonempty inclusive ranges starting at 2 or later")
    ordered = sorted(blocks)
    if any(a[1] >= b[0] for a, b in zip(ordered, ordered[1:])):
        raise ValueError("overlapping blocks would double-count observations")
    if not math.isfinite(cutoff_scale) or cutoff_scale <= 0:
        raise ValueError("cutoff scale must be positive and finite")
    if ordinate_error is not None and (
        not math.isfinite(ordinate_error) or ordinate_error < 0
    ):
        raise ValueError("ordinate error must be finite and nonnegative")
    if not zeros or cutoff_scale * max(end for _, end in blocks) + (ordinate_error or 0) >= zeros[-1]:
        raise ValueError("zero table does not cover all requested cutoffs and perturbations")
    prime, mangoldt = arithmetic_truth(max(end for _, end in blocks))
    rows, summaries = [], []
    for start, end in blocks:
        block_rows = []
        confusion = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        for n in range(start, end + 1):
            value, count = estimate(n, zeros, cutoff_scale)
            threshold = 0.75 * math.log(n)
            predicted, actual = value > threshold, bool(prime[n])
            key = "tp" if predicted and actual else "fp" if predicted else "fn" if actual else "tn"
            confusion[key] += 1
            crossing_count = (
                bisect.bisect_right(zeros, cutoff_scale * n + ordinate_error)
                - bisect.bisect_left(zeros, cutoff_scale * n - ordinate_error)
                if ordinate_error is not None else None
            )
            row = {
                "n": n, "estimate": value, "exact_lambda": mangoldt[n],
                "error": value - mangoldt[n], "is_prime": actual,
                "predicted_prime": predicted, "threshold": threshold,
                "zero_count": count, "cutoff": cutoff_scale * n,
                # Includes possible cutoff crossings, but excludes rounding
                # and the conjectural omitted-tail error.
                "possible_cutoff_crossings": crossing_count,
                "ordinate_perturbation_bound": (
                    2 / math.sqrt(n) * (count * math.log(n) * ordinate_error + crossing_count)
                    if ordinate_error is not None else None
                ),
            }
            block_rows.append(row)
        rows.extend(block_rows)
        summaries.append({
            "start": start, "end": end, "count": len(block_rows),
            "rmse": math.sqrt(math.fsum(r["error"] ** 2 for r in block_rows) / len(block_rows)),
            "max_abs_error": max(abs(r["error"]) for r in block_rows),
            "correct": confusion["tp"] + confusion["tn"], "confusion": confusion,
        })
    totals = {key: sum(b["confusion"][key] for b in summaries) for key in ("tp", "tn", "fp", "fn")}
    return rows, {"blocks": summaries, "count": len(rows), "confusion": totals,
                  "rmse": math.sqrt(math.fsum(r["error"] ** 2 for r in rows) / len(rows))}


def parse_block(value):
    try:
        start, end = (int(x) for x in value.split(":"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("use an inclusive START:END range") from exc
    if start < 2 or end < start:
        raise argparse.ArgumentTypeError("require 2 <= START <= END")
    return start, end


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zeros", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--block", type=parse_block, action="append", help="repeatable; defaults to seven paper blocks")
    parser.add_argument("--cutoff-scale", type=float, default=math.pi)
    args = parser.parse_args(argv)
    try:
        zeros, source = load_zeros(args.zeros)
        rows, summary = validate(args.block or PAPER_BLOCKS, zeros, args.cutoff_scale,
                                 source["published_ordinate_error_bound"])
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    summary.update({
        "experiment": "SASRL conjectural hard-cutoff reconstruction",
        "formula": "1 - 2/sqrt(n) * sum(gamma <= cutoff_scale*n, cos(gamma*log(n)))",
        "threshold_fraction": 0.75, "cutoff_scale": args.cutoff_scale,
        "source": source, "python": platform.python_version(),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "claim_scope": "finite numerical experiment; not a weighted-theorem proof, RNG, entropy source, or cryptographic validation",
    })
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "estimates.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    print(json.dumps({"count": summary["count"], "confusion": summary["confusion"],
                      "rmse": summary["rmse"]}, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
