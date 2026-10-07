#!/usr/bin/env python3
"""Bounded, offline SASRL experiments. Never a cryptographic primality test.

Input JSON: {"source": "URL or publication", "complete_through": 100.0,
"ordinates": [14.134725141734693, ...]}. Completeness is the supplier's
assertion, not something this tool can prove. Supply positive zeta zeros with
multiplicity in nondecreasing order, starting from the first zero.
"""

from __future__ import annotations

import argparse
from bisect import bisect_left, bisect_right
import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_ORDINATES = 250_000
MAX_EVALUATIONS = 5_000_000
MAX_QUADRATURE_INTERVALS = 65_536
MAX_INTEGER = 100_000


def zeta_model() -> dict:
    """Exact supported analytic model; declarations do not verify input zeros."""
    return {'id':'riemann_zeta','degree':1,'conductor':1,'self_dual':True,
            'normalization':'unshifted','critical_line_real_part':0.5,
            'pole_at_one_order':1,'gamma_factor':'Gamma(s/2)',
            'trivial_zeros':'negative_even_integers_starting_at_minus_two'}


def validate_model(data: dict) -> str:
    allowed={'source','complete_through','ordinates','ordinate_error_bound','l_function'}
    if set(data)-allowed:
        raise ValueError('unsupported zero-table metadata field; this tool supports zeta only')
    if 'l_function' not in data:
        return 'implicit_zeta_legacy_input'
    declared=data['l_function']
    expected=zeta_model()
    if type(declared) is not dict or set(declared)!=set(expected):
        raise ValueError('l_function must declare the complete supported zeta model')
    # Python equates True and 1: exact types are part of the metadata contract.
    for key,value in expected.items():
        if type(declared[key]) is not type(value) or declared[key]!=value:
            raise ValueError(f'unsupported l_function {key}; zeta corrections cannot be reused')
    return 'explicit_unverified_zeta_declaration'


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    """Reject ambiguous duplicate JSON metadata fields."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def finite_number(value: object, name: str) -> float:
    """Reject booleans, strings, infinities and NaNs in numerical inputs."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number")
    try:
        result = float(value)
    except OverflowError as error:
        raise ValueError(f"{name} must be a finite number") from error
    if not math.isfinite(result):
        raise ValueError(f"{name} must be a finite number")
    return result


def validate_integer(n: int) -> None:
    if isinstance(n, bool) or not isinstance(n, int) or not 2 <= n <= MAX_INTEGER:
        raise ValueError(f"integer must be in [2, {MAX_INTEGER}]")


@dataclass(frozen=True)
class ZeroSpectrum:
    """Positive zeta ordinates with an explicit, unverified coverage assertion."""

    ordinates: tuple[float, ...]
    complete_through: float
    source: str
    sha256: str
    ordinate_error_bound: float = 0.0
    model_declaration: str = 'implicit_zeta_legacy_input'

    @classmethod
    def load(cls, path: Path) -> ZeroSpectrum:
        # Read at most the budget even if the file grows after inspection.
        with path.open("rb") as handle:
            raw = handle.read(MAX_INPUT_BYTES + 1)
        return cls.from_bytes(raw)

    @classmethod
    def from_bytes(cls, raw: bytes) -> ZeroSpectrum:
        """Validate untrusted JSON bytes; also used by the stdin fuzz target."""
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("zero table exceeds the input byte budget")
        try:
            data = json.loads(raw, object_pairs_hook=unique_object)
        except RecursionError as error:
            raise ValueError("zero table nesting is too deep") from error
        if not isinstance(data, dict):
            raise ValueError("zero table must be a JSON object")
        declaration=validate_model(data)
        source = data.get("source")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("zero table must identify its source")
        coverage = finite_number(data.get("complete_through"), "complete_through")
        if coverage <= 0:
            raise ValueError("complete_through must be positive")
        values = data.get("ordinates")
        if not isinstance(values, list) or len(values) > MAX_ORDINATES:
            raise ValueError(f"ordinates must be a list of at most {MAX_ORDINATES} zeros")
        ordinates = tuple(finite_number(v, "ordinate") for v in values)
        if any(v <= 0 for v in ordinates):
            raise ValueError("zero ordinates must be positive")
        if any(a > b for a, b in zip(ordinates, ordinates[1:])):
            raise ValueError("zero ordinates must be nondecreasing (retain multiplicity)")
        error_bound = finite_number(data.get("ordinate_error_bound", 0), "ordinate_error_bound")
        if error_bound < 0:
            raise ValueError("ordinate_error_bound must be nonnegative")
        return cls(ordinates, coverage, source.strip(), hashlib.sha256(raw).hexdigest(), error_bound,
                   declaration)

    def through(self, cutoff: float) -> tuple[float, ...]:
        cutoff = finite_number(cutoff, "cutoff")
        if cutoff <= 0 or cutoff > self.complete_through:
            raise ValueError("requested cutoff exceeds declared complete coverage")
        lower = bisect_left(self.ordinates, cutoff - self.ordinate_error_bound)
        upper = bisect_right(self.ordinates, cutoff + self.ordinate_error_bound)
        if self.ordinate_error_bound and lower < upper:
            raise ValueError("zero uncertainty straddles the requested cutoff")
        return self.ordinates[:bisect_right(self.ordinates, cutoff)]


def von_mangoldt(n: int) -> float:
    """Exact integer factorization oracle; floating log only after classification."""
    validate_integer(n)
    factor = 2
    while factor * factor <= n and n % factor:
        factor += 1
    if factor * factor > n:
        return math.log(n)
    remainder = n
    while remainder % factor == 0:
        remainder //= factor
    return math.log(factor) if remainder == 1 else 0.0


def smooth_step(t: float) -> float:
    """C-infinity step, evaluated without simultaneous exponential underflow."""
    if t <= 0:
        return 0.0
    if t >= 1:
        return 1.0
    exponent = 1.0 / t - 1.0 / (1.0 - t)
    if exponent >= 0:
        small = math.exp(-exponent)
        return small / (1.0 + small)
    return 1.0 / (1.0 + math.exp(exponent))


def cardinal_window(m: int, x: float) -> float:
    """Paper section 3: compact cutoff times Gaussian times normalized sinc."""
    validate_integer(m)
    x = finite_number(x, "x")
    ratio = x / m
    if ratio <= 0.5 or ratio >= 1.5:
        return 0.0
    delta = x - m
    # Mathematical cardinal zeros, without sin(pi * integer) rounding residue.
    if delta == 0:
        return 1.0
    if delta.is_integer():
        return 0.0
    cutoff = smooth_step((ratio - 0.5) * 4) * smooth_step((1.5 - ratio) * 4)
    angle = math.pi * delta
    sinc = math.sin(angle) / angle
    return cutoff * math.exp(-delta * delta / (2 * m)) * sinc


def hard_cutoff(m: int, spectrum: ZeroSpectrum, edge: float = math.pi) -> dict:
    """Conjectural rectangular estimator from section 8, retaining pole +1."""
    validate_integer(m)
    edge = finite_number(edge, "edge")
    zeros = spectrum.through(edge * m)
    if len(zeros) > MAX_EVALUATIONS:
        raise ValueError("hard-cutoff evaluation budget exceeded")
    value = 1.0 - 2.0 / math.sqrt(m) * math.fsum(
        math.cos(gamma * math.log(m)) for gamma in zeros
    )
    return {"method": "conjectural_hard_cutoff", "estimate": value,
            "cutoff": edge * m, "positive_zero_count": len(zeros),
            "ordinate_sensitivity_bound": 2 * len(zeros) * math.log(m)
                                          / math.sqrt(m) * spectrum.ordinate_error_bound}


def weighted_at_resolution(m: int, zeros: tuple[float, ...], intervals: int) -> dict:
    """Composite Simpson quadrature of W(1), zero pair sum and trivial sum.

    For m >= 3 the support lies above 1, so the summed trivial-zero kernel is
    sum(x**(-2k-1), k>=1) = 1 / (x * (x*x - 1)). No RH proof or finite-tail
    bound is provided by quadrature.
    """
    if m < 3:
        raise ValueError("weighted mode requires m >= 3")
    if isinstance(intervals, bool) or not isinstance(intervals, int):
        raise ValueError("quadrature interval count must be an integer")
    if intervals < 8 * m or intervals % 2 or intervals > MAX_QUADRATURE_INTERVALS:
        raise ValueError("quadrature needs an even interval count >= 8*m within the grid memory budget")
    if (intervals + 1) * (len(zeros) + 2) > MAX_EVALUATIONS:
        raise ValueError("weighted quadrature evaluation budget exceeded")
    step = m / intervals
    grid = []
    for index in range(1, intervals):
        x = m / 2.0 + index * step
        weight = (4 if index % 2 else 2) * step / 3 * cardinal_window(m, x)
        grid.append((x, math.log(x), weight))
    pole = math.fsum(weight for _, _, weight in grid)
    trivial = math.fsum(weight / (x * (x * x - 1)) for x, _, weight in grid)
    zero_sum = math.fsum(
        math.fsum(weight / math.sqrt(x) * math.cos(gamma * log_x)
                  for x, log_x, weight in grid)
        for gamma in zeros
    )
    return {"estimate": pole - 2 * zero_sum - trivial, "pole": pole,
            "trivial_zero_correction": trivial, "paired_zero_sum": 2 * zero_sum,
            "quadrature_intervals": intervals}


def weighted(m: int, spectrum: ZeroSpectrum, epsilon: float = 0.25) -> dict:
    """Conditional cardinal-Mellin experiment with coarse/fine discrepancy."""
    validate_integer(m)
    epsilon = finite_number(epsilon, "epsilon")
    if not 0 < epsilon < 0.5:
        raise ValueError("epsilon must lie strictly between 0 and 1/2")
    if m < 3:
        raise ValueError("weighted mode requires m >= 3")
    if 16 * m > MAX_QUADRATURE_INTERVALS:
        raise ValueError("weighted coarse/fine grids exceed the memory budget")
    cutoff = math.pi * m + m ** (0.5 + epsilon)
    zeros = spectrum.through(cutoff)
    intervals = 8 * m
    # Budget includes BOTH grids, not just the finer grid.
    if (3 * intervals + 2) * (len(zeros) + 2) > MAX_EVALUATIONS:
        raise ValueError("coarse/fine weighted evaluation budget exceeded")
    coarse = weighted_at_resolution(m, zeros, intervals)
    fine = weighted_at_resolution(m, zeros, 2 * intervals)
    return {**fine, "method": "conditional_cardinal_mellin", "epsilon": epsilon,
            "cutoff": cutoff, "positive_zero_count": len(zeros),
            "quadrature_discrepancy": abs(fine["estimate"] - coarse["estimate"]),
            "error_bound_available": False}


def score(m: int, recovery: dict) -> dict:
    reference = von_mangoldt(m)
    is_prime = reference == math.log(m)
    threshold = 0.75 * math.log(m)
    estimate = recovery["estimate"]
    return {"integer": m, **recovery, "reference": reference,
            "absolute_error": abs(estimate - reference), "threshold": threshold,
            "threshold_margin": estimate - threshold, "is_prime": is_prime,
            "predicted_prime": estimate > threshold,
            "classification_correct": (estimate > threshold) == is_prime}


def summarize(rows: list[dict]) -> dict:
    """Report unnormalized errors and all four confusion-matrix cells."""
    cells = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    for row in rows:
        key = ("T" if row["classification_correct"] else "F") + (
            "P" if row["predicted_prime"] else "N")
        cells[key] += 1
    return {"count": len(rows), **cells,
            "rmse": math.sqrt(math.fsum(row["absolute_error"] ** 2 for row in rows)
                              / len(rows))}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zeros", type=Path)
    parser.add_argument("--start", type=int, required=True)
    parser.add_argument("--stop", type=int, required=True, help="inclusive")
    parser.add_argument("--method", choices=("hard", "weighted"), default="hard")
    parser.add_argument("--epsilon", type=float, default=0.25)
    parser.add_argument("--edges", type=float, nargs="+", default=[math.pi],
                        help="hard mode cutoff multipliers, e.g. 3.13659 3.14159 3.14659")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.zeros.resolve() == args.output.resolve():
            raise ValueError("output must not overwrite the source zero table")
        validate_integer(args.start)
        validate_integer(args.stop)
        if args.start > args.stop or args.stop - args.start >= 1000:
            raise ValueError("choose an ascending inclusive block of at most 1000 integers")
        if args.method == "weighted" and 16 * args.stop > MAX_QUADRATURE_INTERVALS:
            raise ValueError("weighted coarse/fine grids exceed the memory budget")
        if len(args.edges) > 9:
            raise ValueError("at most nine cutoff multipliers are allowed")
        if args.method == "weighted" and args.edges != [math.pi]:
            raise ValueError("--edges applies only to hard mode")
        spectrum = ZeroSpectrum.load(args.zeros)
        runs = []
        # Preflight the ENTIRE run before doing expensive work or writing output.
        evaluations = 0
        for edge in (args.edges if args.method == "hard" else [math.pi]):
            for m in range(args.start, args.stop + 1):
                if args.method == "hard":
                    cutoff = finite_number(edge, "edge") * m
                    cost_per_zero = 1
                else:
                    if args.start < 3 or not 0 < args.epsilon < 0.5:
                        raise ValueError("weighted mode requires start >= 3 and 0 < epsilon < 1/2")
                    cutoff = math.pi * m + m ** (0.5 + args.epsilon)
                    cost_per_zero = 24 * m + 2
                count = len(spectrum.through(cutoff))
                evaluations += cost_per_zero * (count + (2 if args.method == "weighted" else 0))
                if evaluations > MAX_EVALUATIONS:
                    raise ValueError("total experiment evaluation budget exceeded; use smaller blocks")
        for edge in (args.edges if args.method == "hard" else [math.pi]):
            rows = [score(m, hard_cutoff(m, spectrum, edge) if args.method == "hard"
                          else weighted(m, spectrum, args.epsilon))
                    for m in range(args.start, args.stop + 1)]
            composites = [row for row in rows if not row["is_prime"]]
            runs.append({"edge_multiplier": edge if args.method == "hard" else None,
                         "summary": summarize(rows),
                         "composite_summary": summarize(composites) if composites else None,
                         "rows": rows})
        report = {"schema_version": 1, "cryptographic_use": False,
                  "l_function": zeta_model(), "model_declaration": spectrum.model_declaration,
                  "analytic_model_verified_from_input": False,
                  "coverage_verified": False, "source": spectrum.source,
                  "input_sha256": spectrum.sha256,
                  "declared_complete_through": spectrum.complete_through,
                  "declared_ordinate_error_bound": spectrum.ordinate_error_bound,
                  "evaluation_budget": MAX_EVALUATIONS, "evaluations": evaluations,
                  "assumptions": ["RH for the paper's asymptotic weighted claim",
                                  "supplier assertion of complete positive zeta zeros with multiplicity",
                                  "hard cutoff is conjectural; quadrature discrepancy is not an error bound"],
                  "runs": runs}
        args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    except (ValueError, OSError, OverflowError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
