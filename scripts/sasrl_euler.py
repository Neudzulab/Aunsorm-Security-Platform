"""Bounded public-data reference oracle for good-reduction elliptic Euler data.

This counts points; it does not recover coefficients from L-function zeros,
generate cryptographic curves, or certify a cryptographic group order.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path

MAX_PRIME = 100_000
MAX_ROWS = 128
MAX_WORK = 1_000_000
MAX_EXPONENT = 32
MAX_COEFFICIENT = 10**12


@dataclass(frozen=True)
class Curve:
    cremona: str
    lmfdb: str
    coefficients: tuple[int, int, int, int, int]
    source: str


# Explicit label mappings matter: Cremona 11a1 is LMFDB 11.a2, not 11.a1.
CURVES = {
    "11a1": Curve("11a1", "11.a2", (0, -1, 1, -10, -20),
                   "https://www.lmfdb.org/EllipticCurve/Q/11/a/2"),
    "37a1": Curve("37a1", "37.a1", (0, 0, 1, -1, 0),
                   "https://www.lmfdb.org/EllipticCurve/Q/37/a/1"),
}


def checked_integer(value: int, minimum: int, maximum: int, name: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def checked_model(model: tuple[int, ...]) -> tuple[int, ...]:
    if type(model) is not tuple or len(model) != 5:
        raise ValueError("model must be an immutable five-integer Weierstrass tuple")
    for coefficient in model:
        checked_integer(coefficient, -MAX_COEFFICIENT, MAX_COEFFICIENT, "coefficient")
    return model


def discriminant(model: tuple[int, ...]) -> int:
    """Exact discriminant of y²+a1xy+a3y=x³+a2x²+a4x+a6."""
    a1, a2, a3, a4, a6 = checked_model(model)
    b2 = a1*a1 + 4*a2
    b4 = 2*a4 + a1*a3
    b6 = a3*a3 + 4*a6
    b8 = a1*a1*a6 + 4*a2*a6 - a1*a3*a4 + a2*a3*a3 - a4*a4
    return -b2*b2*b8 - 8*b4**3 - 27*b6*b6 + 9*b2*b4*b6


def checked_prime(prime: int) -> int:
    checked_integer(prime, 2, MAX_PRIME, "prime")
    if prime != 2 and prime % 2 == 0:
        raise ValueError("field size must be a prime")
    for divisor in range(3, math.isqrt(prime) + 1, 2):
        if prime % divisor == 0:
            raise ValueError("field size must be a prime")
    return prime


def point_count(model: tuple[int, ...], prime: int) -> int:
    """Count affine solutions plus the point at infinity, with exact arithmetic.

    For odd p, each quadratic in y has 1+Legendre(discriminant) roots.
    Characteristic two is handled by direct enumeration of its four pairs.
    Bad reduction of the supplied model is refused, not treated as an elliptic
    good-prime Euler factor. An alternative integral model may have better
    reduction; this tool performs no minimal-model search.
    """
    a1, a2, a3, a4, a6 = checked_model(model)
    checked_prime(prime)
    delta = discriminant(model)
    if delta == 0 or delta % prime == 0:
        raise ValueError("singular model or bad reduction at the supplied prime")
    a1, a2, a3, a4, a6 = (value % prime for value in model)
    if prime == 2:
        count = 1 + sum(
            (y*y + a1*x*y + a3*y - x**3 - a2*x*x - a4*x - a6) % 2 == 0
            for x in range(2) for y in range(2)
        )
    else:
        count = 1
        for x in range(prime):
            rhs = (x**3 + a2*x*x + a4*x + a6) % prime
            delta_y = ((a1*x + a3)**2 + 4*rhs) % prime
            character = pow(delta_y, (prime - 1)//2, prime)
            count += 1 + (-1 if character == prime - 1 else character)
    trace = prime + 1 - count
    if trace*trace > 4*prime:
        raise ArithmeticError("point count violates the exact Hasse bound")
    return count


def frobenius_power(trace: int, prime: int, exponent: int) -> int:
    """alpha^k+beta^k, NOT the Dirichlet-series coefficient a_(p^k)."""
    checked_prime(prime)
    checked_integer(trace, -2*math.isqrt(prime)-2, 2*math.isqrt(prime)+2, "trace")
    checked_integer(exponent, 1, MAX_EXPONENT, "exponent")
    if trace*trace > 4*prime:
        raise ValueError("trace violates the Hasse bound")
    previous, current = 2, trace
    for _ in range(2, exponent + 1):
        previous, current = current, trace*current - prime*previous
    return current


def local_reference(model: tuple[int, ...], prime: int, exponent: int = 1) -> dict:
    checked_integer(exponent, 1, MAX_EXPONENT, "exponent")
    count = point_count(model, prime)
    trace = prime + 1 - count
    power_trace = frobenius_power(trace, prime, exponent)
    normalized = power_trace / prime**(exponent/2)
    return {
        "p": prime, "exponent": exponent, "n": prime**exponent,
        "points_over_fp": count, "a_p": trace,
        "frobenius_power_trace": power_trace,
        "unitary_logarithmic_coefficient": normalized,
        "unitary_lambda_at_prime_power": normalized * math.log(prime),
    }


def reference_report(curve_name: str, primes: list[int], exponent: int = 1) -> dict:
    if curve_name not in CURVES:
        raise ValueError("unknown pinned public curve")
    if type(primes) is not list or not 1 <= len(primes) <= MAX_ROWS:
        raise ValueError("prime rows must be a nonempty bounded list")
    for prime in primes:
        checked_prime(prime)
    if len(set(primes)) != len(primes):
        raise ValueError("duplicate prime rows are not allowed")
    if sum(primes) > MAX_WORK:
        raise ValueError("aggregate point-count work budget exceeded")
    checked_integer(exponent, 1, MAX_EXPONENT, "exponent")
    curve = CURVES[curve_name]
    provenance = {"cremona": curve.cremona, "lmfdb": curve.lmfdb,
                  "a_invariants": list(curve.coefficients), "source": curve.source}
    pinned = json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode()
    return {
        "kind": "exact_public_curve_reference_not_spectral_recovery",
        "provenance": provenance, "model_sha256": hashlib.sha256(pinned).hexdigest(),
        "discriminant": discriminant(curve.coefficients),
        "normalization": "L_unitary(s)=L_E(s+1/2); lambda(p^k)=(alpha^k+beta^k)*p^(-k/2)*log(p)",
        "exact_fields": ["n", "points_over_fp", "a_p", "frobenius_power_trace"],
        "floating_fields": ["unitary_logarithmic_coefficient", "unitary_lambda_at_prime_power"],
        "work": {"x_values_upper_bound": sum(primes), "maximum": MAX_WORK},
        "rows": [local_reference(curve.coefficients, p, exponent) for p in primes],
        "limitations": ["good reduction of the supplied model only",
                        "no complete L-zero spectrum or gamma/pole correction supplied",
                        "no cryptographic curve generation or group-order certification"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--curve", choices=tuple(CURVES), required=True)
    parser.add_argument("--primes", type=int, nargs="+", default=[2, 3, 5, 7, 13, 17, 19, 23, 29, 31])
    parser.add_argument("--exponent", type=int, default=1)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = reference_report(args.curve, args.primes, args.exponent)
        encoded = json.dumps(report, indent=2, allow_nan=False) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded)
        else:
            print(encoded, end="")
    except (ValueError, ArithmeticError, OSError) as error:
        parser.exit(2, f"error: {error}\n")


if __name__ == "__main__":
    main()
