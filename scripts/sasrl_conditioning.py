#!/usr/bin/env python3
"""Two-mode conditioning diagnostic for uniformly sampled public signals.

An explicit implementation of the paper's conditioning caution, not a general
sub-Nyquist recovery theorem or a production anomaly decision.
"""

import argparse
import json
import math

from sasrl_recovery import finite_number


def two_mode_conditioning(samples: int, spacing_hz: float, sample_rate_hz: float) -> dict:
    """Singular values of two normalized Fourier columns on a uniform grid.

    Gram eigenvalues are 1 +/- |c| where c is the average exp(i*k*delta).
    Near a cluster, compute 1-|c| from a nonnegative sine-squared identity
    instead of subtracting nearly equal numbers. This avoids cancellation.
    """
    if isinstance(samples, bool) or not isinstance(samples, int) or not 2 <= samples <= 4096:
        raise ValueError("sample count must be an integer in [2, 4096]")
    spacing_hz = finite_number(spacing_hz, "spacing_hz")
    sample_rate_hz = finite_number(sample_rate_hz, "sample_rate_hz")
    if spacing_hz < 0 or sample_rate_hz <= 0:
        raise ValueError("spacing must be nonnegative and sample rate must be positive")
    # Check the ratio before multiplying by 2*pi, to reject overflow clearly.
    ratio = finite_number(spacing_hz / sample_rate_hz, "normalized spacing")
    # Aliasing is periodic; reduce before multiplication, preserving small gaps.
    delta = math.tau * math.remainder(ratio, 1.0)
    real = math.fsum(math.cos(index * delta) for index in range(samples)) / samples
    imaginary = math.fsum(math.sin(index * delta) for index in range(samples)) / samples
    correlation = min(1.0, math.hypot(real, imaginary))
    # 1-|c|^2 = (4/N^2) sum_{d=1}^{N-1} (N-d)*sin^2(d*delta/2).
    determinant = 4.0 / (samples * samples) * math.fsum(
        (samples - distance) * math.sin(distance * delta / 2) ** 2
        for distance in range(1, samples)
    )
    sigma_min = math.sqrt(determinant / (1 + correlation))
    sigma_max = math.sqrt(1 + correlation)
    return {"model": "two_normalized_uniform_fourier_columns",
            "samples": samples, "sample_rate_hz": sample_rate_hz,
            "frequency_spacing_hz": spacing_hz, "nyquist_hz": sample_rate_hz / 2,
            "sigma_min": sigma_min, "sigma_max": sigma_max,
            "condition_number": sigma_max / sigma_min if sigma_min else None,
            "worst_case_noise_gain": 1 / sigma_min if sigma_min else None,
            "indistinguishable_modes": sigma_min == 0,
            "limitations": ["Only two modes and exact uniform sample times",
                            "Larger clusters require their full matrix singular values",
                            "Does not certify recovery or authenticate missing events"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, required=True)
    parser.add_argument("--spacing-hz", type=float, required=True)
    parser.add_argument("--sample-rate-hz", type=float, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(two_mode_conditioning(args.samples, args.spacing_hz,
                                              args.sample_rate_hz), indent=2, allow_nan=False))
    except (ValueError, OverflowError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
