"""Bounded synthetic two-mode noise experiment, independent QR/Gram controls."""

import json
import math

from sasrl_conditioning import two_mode_conditioning
from sasrl_recovery import finite_number

MAX_SAMPLES = 4096
MIN_QR_RESIDUAL = 1e-12


def complex_sum(values):
    values = tuple(values)
    return complex(math.fsum(x.real for x in values), math.fsum(x.imag for x in values))


def norm(values):
    return math.sqrt(math.fsum(abs(x)**2 for x in values))


def qr_model(samples, spacing, rate):
    spacing = finite_number(spacing, 'spacing')
    rate = finite_number(rate, 'rate')
    report = two_mode_conditioning(samples, spacing, rate)
    delta = math.tau * math.remainder(spacing/rate, 1.0)
    # e^(it)-1 without subtracting cos(t) from 1 near clustered columns.
    changes = tuple(complex(-2*math.sin(k*delta/2)**2, math.sin(k*delta))
                    for k in range(samples))
    mean_change = complex_sum(changes)/samples
    residual = tuple((x-mean_change)/math.sqrt(samples) for x in changes)
    r22 = norm(residual)
    if r22 <= MIN_QR_RESIDUAL:
        raise ValueError('aliased or numerically unresolved Fourier columns')
    q1 = tuple(x/r22 for x in residual)
    correlation = 1 + mean_change
    return changes, correlation, q1, r22, report


def solve(values, correlation, q1, r22):
    if not 2 <= len(values) <= MAX_SAMPLES or len(values) != len(q1):
        raise ValueError('bounded matching sample vectors required')
    if not all(math.isfinite(x.real) and math.isfinite(x.imag) for x in values):
        raise ValueError('samples must be finite')
    if not math.isfinite(r22) or r22 <= MIN_QR_RESIDUAL:
        raise ValueError('numerically unresolved QR residual')
    alpha = complex_sum(values)/math.sqrt(len(values))
    beta = complex_sum(q.conjugate()*x for q, x in zip(q1, values))
    second = beta/r22
    return alpha-correlation*second, second


def experiment(samples=64, spacing=.001, rate=64, epsilon=1e-7):
    if type(epsilon) not in (float, int) or not math.isfinite(epsilon) or not 0 < epsilon <= 1e-3:
        raise ValueError('perturbation norm must be finite in (0, 1e-3]')
    changes, correlation, q1, r22, report = qr_model(samples, spacing, rate)
    coefficients = (.7+.2j, -.1+.4j)
    clean = tuple((coefficients[0]+coefficients[1]*(1+x))/math.sqrt(samples)
                  for x in changes)
    # Left weakest direction from A*v_min. Trig difference avoids cancellation
    # when both phases are close; normalize the actually represented vector.
    phase = math.atan2(correlation.imag, correlation.real)
    delta = math.tau*math.remainder(spacing/rate, 1.0)
    direction = tuple(2j*math.sin((k*delta-phase)/2)
                      *complex(math.cos((k*delta+phase)/2), math.sin((k*delta+phase)/2))
                      for k in range(samples))
    length = norm(direction)
    if length == 0:
        raise ValueError('unresolved perturbation direction')
    noisy = tuple(x+epsilon*d/length for x,d in zip(clean,direction))
    clean_fit = solve(clean,correlation,q1,r22)
    noisy_fit = solve(noisy,correlation,q1,r22)
    actual_noise = norm(tuple(a-b for a,b in zip(noisy,clean)))
    if actual_noise == 0:
        raise ValueError('perturbation rounded away')
    coefficient_shift = norm(tuple(a-b for a,b in zip(noisy_fit,clean_fit)))
    return {'samples': samples, 'spacing_hz': spacing, 'sample_rate_hz': rate,
            'requested_noise_l2': epsilon, 'represented_noise_l2': actual_noise,
            'coefficient_shift_l2': coefficient_shift,
            'measured_noise_gain': coefficient_shift/actual_noise,
            'predicted_worst_case_noise_gain': report['worst_case_noise_gain'],
            'measured_to_predicted_gain': coefficient_shift/actual_noise/report['worst_case_noise_gain'],
            'clean_coefficient_error_l2': norm(tuple(a-b for a,b in zip(clean_fit,coefficients))),
            'qr_residual_norm': r22, 'gram_determinant': report['sigma_min']**2*report['sigma_max']**2,
            'qr_residual_squared': r22*r22,
            'solver': 'two-column complex QR with cancellation-aware centered residual',
            'sample_lattice': 'complete exact uniform grid; known frequencies; no missing samples'}


def run():
    rejected = []
    for spacing in (0,64,128):
        try:
            qr_model(64,spacing,64)
        except ValueError:
            rejected.append(spacing)
        else:
            raise ArithmeticError('aliased columns were accepted')
    return {'fixture': 'synthetic complex normalized Fourier columns, not authenticated events',
            'rows': [experiment(spacing=x) for x in (1,.1,.01,.001,.0001,.00001,.000001)],
            'maximum_fixture_samples': 64, 'number_of_rows': 7,
            'alias_cases_rejected': rejected, 'minimum_resolvable_qr_residual': MIN_QR_RESIDUAL,
            'limitations': ['Known two-mode uniform grid only, not arbitrary spectral clusters',
                            'QR and trig calculations use binary64; explicit roundoff errors are reported',
                            'Weakest-direction perturbation is adversarial, not a typical noise distribution',
                            'Complex Fourier coefficients are not a real mono PCM recovery model',
                            'No source authentication, audit-event reconstruction or sub-Nyquist guarantee']}


if __name__ == '__main__':
    print(json.dumps(run(),indent=2,allow_nan=False))
