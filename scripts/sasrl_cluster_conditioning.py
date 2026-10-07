"""Bounded small Fourier-cluster diagnostic; not a certified SVD/recovery tool."""

import argparse
import json
import math
import sys

from sasrl_recovery import finite_number

MAX_SAMPLES = 512
MAX_MODES = 8
MAX_SWEEPS = 40
MAX_WORK = 8_000_000
CORRELATION_TOLERANCE = 1e-12


def work_bound(samples, modes, sweeps):
    return 12*samples*(modes*(modes-1)//2)*sweeps + 4*samples*modes


def norm_squared(column):
    return math.fsum(x.real*x.real + x.imag*x.imag for x in column)


def inner(left, right):
    products = tuple(a.conjugate()*b for a,b in zip(left,right))
    return complex(math.fsum(x.real for x in products), math.fsum(x.imag for x in products))


def residual_correlation(columns, floor):
    norms = [norm_squared(column) for column in columns]
    maximum = 0.0
    for left in range(len(columns)):
        for right in range(left+1,len(columns)):
            if min(norms[left],norms[right]) <= floor*floor:
                continue
            maximum = max(maximum,abs(inner(columns[left],columns[right]))
                          /math.sqrt(norms[left]*norms[right]))
    return maximum


def cluster_conditioning(samples, frequencies, rate, sweeps=MAX_SWEEPS):
    if type(samples) is not int or not 2 <= samples <= MAX_SAMPLES:
        raise ValueError('sample count must be an integer in 2..512')
    if type(frequencies) not in (tuple,list) or not 2 <= len(frequencies) <= min(samples,MAX_MODES):
        raise ValueError('a plain vector of 2..8 known modes, not exceeding samples, is required')
    if type(sweeps) is not int or not 1 <= sweeps <= MAX_SWEEPS:
        raise ValueError('sweeps must be an integer in 1..40')
    rate = finite_number(rate,'sample rate')
    if rate <= 0:
        raise ValueError('sample rate must be positive')
    frequencies = tuple(finite_number(x,'frequency') for x in frequencies)
    ratios = tuple(finite_number(x/rate,'normalized frequency') for x in frequencies)
    if any(abs(x)>1e6 for x in ratios):
        raise ValueError('frequency/sample-rate ratio exceeds the bounded phase range')
    phases = tuple(math.remainder(x,1.0) for x in ratios)
    aliases = len(set(phases)) != len(phases)
    modes = len(phases)
    bound = work_bound(samples,modes,sweeps)
    if bound > MAX_WORK:
        raise ValueError('matrix exceeds the sample-scaled sweep work budget')
    scale = 1/math.sqrt(samples)
    columns = [[complex(math.cos(math.tau*f*k),math.sin(math.tau*f*k))*scale
                for k in range(samples)] for f in phases]
    return _diagnose(columns,frequencies,rate,sweeps,aliases,bound)


def timestamp_cluster_conditioning(timestamps_ms,frequencies,sweeps=MAX_SWEEPS):
    """Use only observed declared positions; no nominal-grid gap filling."""
    if type(timestamps_ms) not in (list,tuple) or not 2 <= len(timestamps_ms) <= MAX_SAMPLES:
        raise ValueError('timestamp vector must contain 2..512 observed positions')
    if any(type(x) is not int or not 0 <= x < 2**64 for x in timestamps_ms):
        raise ValueError('timestamps must be unsigned 64-bit integer milliseconds')
    if any(b <= a for a,b in zip(timestamps_ms,timestamps_ms[1:])):
        raise ValueError('observed timestamps must be strictly increasing')
    samples=len(timestamps_ms)
    if type(frequencies) not in (list,tuple) or not 2 <= len(frequencies) <= min(samples,MAX_MODES):
        raise ValueError('a bounded vector of 2..8 known frequencies is required')
    if type(sweeps) is not int or not 1 <= sweeps <= MAX_SWEEPS:
        raise ValueError('sweeps must be an integer in 1..40')
    frequencies=tuple(finite_number(x,'frequency') for x in frequencies)
    # Subtract integers first: converting large absolute epochs to float loses
    # millisecond differences, especially near the u64 timestamp limit.
    relative_ms=tuple(x-timestamps_ms[0] for x in timestamps_ms)
    if relative_ms[-1] > 86_400_000:
        raise ValueError('observed span exceeds the 24-hour diagnostic budget')
    span=relative_ms[-1]/1000
    if any(abs(finite_number(f*span,'phase extent'))>1e6 for f in frequencies):
        raise ValueError('frequency/span product exceeds the phase budget')
    bound=work_bound(samples,len(frequencies),sweeps)
    if bound > MAX_WORK:
        raise ValueError('matrix exceeds the sample-scaled sweep work budget')
    scale=1/math.sqrt(samples)
    # Reduce each actual phase, not f/nominal_rate: irregular positions do not
    # inherit the uniform grid's alias equivalence.
    columns=[]
    for frequency in frequencies:
        cycles=[math.remainder(frequency*(offset/1000),1.0) for offset in relative_ms]
        columns.append([complex(math.cos(math.tau*x),math.sin(math.tau*x))*scale for x in cycles])
    aliases=len(set(tuple(column) for column in columns)) != len(columns)
    result=_diagnose(columns,frequencies,None,sweeps,aliases,bound)
    result['model']='known complex Fourier modes at observed declared millisecond timestamps'
    result['relative_timestamps_ms']=relative_ms
    result['timestamp_origin_ms']=timestamps_ms[0]
    result['nyquist_hz']=None
    result.pop('exact_binary64_alias_detected')
    result['exact_binary64_duplicate_columns_detected']=aliases
    result['limitations']=[
        'Observed positions only; no missing samples, jitter correction or cadence inference',
        'Producer timestamps are unverified and can hide sub-millisecond physical jitter',
        'Irregular timestamps have no single declared Nyquist frequency',
    ]+result['limitations']
    return result


def _diagnose(columns,frequencies,rate,sweeps,aliases,bound):
    samples=len(columns[0])
    modes=len(columns)
    # A heuristic resolution cutoff, deliberately not a rigorous error bound.
    floor = 64*sys.float_info.epsilon*math.sqrt(samples*modes)*math.sqrt(modes)
    converged = False
    rotations = 0
    completed = 0
    for sweep in range(sweeps):
        for left in range(modes):
            for right in range(left+1,modes):
                a,b = columns[left],columns[right]
                aa,bb = norm_squared(a),norm_squared(b)
                if min(aa,bb) <= floor*floor:
                    continue
                cross = inner(a,b)
                magnitude = abs(cross)
                if magnitude <= CORRELATION_TOLERANCE*math.sqrt(aa*bb):
                    continue
                phase = cross.conjugate()/magnitude
                tau = (bb-aa)/(2*magnitude)
                tangent = math.copysign(1,tau)/(abs(tau)+math.hypot(1,tau))
                cosine = 1/math.hypot(1,tangent)
                sine = tangent*cosine
                columns[left] = [cosine*x-sine*phase*y for x,y in zip(a,b)]
                columns[right] = [sine*x+cosine*phase*y for x,y in zip(a,b)]
                rotations += 1
        completed = sweep+1
        residual = residual_correlation(columns,floor)
        if residual <= CORRELATION_TOLERANCE:
            converged = True
            break
    singular = sorted(math.sqrt(norm_squared(column)) for column in columns)
    trace_error = abs(math.fsum(x*x for x in singular)-modes)
    if not all(math.isfinite(x) for x in singular) or trace_error > 1e-10*modes:
        raise ArithmeticError('Jacobi transformations violated the finite/Frobenius invariant')
    unresolved = aliases or singular[0] <= floor
    reliable = converged and not unresolved
    return {'model':'small complete uniform complex Fourier matrix, known frequencies',
            'algorithm':'unpreconditioned one-sided complex Jacobi column rotations',
            'samples':samples,'frequencies_hz':frequencies,'sample_rate_hz':rate,
            'singular_value_estimates':singular,'converged':converged,
            'sweeps_completed':completed,'sweep_limit':sweeps,'rotations':rotations,
            'maximum_resolved_column_correlation':residual,
            'correlation_tolerance':CORRELATION_TOLERANCE,
            'heuristic_resolution_floor':floor,'exact_binary64_alias_detected':aliases,
            'numerically_unresolved':unresolved,
            'condition_estimate':singular[-1]/singular[0] if reliable else None,
            'noise_gain_estimate':1/singular[0] if reliable else None,
            'frobenius_squared_error':trace_error,'sample_scaled_work_upper_bound':bound,
            'status':'converged estimate' if reliable else 'unresolved' if unresolved else 'nonconverged',
            'limitations':['Binary64 diagnostic, not LAPACK accuracy guarantees or certified rank',
                           'Resolution floor is heuristic; sub-floor column correlations are excluded',
                           'Known 2..8 modes only; matrix positions do not authenticate data',
                           'No inverse, missing-data reconstruction, authentication or sub-Nyquist theorem']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples',type=int,required=True)
    parser.add_argument('--frequencies-hz',type=float,nargs='+',required=True)
    parser.add_argument('--sample-rate-hz',type=float,required=True)
    args=parser.parse_args()
    try:
        print(json.dumps(cluster_conditioning(args.samples,args.frequencies_hz,args.sample_rate_hz),
                         indent=2,allow_nan=False))
    except ValueError as error:
        parser.error(str(error))


if __name__=='__main__':
    main()
