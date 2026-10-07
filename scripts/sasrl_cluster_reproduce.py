"""Fixed aggregate-budget Fourier cluster fixtures, including failure statuses."""

import argparse
import hashlib
import json
import math
from pathlib import Path

from sasrl_cluster_conditioning import cluster_conditioning, work_bound

AGGREGATE_WORK_LIMIT = 2_500_000


def run():
    frequencies = [(0,1), (0,.01), (0,.1,.2), (0,.01,.02), (0,.001,.002),
                   (0,.01,.02,.03), tuple(range(8)), tuple(i*.1 for i in range(8)),
                   (0,64,1), (0,1e-10,2e-10)]
    planned = sum(work_bound(64,len(row),40) for row in frequencies) + work_bound(64,4,1)
    if planned > AGGREGATE_WORK_LIMIT:
        raise ValueError('cluster reproduction exceeds aggregate sweep budget')
    rows = [cluster_conditioning(64,row,64,sweeps=40) for row in frequencies]
    incomplete = cluster_conditioning(64,[0,.03,.09,.11],64,sweeps=1)
    # Include every diagnostic, even when numerical convergence is unavailable.
    return {'fixture':'synthetic complex complete-grid known-frequency matrices',
            'rows':rows,'nonconvergence_control':incomplete,
            'planned_sample_scaled_work_upper_bound':planned,
            'aggregate_work_limit':AGGREGATE_WORK_LIMIT,
            'implementation_sha256':hashlib.sha256(Path(__file__).with_name('sasrl_cluster_conditioning.py').read_bytes()).hexdigest(),
            'method_reference':'https://www.netlib.org/lapack/explore-html/d1/d5e/dgesvj_8f_source.html',
            'reference_scope':'one-sided Jacobi concept only; this routine is not LAPACK or its accuracy guarantee',
            'limitations':['No inverse or authenticated missing-event reconstruction',
                           'Known synthetic modes; unresolved/nonconverged rows are retained explicitly',
                           'Independent DFT/two-mode/three-mode controls do not prove arbitrary-matrix accuracy']}


def validate_numpy(report):
    # Explicit optional host verification, never an implicit runtime fallback.
    import numpy as np

    rows = []
    for row in report['rows']:
        samples = row['samples']
        rate = row['sample_rate_hz']
        frequencies = row['frequencies_hz']
        matrix = np.array([
            [complex(math.cos(math.tau*math.remainder(f/rate,1)*k),
                     math.sin(math.tau*math.remainder(f/rate,1)*k))/math.sqrt(samples)
             for f in frequencies] for k in range(samples)], dtype=np.complex128)
        reference = sorted(float(x) for x in np.linalg.svd(matrix,compute_uv=False))
        estimated = row['singular_value_estimates']
        maximum = max(abs(a-b) for a,b in zip(estimated,reference))
        relative = abs(estimated[0]/reference[0]-1) if row['noise_gain_estimate'] is not None else None
        if maximum >= 1e-12 or (relative is not None and relative >= 1e-7):
            raise ArithmeticError('independent NumPy SVD comparison failed')
        rows.append({'frequencies_hz':frequencies,'numpy_singular_values':reference,
                     'maximum_absolute_sigma_difference':maximum,
                     'relative_min_sigma_error_if_resolved':relative,'status':row['status']})
    report['independent_numpy_validation'] = {
        'version':np.__version__,'api':'numpy.linalg.svd(compute_uv=False), complex128',
        'api_source':'https://numpy.org/doc/stable/reference/generated/numpy.linalg.svd.html',
        'scope':'explicit host validation only; runtime diagnostic remains standard-library-only',
        'rows':rows}
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-numpy',action='store_true',help='explicit independent SVD validation; requires NumPy')
    args=parser.parse_args()
    result=run()
    if args.verify_numpy:
        result=validate_numpy(result)
    print(json.dumps(result,indent=2,allow_nan=False))
