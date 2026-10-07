"""Fixed observed-time controls; no values fitted or missing events recovered."""

import argparse
import hashlib
import json
import math
from pathlib import Path

from sasrl_cluster_conditioning import work_bound
from sasrl_telemetry import GaugeCapture, analyze

AGGREGATE_WORK_LIMIT=100_000


def fixture(offsets, sequences):
    origin=2**64-100_000
    return {'source':'synthetic observed-time control; not a live capture',
            'connection_id':'synthetic-only','metric':'active_contexts',
            'expected_interval_ms':1000,
            'records':[{'connection_id':'synthetic-only','frame':{
                'version':1,'channel':0,'sequence':sequence,
                'timestamp_ms':origin+offset,'payload':{'otel':{'gauges':[
                    {'name':'active_contexts','value':math.cos(math.tau*i/32)}]}}}}
                for i,(offset,sequence) in enumerate(zip(offsets,sequences))]}


def run():
    uniform=[i*1000 for i in range(32)]
    jitter=uniform.copy()
    jitter[7]+=1
    configurations=[('uniform',uniform,list(range(32)),[0,.5]),
                    ('thinned',[i*2000 for i in range(32)],list(range(0,64,2)),[0,.5]),
                    ('jitter_breaks_alias',jitter,list(range(32)),[0,1]),
                    ('nominal_alias',uniform,list(range(32)),[0,1])]
    planned=sum(work_bound(len(offsets),len(frequencies),40)
                for _,offsets,_,frequencies in configurations)
    if planned>AGGREGATE_WORK_LIMIT:
        raise ValueError('observed reproduction exceeds aggregate matrix budget')
    rows=[]
    for name,offsets,sequences,frequencies in configurations:
        raw=json.dumps(fixture(offsets,sequences),allow_nan=False).encode('utf-8')
        result=analyze(GaugeCapture.from_bytes(raw),spectrum=True,
                       conditioning_frequencies=frequencies)
        rows.append({'control':name,'analysis':result})
    return {'fixture':'synthetic decoded gauge geometry at observed millisecond timestamps',
            'rows':rows,'planned_sample_scaled_work_upper_bound':planned,
            'aggregate_work_limit':AGGREGATE_WORK_LIMIT,
            'implementation_sha256':{name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                for name in ('sasrl_cluster_conditioning.py','sasrl_telemetry.py')},
            'limitations':['Gauge values not fitted; no missing slots reconstructed',
                           'Producer time/context are unverified; no live transport claim',
                           'Resolution floor is heuristic; known 2..8 modes only']}


def validate_numpy(report):
    import numpy as np

    rows=[]
    for control in report['rows']:
        row=control['analysis']['known_frequency_conditioning']['matrix']
        times=row['relative_timestamps_ms']
        frequencies=row['frequencies_hz']
        # Independent construction from relative integer times; no nominal Fs.
        matrix=np.exp(2j*np.pi*np.outer(np.asarray(times,dtype=np.float64)/1000,
                                       np.asarray(frequencies,dtype=np.float64)))/math.sqrt(len(times))
        reference=sorted(float(x) for x in np.linalg.svd(matrix,compute_uv=False))
        error=max(abs(a-b) for a,b in zip(reference,row['singular_value_estimates']))
        relative=abs(row['singular_value_estimates'][0]/reference[0]-1) if row['noise_gain_estimate'] is not None else None
        if error>=1e-12 or (relative is not None and relative>=1e-7):
            raise ArithmeticError('independent observed-time SVD comparison failed')
        rows.append({'control':control['control'],'numpy_singular_values':reference,
                     'maximum_absolute_sigma_difference':error,
                     'relative_min_sigma_error_if_resolved':relative})
    report['independent_numpy_validation']={
        'version':np.__version__,'api':'numpy.linalg.svd, complex128 observed-time matrix',
        'scope':'explicit optional host verification; runtime remains standard-library-only',
        'api_source':'https://numpy.org/doc/stable/reference/generated/numpy.linalg.svd.html',
        'rows':rows}
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-numpy',action='store_true')
    args=parser.parse_args()
    report=run()
    if args.verify_numpy:
        report=validate_numpy(report)
    print(json.dumps(report,indent=2,allow_nan=False))
