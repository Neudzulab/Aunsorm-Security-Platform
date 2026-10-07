"""Bounded deterministic gauge parser/matrix mutations; not coverage-guided."""

import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))

from sasrl_cluster_conditioning import work_bound
from sasrl_observed_reproduce import fixture
from sasrl_signal_stdin import fuzz
from sasrl_telemetry import GaugeCapture

MAX_CASES=1024
MAX_MATRIX_WORK=32_000_000


def corpus():
    offsets=[i*1000 for i in range(32)]
    jitter=offsets.copy()
    jitter[7]+=1
    controls=[fixture(offsets,list(range(32))),
              fixture([i*2000 for i in range(32)],list(range(0,64,2))),
              fixture(jitter,list(range(32)))]
    cases=[]
    for control in controls:
        raw=json.dumps(control,separators=(',',':')).encode('utf-8')
        cases.append(raw)
        # Valid JSON mutations exercise accepted data beyond the three seeds:
        # timing geometry, sequence gaps/duplicates and gauge amplitude bounds.
        for index in (1,7,16,31):
            for field in ('timestamp_ms','sequence','gauge'):
                changed=json.loads(raw)
                frame=changed['records'][index]['frame']
                if field=='gauge':
                    frame['payload']['otel']['gauges'][0]['value']=1e101
                elif field=='sequence':
                    frame[field]=changed['records'][index-1]['frame'][field]
                else:
                    frame[field]+=1
                cases.append(json.dumps(changed,separators=(',',':'),allow_nan=False).encode('utf-8'))
        for index in range(0,len(raw),64):
            altered=bytearray(raw)
            altered[index]^=128
            cases.append(bytes(altered))
        for end in range(0,len(raw),64):
            cases.append(raw[:end])
    return cases


def run():
    cases=corpus()
    planned=len(cases)*work_bound(64,2,40)
    if len(cases)>MAX_CASES or planned>MAX_MATRIX_WORK:
        raise ValueError('deterministic corpus exceeds case/aggregate matrix budget')
    digest=hashlib.sha256()
    accepted=0
    for raw in cases:
        digest.update(len(raw).to_bytes(8,'little'))
        digest.update(raw)
        try:
            GaugeCapture.from_bytes(raw)
        except ValueError:
            pass
        else:
            accepted+=1
        fuzz(raw)
    return {'cases':len(cases),'accepted_gauge_inputs':accepted,
            'failures':0,'corpus_sha256':digest.hexdigest(),
            'planned_sample_scaled_matrix_work_upper_bound':planned,
            'aggregate_matrix_work_limit':MAX_MATRIX_WORK,
            'harness_sha256':hashlib.sha256(Path(__file__).with_name('sasrl_signal_stdin.py').read_bytes()).hexdigest(),
            'coverage_guided':False,
            'scope':'three synthetic 32-position controls, valid timing/sequence/gauge mutations, high-bit changes and truncations',
            'limitations':['Expected parser rejection only; post-parse failures propagate',
                           'No live capture, sustained fuzz coverage or authenticated recovery claim']}


if __name__=='__main__':
    print(json.dumps(run(),indent=2,allow_nan=False))
