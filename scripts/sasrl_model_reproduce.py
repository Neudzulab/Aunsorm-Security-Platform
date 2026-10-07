"""Reproduce supported-model contract using the real bundled Odlyzko prefix."""

import hashlib
import json
from pathlib import Path

from sasrl_recovery import MAX_INPUT_BYTES, ZeroSpectrum, hard_cutoff, weighted, zeta_model


def run():
    path=Path(__file__).with_name('data')/'sasrl-odlyzko-prefix.json'
    with path.open('rb') as handle:
        raw=handle.read(MAX_INPUT_BYTES+1)
    legacy=ZeroSpectrum.from_bytes(raw)
    data=json.loads(raw)
    data['l_function']=zeta_model()
    declared_raw=json.dumps(data,allow_nan=False).encode('utf-8')
    declared=ZeroSpectrum.from_bytes(declared_raw)
    comparisons=[]
    for m in (3,10,20):
        for name,method in (('hard',hard_cutoff),('weighted',weighted)):
            left,right=method(m,legacy),method(m,declared)
            if left!=right:
                raise ArithmeticError('model declaration changed numerical results')
            comparisons.append({'integer':m,'method':name,'estimate':left['estimate'],
                                'legacy_explicit_results_identical':True})
    alternatives={'id':'dirichlet_beta','degree':2,'conductor':4,'self_dual':False,
                  'normalization':'unitary_shift_by_half','critical_line_real_part':1.0,
                  'pole_at_one_order':0,'gamma_factor':'Gamma((s+1)/2)',
                  'trivial_zeros':'negative_odd_integers'}
    rejected=[]
    for field,value in alternatives.items():
        changed=json.loads(declared_raw)
        changed['l_function'][field]=value
        try:
            ZeroSpectrum.from_bytes(json.dumps(changed).encode('utf-8'))
        except ValueError as error:
            rejected.append({'field':field,'rejected':True,'reason':str(error)})
        else:
            raise AssertionError('contradictory model accepted')
    return {'source':legacy.source,'input_sha256':legacy.sha256,
            'explicit_metadata_input_sha256':declared.sha256,
            'implementation_sha256':hashlib.sha256(Path(__file__).with_name('sasrl_recovery.py').read_bytes()).hexdigest(),
            'supported_model':zeta_model(),'legacy_declaration':legacy.model_declaration,
            'explicit_declaration':declared.model_declaration,'comparisons':comparisons,
            'rejected_contradictions':rejected,'analytic_model_verified_from_input':False,
            'coverage_verified':False,'cryptographic_use':False,
            'limitations':['Metadata contract does not prove that ordinates belong to zeta',
                           'No general primitive L-function or missing correction support',
                           'Explicit declarations do not certify RH, completeness or input precision']}


if __name__=='__main__':
    print(json.dumps(run(),indent=2,allow_nan=False))
