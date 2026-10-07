"""Bounded real AES-GCM seed mutations against the production shared decoder."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess

MAX_CASES=1024
MAX_BYTES=1104


def corpus(seed):
    if len(seed)!=88 or seed[80:]!=b'pkcs-key':
        raise ValueError('expected the synthetic native-nonce fixture framing')
    envelope=base64.b64decode(seed[:80],validate=True)
    if len(envelope)!=60:
        raise ValueError('fixture must contain the exact nonce/seed/tag envelope')
    cases=[seed]
    for index in range(60):
        for bit in range(8):
            mutated=bytearray(envelope)
            mutated[index]^=1<<bit
            cases.append(base64.b64encode(mutated)+seed[80:])
    for index in range(80):
        mutated=bytearray(seed)
        mutated[index]^=128
        cases.append(bytes(mutated))
    cases.extend(seed[:end] for end in range(len(seed)))
    cases.extend([seed+b'\x00',seed[:80]+b'other-key',b'!'*80+b'pkcs-key',
                  b'A'*79,b'A'*81,base64.b64encode(envelope[:-1])+seed[80:],
                  seed[:80]+b'A'*1024])
    return cases


def run(executable,fixture):
    with fixture.open('rb') as handle:
        seed=handle.read(MAX_BYTES+1)
    cases=corpus(seed)
    if len(cases)>MAX_CASES or any(len(raw)>MAX_BYTES for raw in cases):
        raise ValueError('wrapped-seed corpus exceeds aggregate/input budgets')
    digest=hashlib.sha256()
    accepted=0
    for index,raw in enumerate(cases):
        digest.update(len(raw).to_bytes(8,'little'))
        digest.update(raw)
        result=subprocess.run([str(executable)],input=raw,capture_output=True,timeout=10)
        if result.returncode:
            raise RuntimeError(f'unexpected failure on case {index}: {result.stderr!r}')
        expected=b'accepted' if index==0 else b'rejected'
        if result.stdout.strip()!=expected:
            raise AssertionError(f'unexpected authentication outcome on case {index}')
        accepted+=result.stdout.strip()==b'accepted'
    return {'cases':len(cases),'accepted':accepted,'rejected':len(cases)-accepted,'failures':0,
            'corpus_sha256':digest.hexdigest(),'fixture_sha256':hashlib.sha256(seed).hexdigest(),
            'decoder_sha256':hashlib.sha256(Path(__file__).resolve().parents[1].joinpath('crates/kms/src/wrapped_seed.rs').read_bytes()).hexdigest(),
            'executable_sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),
            'case_budget':MAX_CASES,'input_byte_budget':MAX_BYTES,'coverage_guided':False,
            'fixture':'known synthetic key/seed, actual AES-GCM with AunsormNativeRng nonce',
            'scope':'every envelope bit, malformed base64, all truncations and AAD/length changes',
            'limitations':['Not live HSM or a sustained coverage-guided engine run',
                           'Known fixture key/seed are test material, not production secrets']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable',type=Path)
    parser.add_argument('fixture',type=Path)
    parser.add_argument('--generate-fixture',action='store_true')
    args=parser.parse_args()
    if args.generate_fixture:
        generated=subprocess.run([str(args.executable),'--seed'],capture_output=True,check=True,timeout=30)
        with args.fixture.open('xb') as handle:
            handle.write(generated.stdout)
    print(json.dumps(run(args.executable,args.fixture),indent=2,allow_nan=False))
