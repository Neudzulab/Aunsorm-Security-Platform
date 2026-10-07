"""Bounded real Ed25519 response mutations; no live HSM or provider mock."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

MAX_CASES=1024
MAX_BYTES=1120


def corpus(seed):
    if len(seed)!=109 or seed[96:]!=b'pkcs-identity':
        raise ValueError('expected the known synthetic Ed25519 response framing')
    cases=[seed]
    for index in range(len(seed)):
        for bit in range(8):
            changed=bytearray(seed)
            changed[index]^=1<<bit
            cases.append(bytes(changed))
    cases.extend(seed[:end] for end in range(len(seed)))
    cases.extend([seed+b'\x00',b'\x00'*32+seed[32:],b'\x01'+b'\x00'*31+seed[32:],
                  seed[:64]+b'\xff'*32+seed[96:],seed[:96]+b'A'*1024])
    return cases


def run(executable,fixture):
    with fixture.open('rb') as handle:
        seed=handle.read(MAX_BYTES+1)
    cases=corpus(seed)
    if len(cases)>MAX_CASES or any(len(raw)>MAX_BYTES for raw in cases):
        raise ValueError('identity corpus exceeds case/input budgets')
    digest=hashlib.sha256()
    for index,raw in enumerate(cases):
        digest.update(len(raw).to_bytes(8,'little'))
        digest.update(raw)
        result=subprocess.run([str(executable)],input=raw,capture_output=True,timeout=10)
        if result.returncode:
            raise RuntimeError(f'identity driver failed on case {index}: {result.stderr!r}')
        expected=b'accepted' if index==0 else b'rejected'
        if result.stdout.strip()!=expected:
            raise AssertionError(f'unexpected response verification outcome on case {index}')
    return {'cases':len(cases),'accepted':1,'rejected':len(cases)-1,'failures':0,
            'corpus_sha256':digest.hexdigest(),'fixture_sha256':hashlib.sha256(seed).hexdigest(),
            'verifier_sha256':hashlib.sha256(Path(__file__).resolve().parents[1].joinpath('crates/kms/src/pkcs11_identity.rs').read_bytes()).hexdigest(),
            'executable_sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),
            'case_budget':MAX_CASES,'input_byte_budget':MAX_BYTES,'coverage_guided':False,
            'fixture':'actual deterministic Ed25519 signature using a known synthetic seed',
            'limitations':['Verifies response math; no hardware session or live HSM claim',
                           'Compiled/seeded controls do not establish sustained fuzz coverage']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable',type=Path)
    parser.add_argument('fixture',type=Path)
    parser.add_argument('--generate-fixture',action='store_true')
    args=parser.parse_args()
    if args.generate_fixture:
        result=subprocess.run([str(args.executable),'--seed'],capture_output=True,check=True,timeout=30)
        with args.fixture.open('xb') as handle:
            handle.write(result.stdout)
    print(json.dumps(run(args.executable,args.fixture),indent=2,allow_nan=False))
