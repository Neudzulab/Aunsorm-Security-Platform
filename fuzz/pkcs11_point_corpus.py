"""Run bounded canonical/DER mutations through the shared-source stdin binary."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

MAX_CASES=4096
MAX_BYTES=4097


def corpus():
    cases=[]
    for first in (0,4,255):
        key=bytes([first])+bytes(range(1,32))
        for prefix in (b'\x04\x20',b'\x04\x22\x04\x20'):
            encoded=prefix+key
            cases.append(encoded)
            cases.extend(encoded[:end] for end in range(len(encoded)))
            cases.append(encoded+b'\x00')
            if first==4:
                for index in range(len(prefix)):
                    for value in range(256):
                        modified=bytearray(encoded)
                        modified[index]=value
                        cases.append(bytes(modified))
    key=bytes(range(32))
    for prefix in (b'\x04\x81\x20',b'\x04\x82\x00\x20',b'\x04\x80',
                   b'\x04\x88'+b'\xff'*8,b'\x04\x24\x04\x22\x04\x20'):
        cases.append(prefix+key)
    cases.extend([b'\x00'*4096,b'\x04\x20'+key+b'\x00'*(4097-34)])
    return cases


def run(executable):
    cases=corpus()
    if len(cases)>MAX_CASES or any(len(raw)>MAX_BYTES for raw in cases):
        raise ValueError('PKCS11 corpus exceeds preflighted case/input budgets')
    digest=hashlib.sha256()
    for raw in cases:
        digest.update(len(raw).to_bytes(8,'little'))
        digest.update(raw)
        result=subprocess.run([str(executable)],input=raw,capture_output=True,timeout=10)
        if result.returncode:
            raise RuntimeError(f'parser failed on corpus index with input length {len(raw)}: {result.stderr!r}')
    return {'cases':len(cases),'failures':0,'corpus_sha256':digest.hexdigest(),
            'executable_sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),
            'parser_sha256':hashlib.sha256(Path(__file__).resolve().parents[1].joinpath(
                'crates/kms/src/pkcs11_point.rs').read_bytes()).hexdigest(),
            'coverage_guided':False,'case_budget':MAX_CASES,'input_byte_budget':MAX_BYTES,
            'scope':'single/double DER, every truncation, full header byte mutations, overflow and trailing data',
            'limitations':['Pure shared-source parser controls, no live HSM invocation',
                           'Cryptoki dependency advisory is not remediated by caller parser changes']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable',type=Path)
    args=parser.parse_args()
    print(json.dumps(run(args.executable),indent=2,allow_nan=False))
