"""Bounded deterministic smoke corpus for the stable QUIC stdin harness."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def corpus():
    # Postcard v1 header, telemetry channel and three empty sample vectors.
    telemetry = bytes([1, 0, 0, 0, 0, 0, 0, 0])
    # Audio enum variant 3: fixed 96kHz mono profile, opaque one-byte shard.
    audio = (bytes([1, 3, 0, 0, 3, 7]) + varint(96000)
             + bytes([1, 0]) + varint(960) + bytes([10, 0, 1, 1, 42]))
    for seed in [telemetry, audio]:
        yield seed
        for end in range(len(seed)):
            yield seed[:end]
        for index in range(len(seed)):
            for bit in range(8):
                mutated = bytearray(seed)
                mutated[index] ^= 1 << bit
                yield bytes(mutated)
        yield seed + b"\x00"
        yield seed + b"\xff" * 1351
    for size in [0, 1, 7, 17, 959, 960, 1150, 1350, 1351, 1919, 1920, 1921]:
        for index in range(8):
            yield hashlib.shake_256(f"quic-corpus:{size}:{index}".encode()).digest(size)
    yield bytes(1920)
    yield bytes(range(256)) * 7 + bytes(range(128))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default = Path(__file__).resolve().parents[1] / "target/debug/examples/quic_datagram_fuzz_stdin.exe"
    parser.add_argument("--executable", type=Path, default=default)
    args = parser.parse_args()
    executable = args.executable.resolve(strict=True)
    count = 0
    digest = hashlib.sha256()
    for count, payload in enumerate(corpus(), 1):
        digest.update(len(payload).to_bytes(4, "little"))
        digest.update(payload)
        result = subprocess.run([str(executable)], input=payload, capture_output=True,
                                timeout=10, check=False)
        if result.returncode:
            raise RuntimeError(f"corpus case {count}: {result.stderr.decode(errors='replace')}")
    print(json.dumps({"cases": count, "failures": 0, "corpus_sha256": digest.hexdigest(),
                      "coverage_guided": False}, indent=2))


if __name__ == "__main__":
    main()
