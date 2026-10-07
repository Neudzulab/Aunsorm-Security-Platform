"""Reproducible synthetic demonstration, NOT entropy measurement or true RNG."""
import hashlib
import json
import math
from pathlib import Path
import random
import sys
from extractor import extract, output_budget


def main():
    n, blocks, security = 4096, 1000, 128
    # Synthetic IID Bernoulli model; its parameter is KNOWN, not inferred from
    # a histogram. PRNG-generated samples do not satisfy an IT-security claim.
    p = 0.8
    k = math.floor(-n * math.log2(max(p, 1 - p)))
    m = output_budget(n, k, security)
    raw_rng, seed_rng = random.Random(20261007), random.Random(20261008)
    raw_ones = out_ones = exact_balanced_blocks = 0
    digest = hashlib.sha256()
    for _ in range(blocks):
        x = sum((raw_rng.random() < p) << j for j in range(n))
        seed = seed_rng.getrandbits(n + m - 1)
        y = extract(x, seed, n, m)
        raw_ones += x.bit_count()
        ones = y.bit_count()
        out_ones += ones
        exact_balanced_blocks += ones == m // 2
        digest.update(y.to_bytes((m + 7) // 8, "little"))
    result = {
        "status": "synthetic PRNG demonstration; no measured physical entropy or production guarantee",
        "model": "IID Bernoulli(p=0.8), known parameter; independent ideal uniform seeds assumed only by theorem",
        "input_bits_per_block": n, "blocks": blocks,
        "model_min_entropy_floor_bits": k, "output_bits_per_block": m,
        "security_bits": security, "conditional_bound": "TV <= 2^-129 per block, only under certified entropy and ideal independent seed assumptions",
        "raw_total_bits": n * blocks, "raw_ones": raw_ones,
        "raw_one_fraction": raw_ones / (n * blocks),
        "output_total_bits": m * blocks, "output_ones": out_ones,
        "output_one_fraction": out_ones / (m * blocks),
        "exact_half_ones_output_blocks": exact_balanced_blocks,
        "output_sha256_padded_little_endian_blocks": digest.hexdigest(),
        "python": sys.version.split()[0],
        "source_sha256": {f: hashlib.sha256(Path(__file__).with_name(f).read_bytes()).hexdigest() for f in ["extractor.py", "experiment.py", "test_extractor.py"]},
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
