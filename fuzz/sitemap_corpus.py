"""Bounded deterministic smoke corpus for the stable sitemap parser harness."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def corpus():
    seeds = [b"<urlset><url><loc>/health?a=1&amp;b=2</loc></url></urlset>",
             b"<sitemapindex xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'><sitemap><loc>/child.xml</loc></sitemap></sitemapindex>"]
    for seed in seeds:
        yield seed
        for end in range(0, len(seed), 3):
            yield seed[:end]
        for index in range(len(seed)):
            mutated = bytearray(seed)
            mutated[index] ^= 1 << (index % 8)
            yield bytes(mutated)
        yield seed + b"<other/>"
    yield b"<!DOCTYPE urlset SYSTEM 'https://outside.invalid/entity'><urlset/>"
    yield b"<!DOCTYPE urlset [<!ENTITY x '&x;&x;'>]><urlset>&x;</urlset>"
    yield b"<x>" * 1000 + b"</x>" * 1000
    yield b"<urlset " + b" ".join(f"a{i}='x'".encode() for i in range(1000)) + b"/>"
    yield b"<urlset><![CDATA[" + b"<" * 32769 + b"]]></urlset>"
    yield b"<urlset><![CDATA[" + b"=" * 16385 + b"]]></urlset>"
    yield b"<urlset>" + b"<url><loc>/x</loc></url>" * 4097 + b"</urlset>"
    yield b"x" * (1024 * 1024 + 1)
    for size in [0, 1, 17, 1024, 32768]:
        yield hashlib.shake_256(f"sitemap-corpus:{size}".encode()).digest(size)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default = Path(__file__).resolve().parents[1] / "target/debug/examples/sitemap_fuzz_stdin.exe"
    parser.add_argument("--executable", type=Path, default=default)
    args = parser.parse_args()
    executable = args.executable.resolve(strict=True)
    count = 0
    digest = hashlib.sha256()
    started = time.monotonic()
    for count, payload in enumerate(corpus(), 1):
        if time.monotonic() - started > 120:
            raise TimeoutError("sitemap corpus exceeds its total time budget")
        digest.update(len(payload).to_bytes(4, "little"))
        digest.update(payload)
        result = subprocess.run([str(executable)], input=payload, capture_output=True,
                                timeout=10, check=False)
        if result.returncode:
            raise RuntimeError(f"case {count}: {result.stderr.decode(errors='replace')}")
    print(json.dumps({"cases": count, "failures": 0, "corpus_sha256": digest.hexdigest(),
                      "coverage_guided": False}, indent=2))


if __name__ == "__main__":
    main()
