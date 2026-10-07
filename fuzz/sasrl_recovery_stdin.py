#!/usr/bin/env python3
"""stdin fuzz entry point for the offline zero-table validator.

Feed mutated JSON bytes from an external corpus fuzzer. Expected validation
errors return normally; unexpected exceptions/assertions remain visible.
Run: python fuzz/sasrl_recovery_stdin.py < corpus-input.json
"""

import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
recovery = importlib.import_module("sasrl_recovery")
reproduction = importlib.import_module("sasrl_reproduce")


def exercise(raw: bytes) -> None:
    for loader in (recovery.ZeroSpectrum.from_bytes, reproduction.spectrum_from_odlyzko):
        exercise_loader(loader, raw)


def exercise_loader(loader, raw: bytes) -> None:
    try:
        spectrum = loader(raw)
    except ValueError:
        return
    assert all(value > 0 for value in spectrum.ordinates)
    assert all(a <= b for a, b in zip(spectrum.ordinates, spectrum.ordinates[1:]))
    assert spectrum.complete_through > 0
    assert len(spectrum.sha256) == 64
    assert spectrum.ordinate_error_bound >= 0
    assert spectrum.model_declaration in ('implicit_zeta_legacy_input',
                                          'explicit_unverified_zeta_declaration')


if __name__ == "__main__":
    exercise(sys.stdin.buffer.read(recovery.MAX_INPUT_BYTES + 1))
