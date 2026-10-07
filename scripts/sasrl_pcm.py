#!/usr/bin/env python3
"""Bounded offline PCM sinc-Gaussian laboratory, separate from QUIC transport.

Only mono signed 16-bit little-endian PCM WAV is supported. This tool cannot
authenticate recordings or detect transport loss hidden by their producer.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import struct

from sasrl_recovery import finite_number, smooth_step

RATES = (8000, 16000, 24000, 32000, 44100, 48000, 96000, 192000)
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_SAMPLES = 192000
MAX_EVALUATIONS = 10_000_000
MAX_L1_GAIN = 4.0


@dataclass(frozen=True)
class FilterDesign:
    name: str
    sigma: float
    support: float
    taper_start: float
    downsample_nyquist_fraction: float


BASELINE = FilterDesign("baseline", 8.0, 40.0, 32.0, 0.9)
REFINED = FilterDesign("refined", 32.0, 160.0, 128.0, 0.95)
FILTER_DESIGNS = {design.name: design for design in (BASELINE, REFINED)}


def validate_design(design: FilterDesign) -> None:
    if design is not BASELINE and design is not REFINED:
        raise ValueError("only the bounded baseline/refined filter designs are supported")


def validate_rate(rate: int) -> None:
    if isinstance(rate, bool) or not isinstance(rate, int) or rate not in RATES:
        raise ValueError(f"sample rate must be one of {RATES}")


@dataclass(frozen=True)
class PcmRecording:
    sample_rate_hz: int
    samples: tuple[int, ...]
    sha256: str

    @classmethod
    def from_bytes(cls, raw: bytes) -> PcmRecording:
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("WAV exceeds the input byte budget")
        if len(raw) < 12 or raw[:4] != b"RIFF" or raw[8:12] != b"WAVE":
            raise ValueError("expected a RIFF WAVE recording")
        if struct.unpack_from("<I", raw, 4)[0] + 8 != len(raw):
            raise ValueError("WAV RIFF length must match exactly")
        chunks = {}
        position = 12
        chunk_count = 0
        while position < len(raw):
            if len(raw) - position < 8:
                raise ValueError("incomplete WAV chunk header")
            kind, size = struct.unpack_from("<4sI", raw, position)
            end = position + 8 + size
            padded_end = end + size % 2
            if padded_end > len(raw):
                raise ValueError("truncated WAV chunk")
            chunk_count += 1
            if chunk_count > 32:
                raise ValueError("WAV exceeds the chunk budget")
            if kind in (b"fmt ", b"data"):
                if kind in chunks:
                    raise ValueError("duplicate WAV format/data chunk")
                chunks[kind] = raw[position + 8:end]
            position = padded_end
        fmt, data = chunks.get(b"fmt "), chunks.get(b"data")
        if fmt is None or data is None or len(fmt) not in (16, 18):
            raise ValueError("expected PCM format and data chunks")
        if len(fmt) == 18 and fmt[16:] != b"\x00\x00":
            raise ValueError("extended PCM format is unsupported")
        encoding, channels, rate, byte_rate, alignment, bits = struct.unpack_from("<HHIIHH", fmt)
        validate_rate(rate)
        if (encoding, channels, alignment, bits, byte_rate) != (1, 1, 2, 16, rate * 2):
            raise ValueError("expected consistent mono PCM S16LE format")
        if len(data) % 2 or not 2 <= len(data) // 2 <= MAX_SAMPLES:
            raise ValueError("WAV must contain 2..192000 complete samples")
        samples = tuple(value[0] for value in struct.iter_unpack("<h", data))
        return cls(rate, samples, hashlib.sha256(raw).hexdigest())

    @classmethod
    def load(cls, path: Path) -> PcmRecording:
        with path.open("rb") as handle:
            return cls.from_bytes(handle.read(MAX_INPUT_BYTES + 1))


def sinc(value: float) -> float:
    value = finite_number(value, "sinc argument")
    if value == 0:
        return 1.0
    if value.is_integer():
        return 0.0
    return math.sin(math.pi * value) / (math.pi * value)


def phase_kernel(fraction: float, cutoff: float, design: FilterDesign = REFINED
                 ) -> tuple[tuple[tuple[int, float], ...], float]:
    """Normalized finite low-pass kernel; cutoff is relative to input Nyquist."""
    fraction = finite_number(fraction, "fraction")
    cutoff = finite_number(cutoff, "cutoff")
    validate_design(design)
    if not 0 <= fraction < 1 or not design.downsample_nyquist_fraction * RATES[0] / RATES[-1] <= cutoff <= 1:
        raise ValueError("filter phase/cutoff exceeds the supported range")
    radius = design.support / cutoff
    taps = []
    for offset in range(math.ceil(fraction - radius), math.floor(fraction + radius) + 1):
        distance = cutoff * (offset - fraction)
        taper = 1.0 - smooth_step((abs(distance) - design.taper_start) / (design.support - design.taper_start))
        weight = cutoff * sinc(distance) * math.exp(-0.5 * (distance / design.sigma) ** 2) * taper
        if weight:
            taps.append((offset, weight))
    total = math.fsum(weight for _, weight in taps)
    if not math.isfinite(total) or abs(total) < 0.5:
        raise ValueError("filter normalization is ill-conditioned")
    taps = tuple((offset, weight / total) for offset, weight in taps)
    gain = math.fsum(abs(weight) for _, weight in taps)
    if gain > MAX_L1_GAIN:
        raise ValueError("filter exceeds the declared worst-case amplitude gain")
    return taps, gain


def reflected_index(index: int, count: int) -> int:
    """Whole-sample reflection; an explicit offline boundary convention."""
    period = 2 * (count - 1)
    folded = index % period
    return folded if folded < count else period - folded


def resample(samples, input_rate: int, output_rate: int, design: FilterDesign = REFINED
             ) -> tuple[list[float], dict]:
    validate_rate(input_rate)
    validate_rate(output_rate)
    validate_design(design)
    if not isinstance(samples, (list, tuple)) or not 2 <= len(samples) <= MAX_SAMPLES:
        raise ValueError("sample array must contain 2..192000 values")
    count = len(samples)
    output_count = (count * output_rate + input_rate - 1) // input_rate
    if output_count > MAX_SAMPLES:
        raise ValueError("output exceeds the sample budget")
    cutoff = design.downsample_nyquist_fraction * output_rate / input_rate if output_rate < input_rate else 1.0
    max_taps = 1 if output_rate == input_rate else 2 * math.ceil(design.support / cutoff) + 2
    preflight = output_count * max_taps
    if preflight > MAX_EVALUATIONS:
        raise ValueError("resampling exceeds the evaluation budget")
    values = tuple(finite_number(value, "PCM sample") for value in samples)
    if any(abs(value) > 1.0 for value in values):
        raise ValueError("normalized PCM samples must be within [-1, 1]")
    kernels = {}
    output = []
    evaluations = 0
    max_gain = 0.0
    for index in range(output_count):
        base, remainder = divmod(index * input_rate, output_rate)
        if remainder not in kernels:
            kernels[remainder] = phase_kernel(remainder / output_rate, cutoff, design)
        taps, gain = kernels[remainder]
        max_gain = max(max_gain, gain)
        evaluations += len(taps)
        value = math.fsum(weight * values[reflected_index(base + offset, count)]
                          for offset, weight in taps)
        if not math.isfinite(value):
            raise ValueError("resampling produced a nonfinite sample")
        output.append(value)
    return output, {"method": "normalized_compact_sinc_gaussian", "experimental": True,
                    "input_rate_hz": input_rate, "output_rate_hz": output_rate,
                    "input_samples": count, "output_samples": output_count,
                    "cutoff_relative_to_input_nyquist": cutoff,
                    "nominal_cutoff_hz": cutoff * input_rate / 2,
                    "boundary": "whole_sample_reflection", "filter_profile": design.name,
                    "sigma_lattice_units": design.sigma, "support_lattice_units": design.support,
                    "taper_start_lattice_units": design.taper_start, "phase_kernels": len(kernels),
                    "support_radius_input_samples": math.ceil(design.support / cutoff),
                    "required_streaming_lookahead_seconds": design.support / cutoff / input_rate,
                    "evaluations": evaluations, "preflight_evaluations": preflight,
                    "maximum_l1_gain": max_gain, "declared_l1_gain_limit": MAX_L1_GAIN,
                    "input_duration_seconds": count / input_rate,
                    "output_duration_seconds": output_count / output_rate,
                    "aligned_input_lattice_samples_exact": output_rate >= input_rate,
                    "all_input_lattice_positions_present": output_rate % input_rate == 0,
                    "limitations": ["Offline measured experiment, not a certified DSP specification",
                                    "Reflection changes edge transients; independent frames need streaming context",
                                    "Finite transition band; cutoff is not a brick-wall guarantee",
                                    "Authenticate and check continuity before converting source frames",
                                    "Cannot detect transport loss hidden by a WAV producer"]}


def encode_wav(samples, rate: int) -> tuple[bytes, int]:
    validate_rate(rate)
    if not isinstance(samples, (list, tuple)) or not 2 <= len(samples) <= MAX_SAMPLES:
        raise ValueError("output WAV exceeds the sample budget")
    pcm = bytearray()
    clipped = 0
    for value in samples:
        value = finite_number(value, "output sample")
        if abs(value) > MAX_L1_GAIN:
            raise ValueError("output exceeds the declared amplitude gain")
        integer = round(value * 32768)
        saturated = min(32767, max(-32768, integer))
        clipped += integer != saturated
        pcm.extend(struct.pack("<h", saturated))
    fmt = struct.pack("<HHIIHH", 1, 1, rate, rate * 2, 2, 16)
    raw = b"WAVEfmt " + struct.pack("<I", len(fmt)) + fmt + b"data" + struct.pack("<I", len(pcm)) + pcm
    return b"RIFF" + struct.pack("<I", len(raw)) + raw, clipped


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rate", type=int, required=True)
    parser.add_argument("--filter-profile", choices=FILTER_DESIGNS, default="refined")
    args = parser.parse_args()
    try:
        if args.output.resolve() == args.input.resolve():
            raise ValueError("output must not replace the source recording")
        source = PcmRecording.load(args.input)
        output, report = resample(tuple(value / 32768 for value in source.samples),
                                  source.sample_rate_hz, args.rate, FILTER_DESIGNS[args.filter_profile])
        raw, clipped = encode_wav(output, args.rate)
        with args.output.open("xb") as handle:
            handle.write(raw)
        report.update(input_sha256=source.sha256, output_sha256=hashlib.sha256(raw).hexdigest(),
                      clipped_output_samples=clipped, quantization="nearest_even_then_s16_saturation")
        print(json.dumps(report, indent=2, allow_nan=False))
    except (ValueError, OSError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
