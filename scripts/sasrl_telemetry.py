#!/usr/bin/env python3
"""Offline cadence/spectrum eligibility checks for decoded QUIC gauge captures.

No missing sample is reconstructed. Input provenance and authentication remain
the producer's responsibility; output never authenticates data or audit events.
"""

from __future__ import annotations

import argparse
import cmath
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path

from sasrl_recovery import finite_number, unique_object

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_SAMPLES = 4096
SEQUENCE_MODULUS = 1 << 32


def bounded_integer(value, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [0, {maximum}]")
    return value


def identifier(value, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 1024:
        raise ValueError(f"{name} must be a nonempty string of at most 1024 characters")
    return value


@dataclass(frozen=True)
class GaugeCapture:
    source: str
    connection_id: str
    metric: str
    expected_interval_ms: int
    sequences: tuple[int, ...]
    timestamps_ms: tuple[int, ...]
    values: tuple[float, ...]
    sha256: str

    def __post_init__(self) -> None:
        if any(not isinstance(vector, tuple)
               for vector in (self.sequences, self.timestamps_ms, self.values)):
            raise ValueError("capture vectors must be immutable tuples")
        identifier(self.source, "source")
        identifier(self.connection_id, "connection_id")
        identifier(self.metric, "metric")
        interval = bounded_integer(self.expected_interval_ms, "expected_interval_ms", 86400000)
        if not interval:
            raise ValueError("expected interval must be positive")
        if not 2 <= len(self.values) <= MAX_SAMPLES:
            raise ValueError("capture requires 2..4096 records")
        if len(self.sequences) != len(self.values) or len(self.timestamps_ms) != len(self.values):
            raise ValueError("sample vectors must have equal lengths")
        for sequence, timestamp, value in zip(self.sequences, self.timestamps_ms, self.values):
            bounded_integer(sequence, "sequence", SEQUENCE_MODULUS - 1)
            bounded_integer(timestamp, "timestamp_ms", (1 << 64) - 1)
            finite_number(value, "gauge value")

    @classmethod
    def from_bytes(cls, raw: bytes) -> GaugeCapture:
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("capture exceeds the input byte budget")
        try:
            data = json.loads(raw, object_pairs_hook=unique_object)
        except (RecursionError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("capture is not bounded valid JSON") from error
        if not isinstance(data, dict):
            raise ValueError("capture must be an object")
        source = identifier(data.get("source"), "source")
        connection = identifier(data.get("connection_id"), "connection_id")
        metric = identifier(data.get("metric"), "metric")
        interval = bounded_integer(data.get("expected_interval_ms"), "expected_interval_ms", 86400000)
        if not interval:
            raise ValueError("expected interval must be positive")
        rows = data.get("records")
        if not isinstance(rows, list) or not 2 <= len(rows) <= MAX_SAMPLES:
            raise ValueError("capture requires 2..4096 records")
        sequences, timestamps, values = [], [], []
        for record in rows:
            if not isinstance(record, dict) or record.get("connection_id") != connection:
                raise ValueError("mixed or missing connection context")
            frame = record.get("frame")
            if not isinstance(frame, dict):
                raise ValueError("record must contain a decoded frame")
            version = bounded_integer(frame.get("version"), "version", 255)
            channel = bounded_integer(frame.get("channel"), "channel", 255)
            if version != 1 or channel != 0:
                raise ValueError("only version-1 telemetry-channel frames are supported")
            sequence = bounded_integer(frame.get("sequence"), "sequence", SEQUENCE_MODULUS - 1)
            timestamp = bounded_integer(frame.get("timestamp_ms"), "timestamp_ms", (1 << 64) - 1)
            payload = frame.get("payload")
            if not isinstance(payload, dict) or set(payload) != {"otel"}:
                raise ValueError("expected a telemetry payload")
            otel = payload["otel"]
            if not isinstance(otel, dict):
                raise ValueError("expected telemetry sample vectors")
            gauges = otel.get("gauges")
            if not isinstance(gauges, list) or len(gauges) > 64:
                raise ValueError("expected at most 64 gauges")
            selected = None
            names = set()
            for gauge in gauges:
                if not isinstance(gauge, dict):
                    raise ValueError("gauge must be an object")
                name = identifier(gauge.get("name"), "gauge name")
                if name in names:
                    raise ValueError("duplicate gauge name")
                names.add(name)
                value = finite_number(gauge.get("value"), "gauge value")
                if name == metric:
                    selected = value
            if selected is None:
                raise ValueError("selected gauge must be present in every frame")
            sequences.append(sequence)
            timestamps.append(timestamp)
            values.append(selected)
        return cls(source, connection, metric, interval, tuple(sequences), tuple(timestamps),
                   tuple(values), hashlib.sha256(raw).hexdigest())

    @classmethod
    def load(cls, path: Path) -> GaugeCapture:
        with path.open("rb") as handle:
            return cls.from_bytes(handle.read(MAX_INPUT_BYTES + 1))


def real_power_spectrum(values: tuple[float, ...], sample_rate_hz: float) -> dict:
    """Complete one-sided FFT with DC/Nyquist and Parseval accounting."""
    count = len(values)
    if not 2 <= count <= MAX_SAMPLES or count & (count - 1):
        raise ValueError("FFT requires a power-of-two sample count in [2, 4096]")
    rate = finite_number(sample_rate_hz, "sample rate")
    if rate <= 0:
        raise ValueError("sample rate must be positive")
    values = tuple(finite_number(value, "FFT sample") for value in values)
    if any(abs(value) > 1e100 for value in values):
        raise ValueError("FFT amplitude exceeds the safe numeric range")
    bits = count.bit_length() - 1
    transformed = [0j] * count
    for index, value in enumerate(values):
        reversed_index = int(f"{index:0{bits}b}"[::-1], 2)
        transformed[reversed_index] = complex(value)
    width = 2
    while width <= count:
        for start in range(0, count, width):
            for index in range(width // 2):
                root = cmath.exp(-2j * math.pi * index / width)
                lower = root * transformed[start + index + width // 2]
                upper = transformed[start + index]
                transformed[start + index] = upper + lower
                transformed[start + index + width // 2] = upper - lower
        width *= 2
    powers = tuple(abs(value) ** 2 for value in transformed[:count // 2 + 1])
    energy = math.fsum(value * value for value in values)
    spectral_energy = (powers[0] + powers[-1] + 2 * math.fsum(powers[1:-1])) / count
    return {"normalization": "unnormalized_dft_squared_magnitude",
            "sample_rate_hz": rate, "nyquist_hz": rate / 2,
            "time_domain_energy": energy, "spectral_energy": spectral_energy,
            "parseval_absolute_discrepancy": abs(energy - spectral_energy),
            "bins": [{"frequency_hz": index * rate / count, "power": power}
                     for index, power in enumerate(powers)]}


def analyze(capture: GaugeCapture, tolerance_ms: int = 0, spectrum: bool = False,
            conditioning_frequencies=None) -> dict:
    tolerance_ms = bounded_integer(tolerance_ms, "tolerance_ms", 86400000)
    if tolerance_ms >= capture.expected_interval_ms:
        raise ValueError("tolerance must be smaller than one expected sample interval")
    lost = 0
    duplicates = 0
    reordered = 0
    clock_nonforward = 0
    max_jitter = 0
    max_phase_error = 0
    offset = 0
    for index in range(1, len(capture.values)):
        delta = (capture.sequences[index] - capture.sequences[index - 1]) % SEQUENCE_MODULUS
        elapsed = capture.timestamps_ms[index] - capture.timestamps_ms[index - 1]
        clock_nonforward += elapsed <= 0
        if delta == 0:
            duplicates += 1
        elif delta >= SEQUENCE_MODULUS // 2:
            reordered += 1
        else:
            lost += delta - 1
            offset += delta
            max_jitter = max(max_jitter, abs(elapsed - delta * capture.expected_interval_ms))
            phase = capture.timestamps_ms[index] - capture.timestamps_ms[0]
            max_phase_error = max(max_phase_error, abs(phase - offset * capture.expected_interval_ms))
    continuous = not (lost or duplicates or reordered or clock_nonforward)
    lattice = continuous and max_phase_error == 0
    rate = 1000 / capture.expected_interval_ms
    reasons = []
    if not continuous:
        reasons.append("sequence gaps, duplicates, reordering/reset or nonforward clock")
    if max_phase_error:
        reasons.append("timestamps do not lie on the exact declared uniform lattice")
    if len(capture.values) & (len(capture.values) - 1):
        reasons.append("sample count is not a power of two")
    if any(abs(value) > 1e100 for value in capture.values):
        reasons.append("gauge amplitude exceeds the safe FFT numeric range")
    result = {"source": capture.source, "input_sha256": capture.sha256,
              "metric": capture.metric, "samples": len(capture.values),
              "expected_interval_ms": capture.expected_interval_ms,
              "sample_rate_hz": rate, "nyquist_hz": rate / 2,
              "missing_sequence_slots": lost, "duplicate_sequences": duplicates,
              "reordered_or_reset_sequences": reordered, "nonforward_clock_steps": clock_nonforward,
              "max_interval_error_ms": max_jitter, "max_lattice_phase_error_ms": max_phase_error,
              "continuous": continuous, "exact_uniform_lattice": lattice,
              "cadence_within_tolerance": continuous and max(max_jitter, max_phase_error) <= tolerance_ms,
              "tolerance_ms": tolerance_ms, "spectrum_eligible": not reasons,
              "spectrum_blocked_reasons": reasons, "reconstructed_samples": 0,
              "authentication_verified_by_tool": False,
              "limitations": ["Provenance and connection context are producer assertions",
                              "Sequence arithmetic assumes fewer than 2^31 slots between observations",
                              "No missing values are filled; clock jitter is not corrected",
                              "Millisecond timestamps can hide finer physical sampling jitter",
                              "Only gauge samples; cumulative counters need reset/rate handling",
                              "FFT powers are diagnostics, not anomaly/authentication decisions"]}
    if spectrum and not reasons:
        result["spectrum"] = real_power_spectrum(capture.values, rate)
    if conditioning_frequencies is not None:
        from sasrl_cluster_conditioning import timestamp_cluster_conditioning
        if type(conditioning_frequencies) not in (list,tuple) or not 2 <= len(conditioning_frequencies) <= 8:
            raise ValueError('conditioning requires a plain vector of 2..8 frequencies')
        conditioning_frequencies=tuple(finite_number(x,'conditioning frequency')
                                      for x in conditioning_frequencies)
        if duplicates or reordered or clock_nonforward:
            result['known_frequency_conditioning']={
                'eligible':False,'blocked_reason':'duplicate/reordered observations or nonforward clock'}
        elif len(capture.values)>512:
            result['known_frequency_conditioning']={
                'eligible':False,'blocked_reason':'observed count exceeds the 512-position matrix budget'}
        else:
            result['known_frequency_conditioning']={
                'eligible':True,'scope':'geometry of observed positions only; gauge values not fitted',
                'missing_slots_reconstructed':0,
                'matrix':timestamp_cluster_conditioning(capture.timestamps_ms,conditioning_frequencies)}
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--tolerance-ms", type=int, default=0)
    parser.add_argument("--spectrum", action="store_true")
    parser.add_argument("--known-frequencies-hz",type=float,nargs='+',
                        help='optional observed-time conditioning; never fills gaps or enables blocked FFT')
    args = parser.parse_args()
    try:
        print(json.dumps(analyze(GaugeCapture.load(args.input), args.tolerance_ms, args.spectrum,
                                 args.known_frequencies_hz),
                         indent=2, allow_nan=False))
    except (ValueError, OSError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
