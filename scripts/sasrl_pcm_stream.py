"""Experimental bounded-state PCM streaming, using the offline filter convention.

The caller must authenticate frames and enforce source/session identity before
push. Sample offsets detect continuity errors, not authenticity. No missing
samples are inferred, and this Python laboratory makes no real-time guarantee.
"""

from __future__ import annotations

import math

from sasrl_pcm import (MAX_EVALUATIONS, REFINED, FilterDesign, phase_kernel,
                       reflected_index, validate_design, validate_rate)
from sasrl_recovery import finite_number

MAX_BLOCK_SAMPLES = 4096
MAX_CACHED_TAPS = 250_000
MAX_SAMPLE_INDEX = 2**63 - 1


class StreamingPcm:
    """One continuous mono normalized-PCM stream, with caller-owned output.

    There is no reset/recovery operation: any invalid push/finish fails the
    stream permanently. Create a new instance only for an explicit new segment.
    Returned prefix samples remain prefix evidence, not proof of later continuity.
    """

    def __init__(self, input_rate: int, output_rate: int,
                 design: FilterDesign = REFINED):
        validate_rate(input_rate)
        validate_rate(output_rate)
        validate_design(design)
        self.input_rate = input_rate
        self.output_rate = output_rate
        self.design = design
        self.cutoff = (design.downsample_nyquist_fraction * output_rate / input_rate
                       if output_rate < input_rate else 1.0)
        self.radius = 0 if input_rate == output_rate else math.ceil(design.support / self.cutoff)
        self.max_taps = 1 if self.radius == 0 else 2 * self.radius + 2
        self.phase_count = output_rate // math.gcd(input_rate, output_rate)
        if self.phase_count * self.max_taps > MAX_CACHED_TAPS:
            raise ValueError("filter exceeds the phase-cache budget")
        self.buffer_limit = 2 * self.radius + MAX_BLOCK_SAMPLES + 2
        self.state = "open"
        self.input_samples = 0
        self.output_samples = 0
        self.evaluations = 0
        self.maximum_l1_gain = 0.0
        self._buffer = []
        self._start = 0
        self._kernels = {}
        self._cached_taps = 0
        self._peak_buffer = 0
        self._largest_preflight = 0

    def _require_open(self):
        if self.state != "open":
            raise ValueError(f"stream is {self.state}")

    def _output_count(self, count):
        result = (count * self.output_rate + self.input_rate - 1) // self.input_rate
        if result > MAX_SAMPLE_INDEX:
            raise ValueError("output sample clock exceeds the integer budget")
        return result

    def _preflight(self, final_count):
        # Include pending lookahead and all as-yet-unbuilt phase kernels. This
        # bounds both filtering and kernel construction before input mutation.
        outputs = self._output_count(final_count) - self.output_samples
        cost = (outputs + self.phase_count - len(self._kernels)) * self.max_taps
        if cost > MAX_EVALUATIONS:
            raise ValueError("stream call exceeds the evaluation budget; use smaller blocks")
        self._largest_preflight = max(self._largest_preflight, cost)

    def _kernel(self, remainder):
        if remainder not in self._kernels:
            kernel = (((0, 1.0),), 1.0) if self.radius == 0 else phase_kernel(
                remainder / self.output_rate, self.cutoff, self.design)
            taps, gain = kernel
            if self._cached_taps + len(taps) > MAX_CACHED_TAPS:
                raise ValueError("stream phase-cache budget exceeded")
            self._kernels[remainder] = kernel
            self._cached_taps += len(taps)
            self.maximum_l1_gain = max(self.maximum_l1_gain, gain)
        return self._kernels[remainder][0]

    def _sample(self, index, eof):
        source = reflected_index(index, self.input_samples) if eof else abs(index)
        offset = source - self._start
        if not 0 <= offset < len(self._buffer):
            raise ValueError("stream history does not cover the required boundary sample")
        return self._buffer[offset]

    def _emit(self, eof):
        output = []
        if self.input_samples == 0:
            return output
        final_outputs = self._output_count(self.input_samples)
        while self.output_samples < final_outputs:
            base, remainder = divmod(self.output_samples * self.input_rate, self.output_rate)
            taps = self._kernel(remainder)
            # Before EOF, negative indices use only the known left reflection.
            # Never reflect against an unknown right boundary or unknown length.
            needed = max(base + taps[-1][0], -(base + taps[0][0]))
            if not eof and needed >= self.input_samples:
                break
            first, last = base + taps[0][0], base + taps[-1][0]
            if self._start <= first and last < self._start + len(self._buffer):
                # Ordered taps lie entirely in retained history. Check the
                # interval once, keeping exactly the reference product order.
                buffer, relative_base = self._buffer, base - self._start
                value = math.fsum(weight * buffer[relative_base + offset]
                                  for offset, weight in taps)
            else:
                value = math.fsum(weight * self._sample(base + offset, eof)
                                  for offset, weight in taps)
            if not math.isfinite(value):
                raise ValueError("stream produced a nonfinite sample")
            output.append(value)
            self.evaluations += len(taps)
            self.output_samples += 1
        return output

    def _trim(self):
        next_base = self.output_samples * self.input_rate // self.output_rate
        # Keep both future convolution history and enough end context for EOF
        # reflection. Short streams retain the whole source for repeated folds.
        first_needed = max(0, min(next_base - self.radius,
                                  self.input_samples - 2 * self.radius - 2))
        discard = first_needed - self._start
        if discard > 0:
            del self._buffer[:discard]
            self._start = first_needed

    def push(self, samples, start_sample: int) -> list[float]:
        self._require_open()
        try:
            if type(start_sample) is not int or not 0 <= start_sample <= MAX_SAMPLE_INDEX:
                raise ValueError("start_sample must be a bounded integer")
            if start_sample != self.input_samples:
                raise ValueError("stream has a gap, duplicate or reordered input block")
            if type(samples) not in (tuple, list):
                raise ValueError("stream block must be a plain tuple/list")
            block = tuple(samples[:MAX_BLOCK_SAMPLES + 1])
            if not 1 <= len(block) <= MAX_BLOCK_SAMPLES:
                raise ValueError("stream block must contain 1..4096 samples")
            final_count = self.input_samples + len(block)
            if final_count > MAX_SAMPLE_INDEX:
                raise ValueError("input sample clock exceeds the integer budget")
            self._preflight(final_count)
            if any(type(value) not in (int, float) for value in block):
                raise ValueError("PCM samples must be plain finite numbers")
            values = tuple(finite_number(value, "PCM sample") for value in block)
            if any(abs(value) > 1.0 for value in values):
                raise ValueError("normalized PCM samples must be within [-1, 1]")
            if len(self._buffer) + len(values) > self.buffer_limit:
                raise ValueError("stream history budget exceeded")
            self._buffer.extend(values)
            self._peak_buffer = max(self._peak_buffer, len(self._buffer))
            self.input_samples = final_count
            output = self._emit(False)
            self._trim()
            return output
        except ValueError:
            self.state = "failed"
            raise

    def finish(self, expected_total_samples: int) -> list[float]:
        self._require_open()
        try:
            if type(expected_total_samples) is not int or not 0 <= expected_total_samples <= MAX_SAMPLE_INDEX:
                raise ValueError("EOF must declare a bounded integer total sample count")
            if expected_total_samples != self.input_samples:
                raise ValueError("EOF total does not match received samples; missing tail or inconsistent source")
            if self.input_samples < 2:
                raise ValueError("stream must contain at least two samples")
            self._preflight(self.input_samples)
            output = self._emit(True)
            self.state = "finished"
            self._buffer.clear()
            self._kernels.clear()
            return output
        except ValueError:
            self.state = "failed"
            raise

    def summary(self) -> dict:
        return {"experimental": True, "state": self.state,
                "input_rate_hz": self.input_rate, "output_rate_hz": self.output_rate,
                "filter_profile": self.design.name, "input_samples": self.input_samples,
                "output_samples": self.output_samples, "evaluations": self.evaluations,
                "maximum_l1_gain": self.maximum_l1_gain,
                "maximum_preflight_evaluations_per_call": self._largest_preflight,
                "per_call_evaluation_limit": MAX_EVALUATIONS,
                "maximum_input_block_samples": MAX_BLOCK_SAMPLES,
                "retained_history_samples": len(self._buffer),
                "peak_history_samples": self._peak_buffer, "history_limit_samples": self.buffer_limit,
                "cached_taps_built": self._cached_taps, "cached_tap_limit": MAX_CACHED_TAPS,
                "retained_phase_kernels": len(self._kernels), "minimum_complete_stream_samples": 2,
                "lookahead_upper_bound_input_samples": self.radius,
                "lookahead_upper_bound_seconds": self.radius / self.input_rate,
                "sample_clock": "integer rational phases; continuous zero-based sample offsets",
                "boundary": "whole_sample_reflection; right reflection only after explicit count-checked EOF",
                "limitations": ["Caller must authenticate and isolate source frames",
                                "Input offsets cannot detect loss hidden by a producer",
                                "No real-time throughput or transport backpressure guarantee",
                                "Already emitted prefixes do not certify later stream continuity"]}


def main() -> None:
    import argparse
    import hashlib
    import json
    from pathlib import Path
    from sasrl_pcm import FILTER_DESIGNS, MAX_SAMPLES, PcmRecording, encode_wav

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rate", type=int, required=True)
    parser.add_argument("--block-samples", type=int, default=960)
    parser.add_argument("--filter-profile", choices=FILTER_DESIGNS, default="refined")
    args = parser.parse_args()
    try:
        if not 1 <= args.block_samples <= MAX_BLOCK_SAMPLES:
            raise ValueError("block-samples must be in 1..4096")
        if args.input.resolve() == args.output.resolve():
            raise ValueError("output must not replace the source recording")
        source = PcmRecording.load(args.input)
        engine = StreamingPcm(source.sample_rate_hz, args.rate, FILTER_DESIGNS[args.filter_profile])
        count = engine._output_count(len(source.samples))
        if not 2 <= count <= MAX_SAMPLES:
            raise ValueError("complete WAV output exceeds the sample budget")
        # Unlike the unbounded-duration stream API, this file export has one
        # aggregate work/output budget and holds the bounded output for encoding.
        aggregate = (count + engine.phase_count) * engine.max_taps
        if aggregate > MAX_EVALUATIONS:
            raise ValueError("WAV export exceeds the aggregate evaluation budget")
        output = []
        for start in range(0, len(source.samples), args.block_samples):
            block = tuple(value / 32768 for value in source.samples[start:start + args.block_samples])
            output.extend(engine.push(block, start))
        output.extend(engine.finish(len(source.samples)))
        raw, clipped = encode_wav(output, args.rate)
        with args.output.open("xb") as handle:
            handle.write(raw)
        report = engine.summary()
        report.update(input_sha256=source.sha256, output_sha256=hashlib.sha256(raw).hexdigest(),
                      clipped_output_samples=clipped, aggregate_preflight_evaluations=aggregate,
                      source_kind="offline WAV chunk experiment; no source authentication",
                      quantization="nearest_even_then_s16_saturation")
        print(json.dumps(report, indent=2, allow_nan=False))
    except (ValueError, OSError) as error:
        parser.exit(2, f"error: {error}\n")


if __name__ == "__main__":
    main()
