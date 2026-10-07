#!/usr/bin/env python3
"""Reproduce bounded public-signal controls; fixtures are synthetic, not live data."""

import argparse
import copy
import hashlib
import json
import math
from pathlib import Path

from sasrl_pcm import FILTER_DESIGNS, REFINED, PcmRecording, encode_wav, resample
from sasrl_telemetry import GaugeCapture, analyze

TOTAL_EVALUATION_BUDGET = 60_000_000


def telemetry_fixture() -> dict:
    return {"source": "Synthetic decoded QUIC gauge fixture, not a live capture",
            "connection_id": "research-fixture", "metric": "sfu_contexts",
            "expected_interval_ms": 5000,
            "records": [{"connection_id": "research-fixture",
                         "frame": {"version": 1, "channel": 0, "sequence": index + 1,
                                   "timestamp_ms": 100000 + index * 5000,
                                   "payload": {"otel": {"counters": [], "histograms": [],
                                                        "gauges": [{"name": "sfu_contexts",
                                                                    "value": 20 + 3 * math.cos(math.tau * 4 * index / 32)}]}}}}
                        for index in range(32)]}


def telemetry_experiments() -> dict:
    uniform = telemetry_fixture()
    jitter = copy.deepcopy(uniform)
    jitter["records"][7]["frame"]["timestamp_ms"] += 2
    loss = copy.deepcopy(uniform)
    del loss["records"][7]
    drift = copy.deepcopy(uniform)
    for index, record in enumerate(drift["records"]):
        record["frame"]["timestamp_ms"] += index
    return {name: analyze(GaugeCapture.from_bytes(json.dumps(data).encode()), 5, True)
            for name, data in [("uniform", uniform), ("jitter", jitter),
                               ("loss", loss), ("drift", drift)]}


def pcm_experiments(design=REFINED) -> dict:
    input_rate, count, margin = 96000, 8192, 256
    frequencies = (1000, 3000, 16000, 20000, 22000, 24000, 26000, 35000, 47000)
    rows = []
    evaluations = 0
    preflight_total = 0
    # Preflight the aggregate run before creating recordings or filtering.
    for rate in (44100, 48000):
        outputs = (count * rate + input_rate - 1) // input_rate
        taps = 2 * math.ceil(design.support / (design.downsample_nyquist_fraction * rate / input_rate)) + 2
        preflight_total += len(frequencies) * outputs * taps
    if preflight_total > TOTAL_EVALUATION_BUDGET:
        raise ValueError("experiment exceeds the aggregate evaluation budget")
    for rate in (44100, 48000):
        for frequency in frequencies:
            source = tuple(0.5 * math.sin(math.tau * frequency * index / input_rate + 0.37)
                           for index in range(count))
            raw, clipped = encode_wav(source, input_rate)
            assert clipped == 0
            recording = PcmRecording.from_bytes(raw)
            actual = tuple(value / 32768 for value in recording.samples)
            output, metadata = resample(actual, input_rate, rate, design)
            output_raw, output_clipped = encode_wav(output, rate)
            input_rms = math.sqrt(math.fsum(value * value for value in actual) / count)
            interior = output[margin:-margin]
            rms = math.sqrt(math.fsum(value * value for value in interior) / len(interior))
            gain = rms / input_rms
            ideal = [0.5 * math.sin(math.tau * frequency * index / rate + 0.37)
                     for index in range(margin, len(output) - margin)]
            error = math.sqrt(math.fsum((a - b) ** 2 for a, b in zip(interior, ideal)) / len(interior))
            evaluations += metadata["evaluations"]
            rows.append({"input_frequency_hz": frequency, "output_rate_hz": rate,
                         "aliased_frequency_hz": abs(math.remainder(frequency, rate)),
                         "input_pcm_sha256": recording.sha256,
                         "output_pcm_sha256": hashlib.sha256(output_raw).hexdigest(),
                         "output_peak_absolute": max(abs(value) for value in output),
                         "clipped_output_samples": output_clipped,
                         "input_rms": input_rms, "interior_output_rms": rms,
                         "observed_rms_gain_db": 20 * math.log10(gain) if gain else None,
                         "interior_error_vs_unfiltered_tone_rms": error,
                         "maximum_l1_gain": metadata["maximum_l1_gain"],
                         "clipped_input_samples": clipped, "filter": metadata})
    return {"synthetic_controls": True, "filter_profile": design.name, "input_rate_hz": input_rate,
            "input_sample_count": count, "output_edge_samples_excluded": margin,
            "evaluations": evaluations, "preflight_evaluations": preflight_total,
            "aggregate_evaluation_budget": TOTAL_EVALUATION_BUDGET, "rows": rows,
            "limitations": ["Discrete tone controls, not a sweep or universal stopband specification",
                            "RMS includes quantization and sample-phase effects",
                            "Excluded edges do not characterize transients or streaming latency",
                            "Above-Nyquist unfiltered reference error is not passband distortion"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--filter-profile", choices=FILTER_DESIGNS, default="refined")
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise ValueError("output already exists; select a new result path")
        result = {"synthetic_controls_only": True, "telemetry": telemetry_experiments(),
                  "pcm": pcm_experiments(FILTER_DESIGNS[args.filter_profile])}
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(result, handle, indent=2, allow_nan=False)
            handle.write("\n")
        print(json.dumps({"pcm_evaluations": result["pcm"]["evaluations"],
                          "telemetry_spectrum_eligible": {name: row["spectrum_eligible"]
                                                          for name, row in result["telemetry"].items()}}))
    except (ValueError, OSError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
