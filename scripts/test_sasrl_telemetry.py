import cmath
import copy
import json
import math
import unittest

from sasrl_telemetry import GaugeCapture, MAX_INPUT_BYTES, analyze, real_power_spectrum


def capture_data(count=16):
    return {"source": "synthetic controlled decoded-frame fixture; not a live capture",
            "connection_id": "fixture-connection", "metric": "sfu_contexts",
            "expected_interval_ms": 5000,
            "records": [{"connection_id": "fixture-connection",
                         "frame": {"version": 1, "channel": 0, "sequence": index + 1,
                                   "timestamp_ms": 100000 + index * 5000,
                                   "payload": {"otel": {"counters": [], "histograms": [],
                                                        "gauges": [{"name": "sfu_contexts",
                                                                    "value": math.cos(math.tau * 3 * index / count)}]}}}}
                        for index in range(count)]}


def capture(data):
    return GaugeCapture.from_bytes(json.dumps(data).encode())


class TelemetryTests(unittest.TestCase):
    def test_exact_server_cadence_is_eligible_and_full_band_is_present(self):
        result = analyze(capture(capture_data()), spectrum=True)
        self.assertTrue(result["exact_uniform_lattice"])
        self.assertTrue(result["spectrum_eligible"])
        self.assertEqual(result["nyquist_hz"], 0.1)
        bins = result["spectrum"]["bins"]
        self.assertEqual(len(bins), 9)
        self.assertEqual(bins[0]["frequency_hz"], 0)
        self.assertEqual(bins[-1]["frequency_hz"], 0.1)
        self.assertAlmostEqual(bins[3]["power"], 64)
        self.assertFalse(result["authentication_verified_by_tool"])

    def test_fft_matches_independent_direct_dft_and_parseval(self):
        for count in [2, 8, 32]:
            values = tuple(math.sin(index * 3.41) + index / 100 for index in range(count))
            result = real_power_spectrum(values, 200)
            for bin_index, row in enumerate(result["bins"]):
                direct = sum(value * cmath.exp(-math.tau * 1j * bin_index * index / count)
                             for index, value in enumerate(values))
                self.assertAlmostEqual(row["power"], abs(direct) ** 2, places=10)
            self.assertLess(result["parseval_absolute_discrepancy"], 1e-12)

    def test_dc_nyquist_and_impulse_controls(self):
        dc = real_power_spectrum((1.0,) * 16, 1)
        self.assertEqual(dc["bins"][0]["power"], 256)
        nyquist = real_power_spectrum(tuple((-1.0) ** index for index in range(16)), 1)
        self.assertEqual(nyquist["bins"][-1]["power"], 256)
        impulse = real_power_spectrum((1.0,) + (0.0,) * 15, 1)
        self.assertTrue(all(row["power"] == 1 for row in impulse["bins"]))

    def test_loss_keeps_cadence_diagnostics_but_never_fills_samples(self):
        data = capture_data(17)
        del data["records"][5]
        result = analyze(capture(data), spectrum=True)
        self.assertEqual(result["missing_sequence_slots"], 1)
        self.assertEqual(result["max_interval_error_ms"], 0)
        self.assertEqual(result["max_lattice_phase_error_ms"], 0)
        self.assertFalse(result["spectrum_eligible"])
        self.assertNotIn("spectrum", result)
        self.assertEqual(result["reconstructed_samples"], 0)

    def test_jitter_within_tolerance_still_blocks_exact_grid_fft(self):
        data = capture_data()
        data["records"][4]["frame"]["timestamp_ms"] += 2
        result = analyze(capture(data), tolerance_ms=5, spectrum=True)
        self.assertTrue(result["cadence_within_tolerance"])
        self.assertEqual(result["max_interval_error_ms"], 2)
        self.assertEqual(result["max_lattice_phase_error_ms"], 2)
        self.assertFalse(result["spectrum_eligible"])
        self.assertNotIn("spectrum", result)

    def test_accumulated_drift_is_not_hidden_by_small_interval_errors(self):
        data = capture_data()
        for index, row in enumerate(data["records"]):
            row["frame"]["timestamp_ms"] += index
        result = analyze(capture(data), tolerance_ms=2)
        self.assertEqual(result["max_interval_error_ms"], 1)
        self.assertEqual(result["max_lattice_phase_error_ms"], 15)
        self.assertFalse(result["cadence_within_tolerance"])

    def test_wrap_is_continuous_duplicates_reordering_and_clock_reset_are_not(self):
        data = capture_data()
        for index, row in enumerate(data["records"]):
            row["frame"]["sequence"] = (2 ** 32 - 3 + index) % 2 ** 32
        self.assertTrue(analyze(capture(data))["spectrum_eligible"])
        for mutation, key in [("duplicate", "duplicate_sequences"),
                              ("reorder", "reordered_or_reset_sequences"),
                              ("clock", "nonforward_clock_steps")]:
            modified = copy.deepcopy(data)
            if mutation == "duplicate":
                modified["records"][5]["frame"]["sequence"] = modified["records"][4]["frame"]["sequence"]
            elif mutation == "reorder":
                modified["records"][4], modified["records"][5] = modified["records"][5], modified["records"][4]
            else:
                modified["records"][5]["frame"]["timestamp_ms"] = 0
            result = analyze(capture(modified))
            self.assertGreater(result[key], 0)
            self.assertFalse(result["spectrum_eligible"])

    def test_non_power_two_and_extreme_values_have_explicit_block_reasons(self):
        self.assertFalse(analyze(capture(capture_data(15)))["spectrum_eligible"])
        data = capture_data()
        data["records"][0]["frame"]["payload"]["otel"]["gauges"][0]["value"] = 1e101
        result = analyze(capture(data), spectrum=True)
        self.assertFalse(result["spectrum_eligible"])
        self.assertNotIn("spectrum", result)
        for values in [(float("nan"), 1), (float("inf"), 1), (1e101, 1), (True, 1), (1, 2, 3)]:
            with self.assertRaises(ValueError):
                real_power_spectrum(values, 1)

    def test_mixed_missing_ambiguous_and_nonfinite_samples_are_rejected(self):
        variants = []
        data = capture_data()
        for field, value in [("connection_id", "other"), ("frame", [])]:
            variant = copy.deepcopy(data)
            variant["records"][3][field] = value
            variants.append(variant)
        for field, value in [("version", True), ("channel", 1), ("sequence", -1),
                             ("timestamp_ms", 1.5), ("payload", {"audit": {}})]:
            variant = copy.deepcopy(data)
            variant["records"][3]["frame"][field] = value
            variants.append(variant)
        for gauges in [[], [{"name": "sfu_contexts", "value": float("nan")}],
                       [{"name": "sfu_contexts", "value": True}],
                       [{"name": "sfu_contexts", "value": 1}] * 2]:
            variant = copy.deepcopy(data)
            variant["records"][3]["frame"]["payload"]["otel"]["gauges"] = gauges
            variants.append(variant)
        for variant in variants:
            with self.assertRaises(ValueError):
                capture(variant)

    def test_duplicate_metadata_byte_nesting_and_size_limits(self):
        raw = json.dumps(capture_data()).encode()
        for invalid in [b'{"source":"a","source":"b"}', b"[" * 1200,
                        b"\xff", b"[]", bytes(MAX_INPUT_BYTES + 1)]:
            with self.assertRaises(ValueError):
                GaugeCapture.from_bytes(invalid)
        for index in range(0, len(raw), 7):
            mutated = bytearray(raw)
            mutated[index] ^= 255
            try:
                source = GaugeCapture.from_bytes(bytes(mutated))
            except ValueError:
                continue
            self.assertGreaterEqual(len(source.values), 2)
            self.assertEqual(analyze(source)["reconstructed_samples"], 0)

    def test_invalid_tolerances_are_rejected(self):
        source = capture(capture_data())
        for value in [True, -1, 5000, float("nan")]:
            with self.assertRaises(ValueError):
                analyze(source, value)


if __name__ == "__main__":
    unittest.main()
