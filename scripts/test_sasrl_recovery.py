"""Deterministic analytical and malformed-input controls for offline research."""

import json
import math
import tempfile
import unittest
from pathlib import Path

from sasrl_recovery import (
    ZeroSpectrum, cardinal_window, finite_number, hard_cutoff, score,
    smooth_step, summarize, von_mangoldt, weighted, weighted_at_resolution,
)
from sasrl_reproduce import spectrum_from_odlyzko, verified_reproduction_spectrum


class RecoveryTests(unittest.TestCase):
    def test_exact_prime_prime_power_and_composite_oracle(self):
        for prime in (2, 3, 23, 97, 997):
            self.assertEqual(von_mangoldt(prime), math.log(prime))
        for power, prime in ((4, 2), (8, 2), (529, 23), (841, 29), (1681, 41)):
            self.assertEqual(von_mangoldt(power), math.log(prime))
        for composite in (6, 12, 30, 77, 999):
            self.assertEqual(von_mangoldt(composite), 0)

    def test_cardinality_and_remote_support(self):
        for center in (3, 10, 101):
            for n in range(1, 2 * center):
                self.assertEqual(cardinal_window(center, float(n)), float(n == center))
            self.assertEqual(cardinal_window(center, center * 0.5), 0)
            self.assertEqual(cardinal_window(center, center * 1.5), 0)

    def test_smooth_step_symmetry_and_no_underflow_at_edges(self):
        for t in (1e-15, 0.01, 0.25, 0.5, 0.75, 1 - 1e-15):
            self.assertAlmostEqual(smooth_step(t) + smooth_step(1 - t), 1)
        self.assertEqual(smooth_step(0), 0)
        self.assertEqual(smooth_step(1), 1)

    def test_quadrature_pole_approaches_one_and_trivial_correction_decays(self):
        # Analytical controls require no fabricated zeta data.
        small = weighted_at_resolution(20, (), 320)
        large = weighted_at_resolution(200, (), 3200)
        self.assertAlmostEqual(large["pole"], 1, places=8)
        self.assertGreater(small["trivial_zero_correction"], large["trivial_zero_correction"])
        self.assertGreater(large["trivial_zero_correction"], 0)

    def test_mellin_quadrature_resolution_agrees(self):
        # An arbitrary frequency tests integration, not arithmetic reconstruction.
        coarse = weighted_at_resolution(20, (7.0,), 320)
        fine = weighted_at_resolution(20, (7.0,), 640)
        self.assertAlmostEqual(coarse["estimate"], fine["estimate"], places=7)

    def test_conjugate_pair_and_pole_in_hard_estimator(self):
        spectrum = ZeroSpectrum((1.0, 1.0, 7.0), 100, "analytical fixture", "fixture")
        actual = hard_cutoff(3, spectrum, edge=1.0)
        self.assertEqual(actual["positive_zero_count"], 2)
        self.assertAlmostEqual(actual["estimate"], 1 - 4 / math.sqrt(3) * math.cos(math.log(3)))
        self.assertEqual(actual["method"], "conjectural_hard_cutoff")

    def test_cutoff_boundary_is_inclusive(self):
        spectrum = ZeroSpectrum((3.0, 3.0001), 10, "fixture", "fixture")
        self.assertEqual(spectrum.through(3.0), (3.0,))

    def test_insufficient_coverage_and_invalid_parameters_fail(self):
        spectrum = ZeroSpectrum((), 10, "analytical empty prefix", "fixture")
        with self.assertRaises(ValueError):
            hard_cutoff(10, spectrum)
        for epsilon in (0, 0.5, math.nan, math.inf):
            with self.assertRaises(ValueError):
                weighted(3, spectrum, epsilon)
        for n in (True, 1, 100001):
            with self.assertRaises(ValueError):
                von_mangoldt(n)
        with self.assertRaises(ValueError):
            weighted_at_resolution(2, (), 32)
        with self.assertRaises(ValueError):
            weighted_at_resolution(20, (), 161)

    def test_weighted_work_budget_is_enforced(self):
        spectrum = ZeroSpectrum((1.0,) * 100_000, 1000, "budget fixture", "fixture")
        with self.assertRaisesRegex(ValueError, "budget"):
            weighted(3, spectrum)

    def test_weighted_grid_memory_and_interval_type_are_bounded(self):
        spectrum = ZeroSpectrum((), 1e9, "analytical fixture", "fixture")
        with self.assertRaisesRegex(ValueError, "memory"):
            weighted(5000, spectrum)
        for intervals in (160.0, True, 131072):
            with self.subTest(intervals=intervals), self.assertRaises(ValueError):
                weighted_at_resolution(20, (), intervals)

    def test_confusion_matrix_and_composites_include_prime_powers(self):
        rows = [score(2, {"estimate": 1.0}), score(3, {"estimate": 0.0}),
                score(4, {"estimate": 0.0}), score(6, {"estimate": 2.0})]
        summary = summarize(rows)
        self.assertEqual([summary[c] for c in ("TP", "TN", "FP", "FN")], [1, 1, 1, 1])
        self.assertFalse(rows[2]["is_prime"])

    def test_load_requires_source_and_valid_ordered_finite_ordinates(self):
        valid = {"source": "fixture", "complete_through": 10, "ordinates": [1, 1, 2]}
        invalid = [None, {**valid, "source": " "}, {**valid, "complete_through": 0},
                   {**valid, "ordinates": [2, 1]}, {**valid, "ordinates": [0]},
                   {**valid, "ordinates": [True]}, {**valid, "ordinates": [math.nan]},
                   {**valid, "ordinates": "1"}, {**valid, "complete_through": "10"}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "zeros.json"
            path.write_text(json.dumps(valid), encoding="utf-8")
            loaded = ZeroSpectrum.load(path)
            self.assertEqual(loaded.ordinates, (1, 1, 2))
            self.assertEqual(len(loaded.sha256), 64)
            for value in invalid:
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.subTest(value=value), self.assertRaises(ValueError):
                    ZeroSpectrum.load(path)

    def test_nonfinite_and_boolean_inputs_are_rejected(self):
        for value in (math.nan, math.inf, True, "2", None, 10 ** 1000):
            with self.subTest(value=str(value)[:20]), self.assertRaises(ValueError):
                finite_number(value, "test")

    def test_duplicate_metadata_and_deep_json_are_rejected(self):
        for raw in (b'{"source":"a","source":"b"}', b'[' * 2000 + b']' * 2000):
            with self.assertRaises(ValueError):
                ZeroSpectrum.from_bytes(raw)

    def test_cutoff_rejects_ordinate_uncertainty_at_the_edge(self):
        spectrum = ZeroSpectrum((3.0,), 10, "fixture", "fixture", 0.01)
        with self.assertRaisesRegex(ValueError, "uncertainty"):
            spectrum.through(3.005)
        self.assertEqual(spectrum.through(3.02), (3.0,))
        estimate = hard_cutoff(3, spectrum)
        self.assertGreater(estimate["ordinate_sensitivity_bound"], 0)

    def test_deterministic_byte_mutations_do_not_escape_validation(self):
        seed = b'{"source":"fixture","complete_through":10,"ordinates":[1,2]}'
        # Every location, structural bytes, control bytes and malformed UTF-8.
        # This is a regression corpus sweep, not a substitute for a fuzz campaign.
        for index in range(len(seed)):
            for replacement in (0, 34, 44, 58, 91, 93, 123, 125, 255):
                raw = seed[:index] + bytes([replacement]) + seed[index + 1:]
                try:
                    spectrum = ZeroSpectrum.from_bytes(raw)
                except ValueError:
                    continue
                self.assertGreater(spectrum.complete_through, 0)
                self.assertEqual(tuple(sorted(spectrum.ordinates)), spectrum.ordinates)

    def test_raw_table_requires_finite_positive_ordered_ascii_ordinates(self):
        spectrum = spectrum_from_odlyzko(b'14.134725142\n21.022039639\n')
        self.assertEqual(spectrum.complete_through, 21)
        for raw in (b'', b'inf\n', b'nan\n', b'2\n1\n', b'-1\n', b'\xff', b'bad\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                spectrum_from_odlyzko(raw)

    def test_manuscript_reproduction_rejects_truncated_or_modified_source(self):
        with self.assertRaisesRegex(ValueError, "pinned"):
            verified_reproduction_spectrum(b'14.134725142\n21.022039639\n')


if __name__ == "__main__":
    unittest.main()
