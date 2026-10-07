"""Analytical controls for the two-column conditioning diagnostic."""

import math
import unittest

from sasrl_conditioning import two_mode_conditioning


class ConditioningTests(unittest.TestCase):
    def test_grid_separated_columns_are_orthogonal(self):
        report = two_mode_conditioning(16, 1, 16)
        self.assertAlmostEqual(report["sigma_min"], 1, places=12)
        self.assertAlmostEqual(report["condition_number"], 1, places=12)

    def test_coincident_and_aliased_modes_are_indistinguishable(self):
        for spacing in (0, 16, 32):
            report = two_mode_conditioning(16, spacing, 16)
            self.assertTrue(report["indistinguishable_modes"])
            self.assertIsNone(report["worst_case_noise_gain"])

    def test_cluster_noise_gain_grows_as_gap_shrinks(self):
        coarse = two_mode_conditioning(32, 0.01, 1)
        fine = two_mode_conditioning(32, 0.001, 1)
        self.assertGreater(fine["worst_case_noise_gain"], coarse["worst_case_noise_gain"])

    def test_tiny_gap_preserves_nonzero_singular_value(self):
        samples = 16
        spacing = 1e-12
        report = two_mode_conditioning(samples, spacing, 1)
        leading_sigma = math.tau * spacing * math.sqrt((samples * samples - 1) / 24)
        self.assertGreater(report["sigma_min"], 0)
        self.assertAlmostEqual(report["sigma_min"] / leading_sigma, 1, places=12)

    def test_stable_identity_agrees_with_direct_gram_eigenvalue(self):
        samples = 32
        spacing = 0.027
        delta = math.tau * spacing
        correlation = abs(sum(complex(math.cos(k * delta), math.sin(k * delta))
                              for k in range(samples)) / samples)
        report = two_mode_conditioning(samples, spacing, 1)
        self.assertAlmostEqual(report["sigma_min"], math.sqrt(1 - correlation), places=12)

    def test_invalid_inputs_fail(self):
        for args in ((1, 1, 1), (4097, 1, 1), (True, 1, 1), (16, -1, 1),
                     (16, 1, 0), (16, math.nan, 1), (16, 1, math.inf),
                     (16, 1e308, 1e-308)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                two_mode_conditioning(*args)


if __name__ == "__main__":
    unittest.main()
