"""Independent public arithmetic controls, with no spectral estimates as oracle."""
import math
import unittest

from sasrl_euler import (CURVES, MAX_EXPONENT, MAX_PRIME, discriminant,
                        frobenius_power, local_reference, point_count, reference_report)


def exhaustive_points(model, prime):
    a1, a2, a3, a4, a6 = model
    return 1 + sum(
        (y*y + a1*x*y + a3*y - x*x*x - a2*x*x - a4*x - a6) % prime == 0
        for x in range(prime) for y in range(prime)
    )


class EulerTests(unittest.TestCase):
    def test_models_labels_and_discriminants(self):
        self.assertEqual(CURVES['11a1'].lmfdb, '11.a2')
        self.assertEqual(discriminant(CURVES['11a1'].coefficients), -11**5)
        self.assertEqual(discriminant(CURVES['37a1'].coefficients), 37)
        self.assertEqual(discriminant((0, 0, 0, -1, 0)), 64)

    def test_all_small_fields_match_independent_exhaustive_equations(self):
        models = [curve.coefficients for curve in CURVES.values()]
        models.extend([(1, 2, 3, 4, 5), (0, 0, 0, -1, 0), (0, 0, 0, 0, 1)])
        for model in models:
            for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41]:
                if discriminant(model) % p:
                    self.assertEqual(point_count(model, p), exhaustive_points(model, p))

    def test_curve37_over_f5_has_8_points_and_negative_trace(self):
        # Enumeration: x=0,1,2,3,4 gives 2,2,2,1,0 affine points.
        row = local_reference(CURVES['37a1'].coefficients, 5)
        self.assertEqual(row['points_over_fp'], 8)
        self.assertEqual(row['a_p'], -2)
        self.assertAlmostEqual(row['unitary_lambda_at_prime_power'], -2*math.log(5)/math.sqrt(5))

    def test_paper_eight_exact_coefficients_are_independently_reproduced(self):
        for label, expected in [('11a1', [-2, -1, 1, -2]), ('37a1', [-2, -3, -2, -1])]:
            actual = [local_reference(CURVES[label].coefficients, p)['a_p']
                      for p in [2, 3, 5, 7]]
            self.assertEqual(actual, expected)

    def test_prime_power_log_coefficients_are_not_dirichlet_coefficients(self):
        # Power sums at k=2 use a_p^2-2p. Series coefficients use a_p^2-p.
        self.assertEqual(frobenius_power(-2, 5, 2), -6)
        self.assertNotEqual(frobenius_power(-2, 5, 2), -1)
        # Independent Newton power-sum binomial formula.
        for trace, p in [(-2, 5), (0, 3), (5, 7), (-1, 2)]:
            for k in range(1, 13):
                expected = sum(
                    (-1)**j * (k*math.comb(k-j, j)//(k-j)) * p**j * trace**(k-2*j)
                    for j in range(k//2 + 1)
                )
                self.assertEqual(frobenius_power(trace, p, k), expected)

    def test_normalized_power_sums_obey_bound_and_exact_integer_metadata(self):
        for k in [1, 2, 3, MAX_EXPONENT]:
            row = local_reference(CURVES['11a1'].coefficients, 7, k)
            self.assertEqual(row['n'], 7**k)
            self.assertLessEqual(abs(row['unitary_logarithmic_coefficient']), 2 + 1e-12)
            self.assertTrue(math.isfinite(row['unitary_lambda_at_prime_power']))

    def test_bad_reduction_singular_model_and_composite_are_rejected(self):
        for model, p in [(CURVES['11a1'].coefficients, 11), (CURVES['37a1'].coefficients, 37),
                         ((0, 0, 0, 0, 0), 5), (CURVES['37a1'].coefficients, 25)]:
            with self.assertRaises(ValueError):
                point_count(model, p)

    def test_invalid_types_and_work_budgets_fail_before_counting(self):
        for p in [True, 3.0, 0, -1, MAX_PRIME + 1]:
            with self.assertRaises(ValueError):
                point_count(CURVES['37a1'].coefficients, p)
        for k in [True, 0, MAX_EXPONENT + 1]:
            with self.assertRaises(ValueError):
                frobenius_power(-2, 5, k)
        for model in [[0, 0, 1, -1, 0], (0, 0, True, -1, 0), (0, 0, 1, -1, 10**13)]:
            with self.assertRaises(ValueError):
                point_count(model, 5)
        for primes in [[], [5, 5], [5]*129, [99991, 99989, 99971, 99961, 99929, 99923,
                                                     99907, 99881, 99877, 99871, 99859]]:
            with self.assertRaises(ValueError):
                reference_report('37a1', primes)
        with self.assertRaises(ValueError):
            frobenius_power(6, 5, 1)

    def test_report_is_reproducible_and_clear_about_missing_spectral_evidence(self):
        report = reference_report('11a1', [2, 3, 5, 7], 2)
        self.assertEqual(report, reference_report('11a1', [2, 3, 5, 7], 2))
        self.assertEqual(len(report['model_sha256']), 64)
        self.assertIn('not_spectral_recovery', report['kind'])
        self.assertEqual(report['rows'][0]['frobenius_power_trace'], 0)


if __name__ == '__main__':
    unittest.main()
