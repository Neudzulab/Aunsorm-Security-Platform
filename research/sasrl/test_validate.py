"""Mathematical oracle, invalid-input, and coverage regressions (offline)."""

import math
from pathlib import Path
import tempfile
import unittest

from validate import arithmetic_truth, estimate, load_zeros, validate


class ValidationTests(unittest.TestCase):
    def test_sieve_matches_independent_trial_division(self):
        primes, values = arithmetic_truth(1000)
        for n in range(2, 1001):
            factors = []
            remaining = n
            divisor = 2
            while divisor * divisor <= remaining:
                while remaining % divisor == 0:
                    factors.append(divisor)
                    remaining //= divisor
                divisor += 1
            if remaining > 1:
                factors.append(remaining)
            self.assertEqual(bool(primes[n]), len(factors) == 1)
            expected = math.log(factors[0]) if len(set(factors)) == 1 else 0.0
            self.assertEqual(values[n], expected)

    def test_prime_power_is_composite_at_fixed_threshold(self):
        # An independent phase fixture produces Lambda(4)=log(2) exactly.
        gamma = math.acos((1 - math.log(2)) * math.sqrt(4) / 2) / math.log(4)
        rows, summary = validate([(4, 4)], (gamma, 100.0))
        self.assertAlmostEqual(rows[0]["estimate"], math.log(2))
        self.assertFalse(rows[0]["predicted_prime"])
        self.assertEqual(summary["confusion"]["tn"], 1)

    def test_cutoff_is_inclusive_and_insufficient_coverage_fails(self):
        zeros = (1.0, 2.0, 3.0, 10.0)
        self.assertEqual(estimate(2, zeros, 1.0)[1], 2)
        with self.assertRaisesRegex(ValueError, "cover"):
            estimate(10, zeros, 1.0)

    def test_ordinate_bound_accounts_for_cutoff_crossing(self):
        original = (1.0, 2.0, 10.0)
        perturbed = (1.01, 2.01, 10.0)
        rows, _ = validate([(2, 2)], original, 1.0, 0.02)
        changed, _ = estimate(2, perturbed, 1.0)
        self.assertEqual(rows[0]["possible_cutoff_crossings"], 1)
        self.assertLessEqual(abs(rows[0]["estimate"] - changed),
                             rows[0]["ordinate_perturbation_bound"])

    def test_bad_ordinate_tables_fail(self):
        for data in (b"", b"nan", b"inf", b"-1 2", b"2 2", b"3 2", b"bad"):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "zeros.txt"
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    load_zeros(path)

    def test_unverified_input_has_no_attributed_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "zeros.txt"
            path.write_bytes(b"14.134725142 21.022039639\n")
            _, metadata = load_zeros(path)
            self.assertFalse(metadata["matches_pinned_odlyzko_file"])
            self.assertIsNone(metadata["source_url"])
            self.assertIsNone(metadata["published_ordinate_error_bound"])

    def test_ranges_and_scales_cannot_silently_change_the_sample(self):
        for blocks in ([], [(1, 2)], [(3, 2)], [(2, 4), (4, 5)]):
            with self.subTest(blocks=blocks), self.assertRaises(ValueError):
                validate(blocks, (1.0, 100.0))
        for scale in (0, -1, math.nan, math.inf):
            with self.subTest(scale=scale), self.assertRaises(ValueError):
                validate([(2, 3)], (1.0, 100.0), scale)


if __name__ == "__main__":
    unittest.main()
