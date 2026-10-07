"""Exact finite checks, including adversarial assumptions; no sampling tests."""
import unittest
from fractions import Fraction
from extractor import extract, output_budget


def matrix_reference(x, seed, n, m):
    result = 0
    for i in range(m):
        parity = 0
        for j in range(n):
            parity ^= ((x >> j) & 1) & ((seed >> (n - 1 + i - j)) & 1)
        result |= parity << i
    return result


class ExtractorTests(unittest.TestCase):
    def test_matches_independent_matrix(self):
        for n, m in [(1, 1), (3, 2), (4, 4)]:
            for seed in range(1 << (n + m - 1)):
                for x in range(1 << n):
                    self.assertEqual(extract(x, seed, n, m), matrix_reference(x, seed, n, m))

    def test_every_nonzero_difference_is_balanced(self):
        # Linearity reduces every pair x != x' to z=x XOR x'. For every z,
        # all 16 outputs occur exactly 128 times across all 2048 seeds.
        n, m = 8, 4
        for z in range(1, 1 << n):
            counts = [0] * (1 << m)
            for seed in range(1 << (n + m - 1)):
                counts[extract(z, seed, n, m)] += 1
            self.assertEqual(counts, [128] * 16)

    def test_public_seed_joint_distance_exact(self):
        # X uniform on four of eight strings: k=2, m=1.
        total = Fraction(0)
        for seed in range(8):
            counts = [0, 0]
            for x in range(4):
                counts[extract(x, seed, 3, 1)] += 1
            total += sum(abs(Fraction(c, 4) - Fraction(1, 2)) for c in counts) / 2
        distance = total / 8
        self.assertEqual(distance, Fraction(1, 8))
        # Avoid floating-point comparison to .5*sqrt(2**(m-k)).
        self.assertLessEqual(distance * distance, Fraction(1, 8))

    def test_marginal_balance_does_not_certify_entropy(self):
        # A block consisting entirely of one fair bit has balanced marginals
        # but only ONE bit of block min-entropy, regardless of n.
        with self.assertRaises(ValueError):
            output_budget(4096, 1, 128)

    def test_source_dependent_seed_can_destroy_output(self):
        # X is fair, but seed=1 XOR X forces Y=0: independence is essential.
        self.assertEqual([extract(x, 1 ^ x, 1, 1) for x in (0, 1)], [0, 0])

    def test_known_input_can_look_balanced_but_is_not_secret(self):
        # X=1 has k=0. Y equals public seed S: output marginals are perfectly
        # uniform, yet an observer predicts every bit. Joint TV is exactly 1/2.
        outputs = [extract(1, seed, 1, 1) for seed in (0, 1)]
        self.assertEqual(outputs, [0, 1])
        self.assertEqual(sum(Fraction(1, 2) for seed, y in enumerate(outputs) if seed == y), 1)
        with self.assertRaises(ValueError):
            output_budget(1, 0, 1)

    def test_zero_seed_is_not_safe_for_all_sources(self):
        self.assertEqual([extract(x, 0, 4, 2) for x in range(16)], [0] * 16)

    def test_budget_and_boundaries(self):
        self.assertEqual(output_budget(4096, 1318, 128), 1062)
        self.assertEqual(extract(0, 0, 1, 1), 0)
        self.assertEqual(extract(1, 1, 1, 1), 1)
        for args in [(0, 0, 1), (4, 5, 1), (4, 2, 1), (4, -1, 1), (4, 4, 0), (4, 4.0, 1), (True, 1, 1)]:
            with self.assertRaises(ValueError):
                output_budget(*args)
        for args in [(2, 0, 1, 1), (0, 2, 1, 1), (-1, 0, 1, 1), (0, 0, 0, 1), (0, 0, 1, 2), (True, 0, 1, 1)]:
            with self.assertRaises(ValueError):
                extract(*args)


if __name__ == "__main__":
    unittest.main()
