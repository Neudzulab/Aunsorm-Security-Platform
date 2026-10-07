import math
import unittest

from sasrl_conditioning_reproduce import experiment, qr_model, solve


class PerturbationControls(unittest.TestCase):
    def test_orthogonal_modes_have_unit_noise_gain(self):
        row=experiment(spacing=1)
        self.assertAlmostEqual(row['measured_noise_gain'],1,places=8)
        self.assertLess(row['clean_coefficient_error_l2'],1e-14)

    def test_qr_residual_agrees_with_independent_gram_identity(self):
        for spacing in [.1,.01,.0001,.000001]:
            row=experiment(spacing=spacing)
            self.assertAlmostEqual(row['qr_residual_squared']/row['gram_determinant'],1,places=10)
            self.assertAlmostEqual(row['measured_to_predicted_gain'],1,places=7)

    def test_small_gap_amplifies_fixed_perturbation(self):
        coarse=experiment(spacing=.01)
        fine=experiment(spacing=.000001)
        self.assertGreater(fine['coefficient_shift_l2'],9000*coarse['coefficient_shift_l2'])
        self.assertLess(fine['clean_coefficient_error_l2'],fine['coefficient_shift_l2']*1e-6)

    def test_alias_and_roundoff_unresolved_columns_rejected(self):
        for spacing in [0,64,128,1e-15]:
            with self.assertRaises(ValueError):
                qr_model(64,spacing,64)

    def test_invalid_noise_or_sample_vectors_rejected(self):
        for epsilon in [0,-1,math.nan,math.inf,True,.01]:
            with self.assertRaises(ValueError):
                experiment(epsilon=epsilon)
        with self.assertRaises(ValueError):
            solve((complex(math.nan,0),0j),0j,(1j,1j),1)
        with self.assertRaises(ValueError):
            solve((1j,2j),0j,(1j,),1)


if __name__ == '__main__':
    unittest.main()
