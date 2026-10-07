import itertools
import math
import unittest
from unittest.mock import patch

from sasrl_cluster_conditioning import cluster_conditioning
from sasrl_conditioning import two_mode_conditioning


class ClusterControls(unittest.TestCase):
    def test_dft_columns_are_orthonormal(self):
        row=cluster_conditioning(32,[0,1,2,3,4,5,6,7],32)
        self.assertTrue(row['converged'])
        for value in row['singular_value_estimates']:
            self.assertAlmostEqual(value,1,places=12)

    def test_two_mode_reference_agrees(self):
        for gap in [.1,.01,.001]:
            row=cluster_conditioning(64,[0,gap],64)
            reference=two_mode_conditioning(64,gap,64)
            self.assertAlmostEqual(row['singular_value_estimates'][0]/reference['sigma_min'],1,places=10)
            self.assertAlmostEqual(row['singular_value_estimates'][1]/reference['sigma_max'],1,places=10)

    def test_three_mode_cauchy_binet_vandermonde_determinant(self):
        samples=16
        for gap in [.1,.01,.001]:
            row=cluster_conditioning(samples,[0,gap,2*gap],samples)
            delta=math.tau*gap/samples
            direct=math.fsum(math.prod(4*math.sin(delta*(b-a)/2)**2
                                      for a,b in itertools.combinations(indices,2))
                             for indices in itertools.combinations(range(samples),3))/samples**3
            estimated=math.prod(x*x for x in row['singular_value_estimates'])
            self.assertTrue(row['converged'])
            self.assertAlmostEqual(estimated/direct,1,places=7)

    def test_larger_cluster_gain_exceeds_two_mode_gain(self):
        row=cluster_conditioning(64,[0,.01,.02],64)
        pair=two_mode_conditioning(64,.01,64)
        self.assertGreater(row['noise_gain_estimate'],20*pair['worst_case_noise_gain'])

    def test_alias_and_precision_floor_hide_gain(self):
        for frequencies in [[0,64,1],[0,1e-10,2e-10]]:
            row=cluster_conditioning(64,frequencies,64)
            self.assertTrue(row['numerically_unresolved'])
            self.assertIsNone(row['noise_gain_estimate'])
            self.assertIsNone(row['condition_estimate'])

    def test_incomplete_sweep_reports_nonconvergence(self):
        row=cluster_conditioning(64,[0,.03,.09,.11],64,sweeps=1)
        self.assertFalse(row['converged'])
        self.assertIsNone(row['noise_gain_estimate'])

    def test_frequency_shift_and_permutation_preserve_spectrum(self):
        reference=cluster_conditioning(64,[0,.1,.2],64)
        changed=cluster_conditioning(64,[10.2,10,10.1],64)
        for a,b in zip(reference['singular_value_estimates'],changed['singular_value_estimates']):
            self.assertAlmostEqual(a,b,places=11)

    def test_invalid_matrix_inputs_rejected(self):
        for arguments in [(1,[0,1],1),(True,[0,1],1),(513,[0,1],1),
                          (2,[0,1,2],1),(64,[0]*9,1),(64,[0,math.nan],1),
                          (64,[0,1],0),(64,[0,1e308],1e-308),(64,[0,1e7],1)]:
            with self.assertRaises(ValueError):
                cluster_conditioning(*arguments)
        with self.assertRaises(ValueError):
            cluster_conditioning(64,[0,1],64,sweeps=0)

    def test_aggregate_preflight_rejects_before_any_matrix_solve(self):
        import sasrl_cluster_reproduce as reproduction
        with patch.object(reproduction,'AGGREGATE_WORK_LIMIT',1), \
                patch.object(reproduction,'cluster_conditioning',side_effect=AssertionError('solve began')):
            with self.assertRaisesRegex(ValueError,'aggregate sweep budget'):
                reproduction.run()

    def test_maximum_configuration_and_per_matrix_preflight(self):
        import sasrl_cluster_conditioning as diagnostic
        row=cluster_conditioning(512,list(range(8)),512)
        self.assertTrue(row['converged'])
        self.assertLessEqual(row['sample_scaled_work_upper_bound'],diagnostic.MAX_WORK)
        with patch.object(diagnostic,'MAX_WORK',1), \
                patch.object(diagnostic.math,'cos',side_effect=AssertionError('matrix generation began')):
            with self.assertRaisesRegex(ValueError,'sweep work budget'):
                cluster_conditioning(64,[0,1],64)


if __name__=='__main__':
    unittest.main()
