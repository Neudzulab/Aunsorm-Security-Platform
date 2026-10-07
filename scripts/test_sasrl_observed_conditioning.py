import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from sasrl_cluster_conditioning import cluster_conditioning, timestamp_cluster_conditioning
from sasrl_telemetry import analyze
from test_sasrl_telemetry import capture, capture_data
import sasrl_observed_reproduce

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'fuzz'))
import sasrl_observed_corpus
import sasrl_signal_stdin


class ObservedConditioningTests(unittest.TestCase):
    def test_uniform_positions_agree_with_complete_grid(self):
        reference=cluster_conditioning(32,[0,.01,.02],1)
        actual=timestamp_cluster_conditioning(tuple(i*1000 for i in range(32)),[0,.01,.02])
        for left,right in zip(reference['singular_value_estimates'],actual['singular_value_estimates']):
            self.assertAlmostEqual(left,right,places=13)

    def test_large_integer_origin_preserves_millisecond_geometry(self):
        offsets=(0,1001,2000,3000)
        origin=2**64-4000
        low=timestamp_cluster_conditioning(offsets,[0,1])
        high=timestamp_cluster_conditioning(tuple(origin+x for x in offsets),[0,1])
        self.assertEqual(low['singular_value_estimates'],high['singular_value_estimates'])
        self.assertEqual(high['relative_timestamps_ms'],offsets)

    def test_actual_jitter_breaks_uniform_alias_without_nominal_reduction(self):
        regular=timestamp_cluster_conditioning([0,1000,2000,3000],[0,1])
        irregular=timestamp_cluster_conditioning([0,1001,2000,3000],[0,1])
        self.assertIsNone(regular['noise_gain_estimate'])
        self.assertIsNotNone(irregular['noise_gain_estimate'])
        self.assertIsNone(irregular['nyquist_hz'])
        self.assertNotIn('exact_binary64_alias_detected',irregular)

    def test_thinning_alias_keeps_fft_blocked_and_gaps_unfilled(self):
        data=capture_data(32)
        data['expected_interval_ms']=1000
        for i,row in enumerate(data['records']):
            row['frame']['sequence']=2*i
            row['frame']['timestamp_ms']=2*i*1000
        result=analyze(capture(data),spectrum=True,conditioning_frequencies=[0,.5])
        matrix=result['known_frequency_conditioning']['matrix']
        self.assertEqual(result['missing_sequence_slots'],31)
        self.assertFalse(result['spectrum_eligible'])
        self.assertNotIn('spectrum',result)
        self.assertEqual(result['reconstructed_samples'],0)
        self.assertTrue(matrix['exact_binary64_duplicate_columns_detected'])
        self.assertIsNone(matrix['noise_gain_estimate'])
        self.assertAlmostEqual(cluster_conditioning(32,[0,.5],1)['noise_gain_estimate'],1)

    def test_invalid_positions_and_phase_bounds(self):
        for positions in ([True,1],[0,1.0],[1,1],[2,1],[-1,0],
                          [0,2**64],[0,86400001],list(range(513))):
            with self.assertRaises(ValueError):
                timestamp_cluster_conditioning(positions,[0,1])
        for frequencies in ([0,float('nan')],[0,1e12],[0],[0,1,2]):
            with self.assertRaises(ValueError):
                timestamp_cluster_conditioning([0,1000],frequencies)
        for sweeps in (True,0,41):
            with self.assertRaises(ValueError):
                timestamp_cluster_conditioning([0,1000],[0,1],sweeps)

    def test_bad_order_and_clock_are_explicitly_blocked(self):
        for field,value in [('sequence',5),('timestamp_ms',0)]:
            data=capture_data()
            data['records'][5]['frame'][field]=value
            result=analyze(capture(data),conditioning_frequencies=[0,.01])
            self.assertFalse(result['known_frequency_conditioning']['eligible'])
            self.assertNotIn('matrix',result['known_frequency_conditioning'])

    def test_large_capture_is_not_cropped(self):
        result=analyze(capture(capture_data(1024)),conditioning_frequencies=[0,.01])
        self.assertEqual(result['samples'],1024)
        self.assertTrue(result['spectrum_eligible'])
        self.assertFalse(result['known_frequency_conditioning']['eligible'])

    def test_invalid_mode_request_is_rejected_even_for_blocked_geometry(self):
        data=copy.deepcopy(capture_data())
        data['records'][5]['frame']['timestamp_ms']=0
        for frequencies in ([0,float('nan')],[0],True):
            with self.assertRaises(ValueError):
                analyze(capture(data),conditioning_frequencies=frequencies)

    def test_reproduction_reserves_aggregate_before_any_analysis(self):
        with patch.object(sasrl_observed_reproduce,'AGGREGATE_WORK_LIMIT',1), \
                patch.object(sasrl_observed_reproduce,'analyze',side_effect=AssertionError('not preflighted')):
            with self.assertRaises(ValueError):
                sasrl_observed_reproduce.run()
        result=sasrl_observed_reproduce.run()
        self.assertEqual(result['planned_sample_scaled_work_upper_bound'],62464)
        self.assertIsNone(result['rows'][1]['analysis']['known_frequency_conditioning']['matrix']['noise_gain_estimate'])

    def test_cli_reports_actual_geometry_without_enabling_jittered_fft(self):
        data=capture_data(32)
        data['records'][7]['frame']['timestamp_ms']+=1
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'capture.json'
            path.write_text(json.dumps(data),encoding='utf-8')
            run=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('sasrl_telemetry.py')),
                                str(path),'--spectrum','--known-frequencies-hz','0','.01'],
                               capture_output=True,text=True,check=True)
        result=json.loads(run.stdout)
        self.assertFalse(result['spectrum_eligible'])
        self.assertNotIn('spectrum',result)
        self.assertEqual(result['known_frequency_conditioning']['matrix']['samples'],32)
        self.assertEqual(result['reconstructed_samples'],0)

    def test_corpus_preflights_before_exercising_inputs(self):
        with patch.object(sasrl_observed_corpus,'MAX_MATRIX_WORK',1), \
                patch.object(sasrl_observed_corpus,'fuzz',side_effect=AssertionError('not preflighted')):
            with self.assertRaises(ValueError):
                sasrl_observed_corpus.run()
        report=sasrl_observed_corpus.run()
        self.assertEqual(report['cases'],669)
        self.assertEqual(report['accepted_gauge_inputs'],39)
        self.assertEqual(report['failures'],0)

    def test_harness_propagates_post_parse_numerical_failure(self):
        data=json.dumps(capture_data(32)).encode('utf-8')
        with patch('sasrl_cluster_conditioning.timestamp_cluster_conditioning',
                   side_effect=ArithmeticError('numerical invariant failure')):
            with self.assertRaises(ArithmeticError):
                sasrl_signal_stdin.fuzz(data)


if __name__=='__main__':
    unittest.main()
