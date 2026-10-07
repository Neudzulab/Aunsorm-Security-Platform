import unittest
from unittest.mock import patch

import sasrl_stream_benchmark as benchmark


class TimingEvidenceTests(unittest.TestCase):
    def test_nearest_rank_and_median_keep_tail_observation(self):
        result = benchmark.timing_summary([1_000_000]*19 + [100_000_000])
        self.assertEqual(result['p95_nearest_rank_ms'], 1)
        self.assertEqual(result['maximum_ms'], 100)
        self.assertEqual(result['median_ms'], 1)

    def test_single_worker_queue_accumulates_and_drains(self):
        result = benchmark.arrival_model([20_000_000, 20_000_000, 0, 0, 0])
        self.assertEqual(result['maximum_queue_wait_ms'], 20)
        self.assertEqual(result['completion_later_than_next_arrival_count'], 3)
        self.assertEqual(result['service_utilization'], .8)
        self.assertFalse(result['backpressure_or_loss_policy_implemented'])

    def test_exact_deadline_is_not_a_miss_and_idle_worker_waits_for_arrival(self):
        result = benchmark.arrival_model([10_000_000, 0, 5_000_000])
        self.assertEqual(result['completion_later_than_next_arrival_count'], 0)
        self.assertEqual(result['maximum_queue_wait_ms'], 0)
        self.assertEqual(result['maximum_arrival_to_completion_ms'], 10)

    def test_invalid_timings_and_period_rejected(self):
        for values in [[], [True], [-1], [1.0]]:
            with self.assertRaises(ValueError):
                benchmark.arrival_model(values)
        for period in [0, -1, True, 1.0]:
            with self.assertRaises(ValueError):
                benchmark.arrival_model([1], period)

    def test_low_budget_rejects_before_fixture_work(self):
        with patch.object(benchmark, 'FILTER_BUDGET', 1), \
                patch.object(benchmark, 'encode_wav', side_effect=AssertionError('fixture began')):
            with self.assertRaisesRegex(ValueError, 'planned benchmark'):
                benchmark.run()


if __name__ == '__main__':
    unittest.main()
