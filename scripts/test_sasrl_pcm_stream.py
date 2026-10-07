import math
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from sasrl_pcm import BASELINE, MAX_EVALUATIONS, REFINED, RATES, encode_wav, resample
from sasrl_pcm_stream import MAX_BLOCK_SAMPLES, MAX_CACHED_TAPS, StreamingPcm


def chunks(source, sizes):
    position, turn = 0, 0
    while position < len(source):
        count = sizes[turn % len(sizes)]
        yield position, source[position:position + count]
        position += min(count, len(source) - position)
        turn += 1


def convert(source, input_rate, output_rate, sizes, design=REFINED):
    stream = StreamingPcm(input_rate, output_rate, design)
    output = []
    for start, block in chunks(source, sizes):
        output.extend(stream.push(block, start))
    output.extend(stream.finish(len(source)))
    return output, stream.summary()


class StreamingTests(unittest.TestCase):
    def test_arbitrary_partitions_equal_offline_samples_exactly(self):
        source = tuple(0.6 * math.sin(index * 0.173) for index in range(1024))
        for rates in [(96000, 44100), (96000, 48000), (48000, 96000),
                      (44100, 48000), (8000, 192000), (96000, 96000)]:
            reference, _ = resample(source, *rates)
            for sizes in [(1, 7, 31, 53), (960,), (4096,)]:
                actual, report = convert(source, *rates, sizes)
                self.assertEqual(actual, reference)
                self.assertEqual(report['state'], 'finished')
                self.assertEqual(report['retained_history_samples'], 0)
                self.assertLessEqual(report['peak_history_samples'], report['history_limit_samples'])
                self.assertLessEqual(report['cached_taps_built'], MAX_CACHED_TAPS)

    def test_both_profiles_and_extreme_downsampling_use_complete_eof_context(self):
        source = tuple(((index * 37) % 101 - 50) / 100 for index in range(4096))
        for design in [BASELINE, REFINED]:
            reference, _ = resample(source, 192000, 8000, design)
            actual, _ = convert(source, 192000, 8000, (1, 17, 256, 960), design)
            self.assertEqual(actual, reference)

    def test_future_samples_are_required_and_prefix_matches_final_reference(self):
        source = tuple(math.sin(index * 0.23) * 0.5 for index in range(1024))
        stream = StreamingPcm(96000, 48000)
        self.assertEqual(stream.push(source[:256], 0), [])
        prefix = stream.push(source[256:512], 256)
        reference, _ = resample(source, 96000, 48000)
        self.assertGreater(len(prefix), 0)
        self.assertLess(len(prefix), 256)
        self.assertEqual(prefix, reference[:len(prefix)])
        output = prefix + stream.push(source[512:], 512) + stream.finish(stream.input_samples)
        self.assertEqual(output, reference)

    def test_short_stream_reflections_match_offline_without_fabricated_lookahead(self):
        for count in [2, 3, 7, 32, 159]:
            source = tuple(index / count / 2 for index in range(count))
            for rates in [(96000, 44100), (48000, 96000), (96000, 96000)]:
                reference, _ = resample(source, *rates)
                output, _ = convert(source, *rates, (1,))
                self.assertEqual(output, reference)

    def test_constant_stream_has_bounded_history_across_many_frames(self):
        stream = StreamingPcm(96000, 48000)
        count = 0
        for frame in range(80):
            output = stream.push([0.25] * 960, frame * 960)
            self.assertTrue(all(abs(value - 0.25) < 2e-15 for value in output))
            count += len(output)
            self.assertLessEqual(len(stream._buffer), 2 * stream.radius + 2)
        tail = stream.finish(stream.input_samples)
        self.assertTrue(all(abs(value - 0.25) < 2e-15 for value in tail))
        self.assertEqual(count + len(tail), 80 * 480)
        report = stream.summary()
        self.assertLessEqual(report['peak_history_samples'], report['history_limit_samples'])
        self.assertLessEqual(report['maximum_preflight_evaluations_per_call'], MAX_EVALUATIONS)

    def test_gaps_duplicates_and_reorder_latch_failure(self):
        for offset in [0, 3, 5, -1, True, 4.0]:
            stream = StreamingPcm(96000, 48000)
            stream.push([0.1] * 4, 0)
            with self.assertRaises(ValueError):
                stream.push([0.1], offset)
            self.assertEqual(stream.state, 'failed')
            self.assertEqual(stream.input_samples, 4)
            with self.assertRaises(ValueError):
                stream.push([0.1], 4)
            with self.assertRaises(ValueError):
                stream.finish(stream.input_samples)

    def test_invalid_values_and_call_budget_fail_before_input_mutation(self):
        for samples in [[], [True], [float('nan')], [float('inf')], [1.01],
                        [0] * (MAX_BLOCK_SAMPLES + 1)]:
            stream = StreamingPcm(96000, 48000)
            with self.assertRaises(ValueError):
                stream.push(samples, 0)
            self.assertEqual(stream.input_samples, 0)
            self.assertEqual(stream.state, 'failed')
        stream = StreamingPcm(8000, 192000)
        with self.assertRaises(ValueError):
            stream.push([0] * 4096, 0)
        self.assertEqual(stream.input_samples, 0)

    def test_lifecycle_and_invalid_design_rates(self):
        for count in [0, 1]:
            stream = StreamingPcm(96000, 48000)
            if count:
                stream.push([0.1], 0)
            with self.assertRaises(ValueError):
                stream.finish(stream.input_samples)
            self.assertEqual(stream.state, 'failed')
        stream = StreamingPcm(96000, 96000)
        self.assertEqual(stream.push([0.1, 0.2], 0), [0.1, 0.2])
        self.assertEqual(stream.finish(stream.input_samples), [])
        with self.assertRaises(ValueError):
            stream.finish(stream.input_samples)
        with self.assertRaises(ValueError):
            stream.push([0], 2)
        for rate in [True, 1, 96000.0]:
            with self.assertRaises(ValueError):
                StreamingPcm(rate, 48000)
        with self.assertRaises(ValueError):
            StreamingPcm(96000, 48000, object())

    def test_all_declared_rate_pairs_have_bounded_phase_and_history_designs(self):
        for source in RATES:
            for target in RATES:
                for design in [BASELINE, REFINED]:
                    stream = StreamingPcm(source, target, design)
                    self.assertLessEqual(stream.phase_count * stream.max_taps, MAX_CACHED_TAPS)
                    self.assertLessEqual(stream.buffer_limit, 13_000)

    def test_identity_stream_emits_each_sample_without_filter_lookahead(self):
        stream = StreamingPcm(96000, 96000)
        self.assertEqual(stream.push([0.1], 0), [0.1])
        self.assertEqual(stream.push([0.2], 1), [0.2])
        self.assertEqual(stream.finish(stream.input_samples), [])
        self.assertEqual(stream.summary()['lookahead_upper_bound_input_samples'], 0)

    def test_eof_declared_length_rejects_missing_tail_and_invalid_counts(self):
        for declared in [3, 5, -1, True, 4.0]:
            stream = StreamingPcm(96000, 48000)
            stream.push([0.1] * 4, 0)
            with self.assertRaises(ValueError):
                stream.finish(declared)
            self.assertEqual(stream.state, 'failed')
            self.assertEqual(stream.output_samples, 0)

    def test_cli_quantized_output_equals_offline_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source.wav'
            destination = Path(directory) / 'stream.wav'
            values = tuple(math.sin(i * 0.2) * 0.5 for i in range(64))
            raw, _ = encode_wav(values, 96000)
            source.write_bytes(raw)
            script = Path(__file__).with_name('sasrl_pcm_stream.py')
            command = [sys.executable, '-B', str(script), str(source), '--rate', '48000',
                       '--block-samples', '7', '--output', str(destination)]
            result = subprocess.run(command, capture_output=True, check=True)
            report = json.loads(result.stdout)
            from sasrl_pcm import PcmRecording
            samples = tuple(value / 32768 for value in PcmRecording.from_bytes(raw).samples)
            expected, _ = resample(samples, 96000, 48000)
            encoded, clipped = encode_wav(expected, 48000)
            self.assertEqual(destination.read_bytes(), encoded)
            self.assertEqual(report['clipped_output_samples'], clipped)
            self.assertEqual(report['state'], 'finished')
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            command[-1] = str(source)
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(source.read_bytes(), raw)


class ReproductionBudgetTests(unittest.TestCase):
    def test_aggregate_budget_rejected_before_fixture_or_filter_work(self):
        import sasrl_stream_reproduce
        with patch.object(sasrl_stream_reproduce, 'TOTAL_FILTER_EVALUATIONS', 1), \
                patch.object(sasrl_stream_reproduce, 'encode_wav', side_effect=AssertionError('fixture work began')):
            with self.assertRaisesRegex(ValueError, 'planned reproduction'):
                sasrl_stream_reproduce.run()


if __name__ == '__main__':
    unittest.main()
