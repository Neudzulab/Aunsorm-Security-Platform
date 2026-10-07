"""Fixed synthetic chunk/edge controls for the experimental streaming PCM API."""

import hashlib
import json
import math

from sasrl_pcm import PcmRecording, encode_wav, resample
from sasrl_pcm_stream import StreamingPcm

TOTAL_FILTER_EVALUATIONS = 20_000_000


def run() -> dict:
    # Five filtering passes per rate: offline, three stream partitions, and
    # independently reflected frames. Count each frame's rounded output too.
    planned_filter_evaluations = 0
    for rate in [44100, 48000]:
        max_taps = StreamingPcm(96000, rate).max_taps
        global_outputs = (4096 * rate + 95999) // 96000
        frame_outputs = sum((min(960, 4096-start)*rate + 95999)//96000
                            for start in range(0, 4096, 960))
        planned_filter_evaluations += (4*global_outputs + frame_outputs)*max_taps
    if planned_filter_evaluations > TOTAL_FILTER_EVALUATIONS:
        raise ValueError('planned reproduction exceeds the aggregate filtering budget')
    source_values = tuple(0.3 * math.sin(math.tau * 1000 * i / 96000 + 0.13)
                          + 0.2 * math.sin(math.tau * 20000 * i / 96000 + 0.37)
                          for i in range(4096))
    raw, input_clipped = encode_wav(source_values, 96000)
    recording = PcmRecording.from_bytes(raw)
    source = tuple(value / 32768 for value in recording.samples)
    rows, spent = [], 0
    for rate in [44100, 48000]:
        offline, reference = resample(source, 96000, rate)
        spent += reference['evaluations']
        reference_wav, reference_clipped = encode_wav(offline, rate)
        for sizes in [(960,), (257,), (1, 7, 31, 53)]:
            engine = StreamingPcm(96000, rate)
            actual, input_position, turn = [], 0, 0
            emitted_per_call = []
            while input_position < len(source):
                block = source[input_position:input_position + sizes[turn % len(sizes)]]
                output = engine.push(block, input_position)
                emitted_per_call.append(len(output))
                actual.extend(output)
                input_position += len(block)
                turn += 1
            tail = engine.finish(len(source))
            actual.extend(tail)
            spent += engine.evaluations
            if spent > TOTAL_FILTER_EVALUATIONS:
                raise ValueError('reproduction exceeds the aggregate filtering budget')
            if actual != offline:
                raise ArithmeticError('chunk partition changed the offline-reference samples')
            encoded, clipped = encode_wav(actual, rate)
            if encoded != reference_wav:
                raise ArithmeticError('quantized chunk partition changed the reference WAV')
            rows.append({'output_rate_hz': rate, 'chunk_sizes': sizes,
                         'output_wav_sha256': hashlib.sha256(encoded).hexdigest(),
                         'float_samples_exactly_equal_offline': True,
                         'quantized_wav_exactly_equal_offline': True,
                         'first_push_output_samples': emitted_per_call[0],
                         'eof_pending_output_samples': len(tail),
                         'output_clipped_samples': clipped, 'stream': engine.summary()})
        independent = []
        for start in range(0, len(source), 960):
            block, report = resample(source[start:start + 960], 96000, rate)
            independent.extend(block)
            spent += report['evaluations']
        if len(independent) != len(offline):
            raise ArithmeticError('10ms framing should have an integral output count')
        seam_rmse = math.sqrt(math.fsum((a-b)**2 for a, b in zip(independent, offline)) / len(offline))
        irregular_count = sum((min(257, len(source)-start)*rate + 96000-1)//96000
                              for start in range(0, len(source), 257))
        rows.append({'output_rate_hz': rate, 'independent_10ms_frames_rmse_vs_whole_stream': seam_rmse,
                     'independent_257_sample_chunk_output_count': irregular_count,
                     'correct_global_output_count': len(offline),
                     'independent_rounding_drift_samples': irregular_count-len(offline),
                     'reference_clipped_samples': reference_clipped})
    if spent > planned_filter_evaluations:
        raise ArithmeticError('actual filtering exceeded its conservative preflight')
    return {'fixture': 'Quantized synthetic 1kHz/20kHz sum; not live authenticated media',
            'input_wav_sha256': recording.sha256, 'input_clipped_samples': input_clipped,
            'input_samples': len(source), 'input_rate_hz': 96000,
            'filter_evaluations': spent, 'aggregate_filter_evaluation_limit': TOTAL_FILTER_EVALUATIONS,
            'planned_filter_evaluation_upper_bound': planned_filter_evaluations,
            'kernel_construction': 'separately bounded by per-call preflight and 250000 cached taps',
            'rows': rows,
            'limitations': ['Exact comparisons reproduce the same defined finite-filter boundary convention',
                            'Seam/rounding controls are fixed synthetic measurements, not universal SNR claims',
                            'Authentication, live QUIC loss/jitter, throughput and backpressure remain unverified']}


if __name__ == '__main__':
    print(json.dumps(run(), indent=2, allow_nan=False))
