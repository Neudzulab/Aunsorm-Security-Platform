"""Fixed-budget host timing experiment, not a real-time or QUIC certification."""

import hashlib
import json
import math
import platform
from pathlib import Path
import statistics
import struct
import sys
import time

from sasrl_pcm import BASELINE, REFINED, PcmRecording, encode_wav
from sasrl_pcm_stream import StreamingPcm

INPUT_RATE = 96000
BLOCK_SAMPLES = 960
BLOCK_COUNT = 16
TRIALS = 3
PERIOD_NS = 10_000_000
FILTER_BUDGET = 45_000_000
RATES = (44100, 48000, 96000)


def timing_summary(durations):
    if not durations or any(type(x) is not int or x < 0 for x in durations):
        raise ValueError('timings must be a nonempty vector of nonnegative integer nanoseconds')
    ordered = sorted(durations)
    return {'count': len(ordered), 'minimum_ms': ordered[0] / 1e6,
            'median_ms': statistics.median(ordered) / 1e6,
            'p95_nearest_rank_ms': ordered[math.ceil(.95 * len(ordered)) - 1] / 1e6,
            'maximum_ms': ordered[-1] / 1e6}


def arrival_model(durations, period_ns=PERIOD_NS):
    """Unbounded FIFO single-worker model fed by measured push service times.

    No queue is actually deployed; EOF and transport costs are excluded.
    """
    timing_summary(durations)
    if type(period_ns) is not int or period_ns <= 0:
        raise ValueError('arrival period must be a positive integer')
    finish, maximum_wait, maximum_latency, missed = 0, 0, 0, 0
    for index, duration in enumerate(durations):
        arrival = index * period_ns
        start = max(arrival, finish)
        maximum_wait = max(maximum_wait, start-arrival)
        finish = start + duration
        latency = finish-arrival
        maximum_latency = max(maximum_latency, latency)
        missed += latency > period_ns
    return {'kind': 'model only: unbounded FIFO worker with periodic arrivals',
            'period_ms': period_ns / 1e6, 'frames': len(durations),
            'maximum_queue_wait_ms': maximum_wait / 1e6,
            'maximum_arrival_to_completion_ms': maximum_latency / 1e6,
            'completion_later_than_next_arrival_count': missed,
            'service_utilization': sum(durations) / (len(durations) * period_ns),
            'transport_or_scheduler_overhead_included': False,
            'backpressure_or_loss_policy_implemented': False}


def planned_filter_work():
    count = BLOCK_SAMPLES * BLOCK_COUNT
    bound = 0
    for design in (BASELINE, REFINED):
        for rate in RATES:
            engine = StreamingPcm(INPUT_RATE, rate, design)
            outputs = (count*rate + INPUT_RATE-1)//INPUT_RATE
            bound += TRIALS * outputs * engine.max_taps
    if bound > FILTER_BUDGET:
        raise ValueError('planned benchmark exceeds the aggregate filtering budget')
    return bound


def run():
    planned = planned_filter_work()  # Reject work before generating the fixture.
    count = BLOCK_SAMPLES * BLOCK_COUNT
    values = tuple(.3*math.sin(math.tau*1000*i/INPUT_RATE+.13)
                   + .2*math.sin(math.tau*20000*i/INPUT_RATE+.37) for i in range(count))
    raw, clipped = encode_wav(values, INPUT_RATE)
    recording = PcmRecording.from_bytes(raw)
    samples = tuple(x/32768 for x in recording.samples)
    rows, spent = [], 0
    for design in (BASELINE, REFINED):
        for rate in RATES:
            trials, output_hashes, cold, steady, eof = [], [], [], [], []
            for _ in range(TRIALS):
                engine = StreamingPcm(INPUT_RATE, rate, design)
                digest, durations, emitted = hashlib.sha256(), [], []
                for start in range(0, count, BLOCK_SAMPLES):
                    block = samples[start:start+BLOCK_SAMPLES]
                    began = time.perf_counter_ns()
                    output = engine.push(block, start)
                    durations.append(time.perf_counter_ns()-began)
                    emitted.append(len(output))
                    for value in output:
                        digest.update(struct.pack('<d', value))
                began = time.perf_counter_ns()
                tail = engine.finish(count)
                eof.append(time.perf_counter_ns()-began)
                for value in tail:
                    digest.update(struct.pack('<d', value))
                output_hashes.append(digest.hexdigest())
                cold.append(durations[0])
                steady.extend(durations[2:])
                spent += engine.evaluations
                trials.append({'push_service_ns': durations, 'push_output_samples': emitted,
                               'eof_output_samples': len(tail), 'stream': engine.summary(),
                               'arrival_model': arrival_model(durations)})
            if len(set(output_hashes)) != 1:
                raise ArithmeticError('identical fixture changed output across timing trials')
            rows.append({'profile': design.name, 'output_rate_hz': rate,
                         'repeatable_float64_le_sha256': output_hashes[0],
                         'cold_first_push': timing_summary(cold),
                         'steady_push_excluding_first_two': timing_summary(steady),
                         'eof_finish': timing_summary(eof), 'trials': trials})
    if spent > planned:
        raise ArithmeticError('actual filtering exceeded conservative preflight')
    return {'fixture': 'quantized synthetic 1kHz/20kHz mono S16 WAV',
            'stream_implementation_sha256': hashlib.sha256(Path(__file__).with_name('sasrl_pcm_stream.py').read_bytes()).hexdigest(),
            'benchmark_implementation_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'source_sha256': recording.sha256, 'input_clipped_samples': clipped,
            'input_rate_hz': INPUT_RATE, 'input_samples': count,
            'audio_duration_per_trial_seconds': count/INPUT_RATE,
            'trials_per_case': TRIALS, 'blocks_per_trial': BLOCK_COUNT,
            'planned_filter_work_upper_bound': planned, 'filter_evaluations': spent,
            'aggregate_filter_limit': FILTER_BUDGET,
            'kernel_construction': 'separate per-call 10m work and 250000 cached-tap limits',
            'host': {'python': sys.version, 'implementation': platform.python_implementation(),
                     'system': platform.system(), 'release': platform.release(),
                     'machine': platform.machine(), 'clock': 'perf_counter_ns monotonic wall time'},
            'timing_scope': 'push includes validation/kernel construction/filtering; finish measured separately; hashing/fixture excluded',
            'rows': rows,
            'limitations': ['Host load, power settings and interpreter affect measured wall time',
                            '42 steady push observations per case cannot prove worst-case latency',
                            'Sequential trials do not measure concurrent sessions or scheduling guarantees',
                            'Queue is a derived model, not live network/backpressure validation',
                            'Authentication, QUIC, clipping of filter output and transport overhead not timed']}


if __name__ == '__main__':
    print(json.dumps(run(), indent=2, allow_nan=False))
