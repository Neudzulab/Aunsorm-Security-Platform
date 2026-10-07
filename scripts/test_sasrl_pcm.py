import io
import math
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import wave

from sasrl_pcm import (BASELINE, MAX_EVALUATIONS, MAX_INPUT_BYTES, MAX_L1_GAIN, MAX_SAMPLES,
                       PcmRecording, encode_wav, phase_kernel, resample)


class PcmTests(unittest.TestCase):
    def test_wav_interoperates_with_independent_standard_library_codec(self):
        signed = (-32768, -1234, 0, 32123, 32767)
        buffer = io.BytesIO()
        with wave.open(buffer, "wb") as writer:
            writer.setparams((1, 2, 96000, 0, "NONE", "not compressed"))
            writer.writeframes(b"".join(struct.pack("<h", value) for value in signed))
        self.assertEqual(PcmRecording.from_bytes(buffer.getvalue()).samples, signed)
        raw, clipped = encode_wav(tuple(value / 32768 for value in signed), 48000)
        with wave.open(io.BytesIO(raw), "rb") as reader:
            self.assertEqual(reader.getparams()[:4], (1, 2, 48000, len(signed)))
            self.assertEqual(reader.readframes(len(signed)),
                             b"".join(struct.pack("<h", value) for value in signed))
        self.assertEqual(clipped, 0)

    def test_pcm_wav_preserves_signed_extremes_and_rate(self):
        values = (-1.0, -1 / 32768, 0.0, 32767 / 32768)
        raw, clipped = encode_wav(values, 96000)
        source = PcmRecording.from_bytes(raw)
        self.assertEqual(source.samples, (-32768, -1, 0, 32767))
        self.assertEqual(source.sample_rate_hz, 96000)
        self.assertEqual(clipped, 0)

    def test_identity_and_integer_upsampling_are_cardinal(self):
        values = [math.sin(index * 2.5) * 0.7 for index in range(50)]
        same, report = resample(values, 96000, 96000)
        self.assertEqual(same, values)
        up, report = resample(values, 48000, 96000)
        self.assertEqual(up[::2], values)
        self.assertEqual(len(up), 100)
        self.assertTrue(report["all_input_lattice_positions_present"])

    def test_noninteger_conversion_does_not_claim_all_input_times(self):
        _, report = resample([0.1] * 100, 32000, 44100)
        self.assertTrue(report["aligned_input_lattice_samples_exact"])
        self.assertFalse(report["all_input_lattice_positions_present"])

    def test_constant_preserved_at_all_phases_and_reflected_edges(self):
        for output_rate in [8000, 44100, 48000, 96000, 192000]:
            output, report = resample([0.25] * 960, 96000, output_rate)
            self.assertLess(max(abs(value - 0.25) for value in output), 2e-15)
            self.assertLessEqual(report["maximum_l1_gain"], MAX_L1_GAIN)
            self.assertLessEqual(report["evaluations"], report["preflight_evaluations"])
            self.assertLessEqual(report["preflight_evaluations"], MAX_EVALUATIONS)
            self.assertEqual(len(output), math.ceil(960 * output_rate / 96000))

    def test_downsampling_preserves_low_tone_and_suppresses_above_nyquist(self):
        count = 4096
        low = [0.5 * math.sin(math.tau * 3000 * index / 96000) for index in range(count)]
        high = [0.5 * math.sin(math.tau * 35000 * index / 96000) for index in range(count)]
        low_output, _ = resample(low, 96000, 48000)
        high_output, _ = resample(high, 96000, 48000)
        target = [0.5 * math.sin(math.tau * 3000 * index / 48000)
                  for index in range(256, len(low_output) - 256)]
        error = math.sqrt(math.fsum((a - b) ** 2 for a, b in
                                   zip(low_output[256:-256], target)) / len(target))
        alias_rms = math.sqrt(math.fsum(value ** 2 for value in high_output[256:-256]) / len(target))
        self.assertLess(error, 1e-5)
        self.assertLess(alias_rms, 1e-5)
        # Unfiltered decimation aliases this tone at essentially full RMS amplitude.
        unfiltered_rms = math.sqrt(math.fsum(value ** 2 for value in high[::2][256:-256]) / len(target))
        self.assertGreater(unfiltered_rms, 0.3)

    def test_refined_window_preserves_20khz_for_both_audio_output_rates(self):
        count = 4096
        source = tuple(0.5 * math.sin(math.tau * 20000 * index / 96000 + 0.37)
                       for index in range(count))
        raw, _ = encode_wav(source, 96000)
        samples = tuple(value / 32768 for value in PcmRecording.from_bytes(raw).samples)
        for rate in [44100, 48000]:
            output, _ = resample(samples, 96000, rate)
            interior = output[256:-256]
            target = [0.5 * math.sin(math.tau * 20000 * index / rate + 0.37)
                      for index in range(256, len(output) - 256)]
            error = math.sqrt(math.fsum((a - b) ** 2 for a, b in zip(interior, target)) / len(target))
            self.assertLess(error, 2e-5)
        baseline, _ = resample(samples, 96000, 44100, BASELINE)
        target = [0.5 * math.sin(math.tau * 20000 * index / 44100 + 0.37)
                  for index in range(256, len(baseline) - 256)]
        old_error = math.sqrt(math.fsum((a - b) ** 2 for a, b in
                                       zip(baseline[256:-256], target)) / len(target))
        self.assertGreater(old_error, 0.1)

    def test_new_nyquist_tone_does_not_escape_filter_via_sample_phase(self):
        source = [0.5 * math.sin(math.tau * 24000 * index / 96000 + 0.37)
                  for index in range(4096)]
        output, _ = resample(source, 96000, 48000)
        rms = math.sqrt(math.fsum(value ** 2 for value in output[256:-256]) / len(output[256:-256]))
        self.assertLess(rms, 1e-6)
        self.assertGreater(abs(0.5 * math.sin(0.37)), 0.1)

    def test_phase_weights_bound_adversarial_amplitude(self):
        for cutoff in [0.95 / 24, 0.475, 0.95 * 44100 / 96000, 1.0]:
            for phase in [0.0, 0.01, 0.25, 0.5, 0.99]:
                taps, gain = phase_kernel(phase, cutoff)
                self.assertAlmostEqual(math.fsum(value for _, value in taps), 1.0, places=14)
                self.assertLessEqual(gain, MAX_L1_GAIN)
                self.assertAlmostEqual(math.fsum(value * math.copysign(1.0, value)
                                               for _, value in taps), gain)
        values = [1.0 if index % 3 else -1.0 for index in range(100)]
        output, report = resample(values, 96000, 44100)
        self.assertLessEqual(max(abs(value) for value in output), report["maximum_l1_gain"] + 1e-14)

    def test_quantization_reports_saturation(self):
        raw, clipped = encode_wav((-1.1, 1.1, 0.5, 0.0), 48000)
        self.assertEqual(clipped, 2)
        self.assertEqual(PcmRecording.from_bytes(raw).samples, (-32768, 32767, 16384, 0))

    def test_malformed_truncated_duplicate_and_nonpcm_wav_rejected(self):
        raw, _ = encode_wav((0.0, 0.1), 96000)
        variants = [raw[:-1], raw + b"x", b"x" * 50, raw[:12]]
        for offset, value, width in [(20, 3, 2), (22, 2, 2), (28, 1, 4),
                                     (32, 4, 2), (34, 32, 2), (24, 1, 4)]:
            modified = bytearray(raw)
            modified[offset:offset + width] = value.to_bytes(width, "little")
            variants.append(bytes(modified))
        duplicate = raw + raw[36:]
        variants.append(duplicate[:4] + struct.pack("<I", len(duplicate) - 8) + duplicate[8:])
        odd = raw[:-1]
        odd = odd[:4] + struct.pack("<I", len(odd) - 8) + odd[8:]
        variants.append(odd)
        for value in variants:
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                PcmRecording.from_bytes(value)

    def test_numeric_and_work_budgets_rejected_before_processing(self):
        for values in [[True, 0], [float("nan"), 0], [float("inf"), 0], [1.01, 0], [0]]:
            with self.assertRaises(ValueError):
                resample(values, 96000, 48000)
        for rate in [True, 0, 96000.0, 12345]:
            with self.assertRaises(ValueError):
                resample([0, 0], rate, 48000)
        with self.assertRaises(ValueError):
            resample([0] * MAX_SAMPLES, 96000, 8000)
        with self.assertRaises(ValueError):
            resample([0] * MAX_SAMPLES, 96000, 192000)
        with self.assertRaises(ValueError):
            PcmRecording.from_bytes(bytes(MAX_INPUT_BYTES + 1))
        with self.assertRaises(ValueError):
            resample([0, 0], 96000, 48000, object())
        for phase, cutoff in [(float("nan"), 1), (1, 1), (0, 1e-300), (0, True)]:
            with self.assertRaises(ValueError):
                phase_kernel(phase, cutoff)

    def test_parser_byte_mutations_do_not_hide_unexpected_errors(self):
        raw, _ = encode_wav((0.0, 0.1, -0.1, 0.25), 96000)
        for index in range(len(raw)):
            for bit in range(8):
                mutated = bytearray(raw)
                mutated[index] ^= 1 << bit
                try:
                    recording = PcmRecording.from_bytes(bytes(mutated))
                except ValueError:
                    continue
                self.assertTrue(2 <= len(recording.samples) <= MAX_SAMPLES)

    def test_cli_source_and_existing_output_are_protected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.wav"
            output = Path(directory) / "output.wav"
            raw, _ = encode_wav(tuple(math.sin(i) * 0.5 for i in range(32)), 96000)
            source.write_bytes(raw)
            script = Path(__file__).with_name("sasrl_pcm.py")
            common = [sys.executable, "-B", str(script), str(source), "--rate", "48000", "--output"]
            result = subprocess.run(common + [str(source)], capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(source.read_bytes(), raw)
            result = subprocess.run(common + [str(output)], capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            converted = output.read_bytes()
            self.assertEqual(PcmRecording.from_bytes(converted).sample_rate_hz, 48000)
            result = subprocess.run(common + [str(output)], capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_bytes(), converted)


if __name__ == "__main__":
    unittest.main()
