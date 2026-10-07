"""Byte-input parser fuzz harness; expected invalid data is rejected explicitly."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from sasrl_pcm import MAX_INPUT_BYTES, PcmRecording, resample
from sasrl_pcm_stream import StreamingPcm
from sasrl_telemetry import GaugeCapture, analyze


def fuzz(data: bytes) -> None:
    try:
        if data.startswith(b"RIFF"):
            source = PcmRecording.from_bytes(data)
        else:
            source = GaugeCapture.from_bytes(data)
    except ValueError:
        return
    # Once parsing accepts input, numerical/state failures are unexpected and
    # must propagate. Keep this fuzz control small regardless of WAV length.
    if isinstance(source, PcmRecording):
        assert 2 <= len(source.samples) <= 192000
        samples = tuple(value / 32768 for value in source.samples[:64])
        expected, _ = resample(samples, source.sample_rate_hz, 48000)
        stream = StreamingPcm(source.sample_rate_hz, 48000)
        actual = []
        for start in range(0, len(samples), 7):
            actual.extend(stream.push(samples[start:start+7], start))
        actual.extend(stream.finish(len(samples)))
        assert actual == expected
    else:
        result = analyze(source)
        assert result["reconstructed_samples"] == 0
        assert result["authentication_verified_by_tool"] is False
        # Exercise the full observed capture, never a cropped matrix. Larger or
        # multi-day inputs remain parser/cadence controls, outside this small
        # numerical fuzz budget. Ordering failures are reported by analyze.
        if len(source.values)<=64 and max(source.timestamps_ms)-min(source.timestamps_ms)<=86_400_000:
            observed=analyze(source,conditioning_frequencies=(0,.5))
            assert observed['reconstructed_samples']==0
            assert observed['spectrum_eligible']==result['spectrum_eligible']
            diagnostic=observed['known_frequency_conditioning']
            if diagnostic['eligible']:
                assert diagnostic['missing_slots_reconstructed']==0
                assert diagnostic['matrix']['samples']==len(source.values)


if __name__ == "__main__":
    fuzz(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
