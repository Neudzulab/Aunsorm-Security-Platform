#![no_main]
#![forbid(unsafe_code)]

use aunsorm_server::{AudioPcmDatagram, DatagramPayload, QuicDatagramV1, MAX_WIRE_BYTES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = QuicDatagramV1::decode(data) {
        assert_eq!(frame.version, QuicDatagramV1::VERSION);
        assert_eq!(frame.channel, frame.payload.channel());
        if let DatagramPayload::Audio(audio) = &frame.payload {
            audio
                .validate()
                .expect("accepted audio metadata must validate");
        }
        let encoded = frame.encode().expect("accepted datagrams must re-encode");
        assert!(encoded.len() <= MAX_WIRE_BYTES);
        assert_eq!(QuicDatagramV1::decode(&encoded).unwrap(), frame);
    }

    // Exercise exact full-frame reconstruction with real codec functions,
    // covering arbitrary S16LE bytes and wrapping/reordered packet sequences.
    if data.len() == AudioPcmDatagram::FRAME_BYTES {
        let mut fragments = QuicDatagramV1::from_pcm_frame(u32::MAX, 1, 7, data).unwrap();
        fragments.reverse();
        assert_eq!(
            QuicDatagramV1::reassemble_pcm_frame(&fragments).unwrap(),
            data
        );
        let budget = 8 + 2 * (usize::from(u16::from_le_bytes([data[0], data[1]])) % 477);
        let mut reserved =
            QuicDatagramV1::from_pcm_frame_with_fragment_bytes(u32::MAX, 1, 7, data, budget)
                .unwrap();
        reserved.reverse();
        assert_eq!(
            QuicDatagramV1::reassemble_pcm_frame(&reserved).unwrap(),
            data
        );
    }
});
