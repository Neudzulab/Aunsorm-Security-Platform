#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

//! Stable-toolchain stdin entry point for QUIC decoder corpus fuzzing.
//! Expected invalid packets are rejected; unexpected exceptions remain failures.

use std::io::{self, Read};

use aunsorm_server::{AudioPcmDatagram, DatagramPayload, QuicDatagramV1, MAX_WIRE_BYTES};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut data = Vec::new();
    io::stdin()
        .take(u64::try_from(AudioPcmDatagram::FRAME_BYTES + 1)?)
        .read_to_end(&mut data)?;
    if let Ok(frame) = QuicDatagramV1::decode(&data) {
        assert_eq!(frame.version, QuicDatagramV1::VERSION);
        assert_eq!(frame.channel, frame.payload.channel());
        if let DatagramPayload::Audio(audio) = &frame.payload {
            audio.validate()?;
        }
        let encoded = frame.encode()?;
        assert!(encoded.len() <= MAX_WIRE_BYTES);
        assert_eq!(QuicDatagramV1::decode(&encoded)?, frame);
    }
    if data.len() == AudioPcmDatagram::FRAME_BYTES {
        let mut fragments = QuicDatagramV1::from_pcm_frame(u32::MAX, 1, 7, &data)?;
        fragments.reverse();
        assert_eq!(QuicDatagramV1::reassemble_pcm_frame(&fragments)?, data);
        let budget = 8 + 2 * (usize::from(u16::from_le_bytes([data[0], data[1]])) % 477);
        let mut reserved =
            QuicDatagramV1::from_pcm_frame_with_fragment_bytes(u32::MAX, 1, 7, &data, budget)?;
        reserved.reverse();
        assert_eq!(QuicDatagramV1::reassemble_pcm_frame(&reserved)?, data);
    }
    Ok(())
}
