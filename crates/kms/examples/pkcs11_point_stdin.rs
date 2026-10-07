#![forbid(unsafe_code)]

use std::io::{self, Read};

#[path = "../src/pkcs11_point.rs"]
mod pkcs11_point;

fn main() -> io::Result<()> {
    let mut data = Vec::new();
    io::stdin().take(4097).read_to_end(&mut data)?;
    if let Ok(public) = pkcs11_point::parse_ed25519_point(&data) {
        let mut canonical = vec![4, 32];
        canonical.extend_from_slice(&public);
        assert_eq!(pkcs11_point::parse_ed25519_point(&canonical), Ok(public));
        if data.len() == 34 {
            assert_eq!(data, canonical);
        } else {
            let mut double = vec![4, 34];
            double.extend_from_slice(&canonical);
            assert_eq!(data, double);
        }
    }
    Ok(())
}
