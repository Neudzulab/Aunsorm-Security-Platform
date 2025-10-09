use aunsorm_core::{
    calib_from_text,
    coord32_derive,
    derive_seed64_and_pdk,
    kdf::KdfPreset,
    kdf::KdfProfile,
    Salts,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = KdfProfile::preset(KdfPreset::Low);
    let (seed, pdk, info) = derive_seed64_and_pdk(
        "example-password",
        b"example-password-salt",
        b"example-calib-salt",
        b"example-chain-salt",
        profile,
    )?;
    println!("Derived seed: {} bytes, PDK: {} bytes", seed.len(), pdk.len());
    println!("KDF profile: {}", info.profile);

    let (calibration, calib_id) = calib_from_text(b"example-org", "Neudzulab | Prod | 2025-08");
    println!("Calibration id: {}", calib_id);

    let salts = Salts::new(
        b"example-calib-salt".to_vec(),
        b"example-chain-salt".to_vec(),
        b"example-coord-salt".to_vec(),
    )?;

    let (coord_id, coord) = coord32_derive(seed.as_ref(), &calibration, &salts)?;
    println!("Coord id: {} ({} bytes)", coord_id, coord.len());
    println!("First eight coord bytes: {:02x?}", &coord[..8]);

    Ok(())
}
