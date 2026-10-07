#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

//! SASRL-inspired full-band checks: uniform marginals can hide periodic output.
//! These regression diagnostics are neither NIST STS nor an entropy proof.

#[path = "support/spectral.rs"]
mod spectral;

use aunsorm_core::AunsormNativeRng;
use rand_core::RngCore;
use spectral::{power_spectrum, simultaneous_energy_bound};

#[test]
fn fft_matches_analytical_dc_impulse_nyquist_and_interior_modes() {
    let constant = power_spectrum(&[1.0; 8]).unwrap();
    assert_eq!(constant, vec![64.0, 0.0, 0.0, 0.0, 0.0]);
    let impulse = power_spectrum(&[1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]).unwrap();
    assert_eq!(impulse, vec![1.0; 5]);
    let alternating = power_spectrum(&[-1.0, 1.0, -1.0, 1.0, -1.0, 1.0, -1.0, 1.0]).unwrap();
    assert_eq!(alternating, vec![0.0, 0.0, 0.0, 0.0, 64.0]);
    let cosine = power_spectrum(&[1.0, 0.0, -1.0, 0.0, 1.0, 0.0, -1.0, 0.0]).unwrap();
    assert!((cosine[2] - 16.0).abs() < 1e-12);
    assert!(cosine
        .iter()
        .enumerate()
        .all(|(bin, value)| bin == 2 || *value < 1e-12));
}

#[test]
fn real_spectrum_satisfies_parseval_with_endpoint_weights() {
    let samples = [0.5, 2.0, -3.0, 4.0, 7.0, -2.0, 0.0, 1.25];
    let power = power_spectrum(&samples).unwrap();
    let spectral_energy = 2.0_f64.mul_add(power[1..4].iter().sum::<f64>(), power[0] + power[4]);
    let spatial_energy = 8.0 * samples.iter().map(|value| value * value).sum::<f64>();
    assert!((spectral_energy - spatial_energy).abs() < 1e-10);
}

#[test]
fn fft_agrees_with_direct_dft_for_asymmetric_input() {
    let samples = [0.25, 2.0, 0.0, 7.0, -4.0, -1.0, 3.0, 0.75];
    let power = power_spectrum(&samples).unwrap();
    for (bin, energy) in power.iter().enumerate() {
        let mut real = 0.0;
        let mut imaginary = 0.0;
        for (index, sample) in samples.iter().enumerate() {
            let angle =
                -std::f64::consts::TAU * f64::from(u32::try_from(bin * index).unwrap()) / 8.0;
            let (sin, cos) = angle.sin_cos();
            real += sample * cos;
            imaginary += sample * sin;
        }
        assert!((energy - real * real - imaginary * imaginary).abs() < 1e-10);
    }
}

#[test]
fn invalid_lengths_nonfinite_samples_and_work_excess_are_rejected() {
    for samples in [
        vec![],
        vec![1.0],
        vec![1.0; 3],
        vec![f64::NAN, 1.0],
        vec![f64::INFINITY, 0.0],
        vec![1.0; 131_072],
    ] {
        assert!(power_spectrum(&samples).is_err());
    }
}

#[test]
fn balanced_periodic_controls_fail_even_when_their_mean_is_zero() {
    let count = 4096_u32;
    let bound = simultaneous_energy_bound(count, count / 2 + 1, 1e-8);
    // Alternation hits the Nyquist endpoint; period 16 hits an interior bin.
    for period in [2_usize, 16, 128] {
        let samples: Vec<_> = (0..count as usize)
            .map(|index| {
                if index % period < period / 2 {
                    -1.0
                } else {
                    1.0
                }
            })
            .collect();
        assert!(samples.iter().sum::<f64>().abs() < f64::EPSILON);
        let power = power_spectrum(&samples).unwrap();
        assert!(power.iter().any(|energy| *energy > bound));
    }
    // A stuck output must also fail via DC rather than a missing endpoint.
    assert!(power_spectrum(&vec![1.0; count as usize]).unwrap()[0] > bound);
}

#[test]
fn native_rng_has_no_gross_full_band_periodicity() {
    const COUNT: u32 = 4096;
    const FALSE_ALARM_PER_BLOCK: f64 = 1e-8;
    let bound = simultaneous_energy_bound(COUNT, COUNT / 2 + 1, FALSE_ALARM_PER_BLOCK);
    let mut rng = AunsormNativeRng::new();
    // Four independently inspected consecutive blocks; union bound <= 4e-8
    // under the unbiased independent-bit reference model. No mean subtraction:
    // this preserves detection of stuck/bias defects in the DC component.
    for block in 0..4 {
        let mut bytes = [0_u8; COUNT as usize / 8];
        rng.fill_bytes(&mut bytes);
        let samples: Vec<_> = bytes
            .iter()
            .flat_map(|byte| (0..8).map(move |bit| if byte & (1 << bit) == 0 { -1.0 } else { 1.0 }))
            .collect();
        let power = power_spectrum(&samples).unwrap();
        let maximum = power.iter().copied().fold(0.0_f64, f64::max);
        println!("block={block} maximum_energy={maximum:.3} simultaneous_bound={bound:.3}");
        assert!(
            maximum < bound,
            "gross spectral defect in Native RNG block {block}"
        );
        bytes.fill(0);
    }
}
