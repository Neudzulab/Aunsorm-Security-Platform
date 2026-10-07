//! Diagnostic FFT only: not an entropy estimator or a NIST certification.

/// Squared magnitudes of all real-input bins, including DC and Nyquist.
pub fn power_spectrum(samples: &[f64]) -> Result<Vec<f64>, &'static str> {
    if samples.len() < 2 || !samples.len().is_power_of_two() {
        return Err("sample count must be a power of two >= 2");
    }
    if samples.len() > 65_536 || samples.iter().any(|value| !value.is_finite()) {
        return Err("samples must be finite and within the diagnostic work budget");
    }
    let count = samples.len();
    let bits = count.trailing_zeros();
    let mut values = vec![(0.0, 0.0); count];
    for (index, sample) in samples.iter().enumerate() {
        let reversed = index.reverse_bits() >> (usize::BITS - bits);
        values[reversed] = (*sample, 0.0);
    }
    let mut width = 2;
    while width <= count {
        let half = width / 2;
        let angular_step = -std::f64::consts::TAU / f64::from(u32::try_from(width).unwrap());
        for offset in (0..count).step_by(width) {
            for position in 0..half {
                let angle = angular_step * f64::from(u32::try_from(position).unwrap());
                let (sin, cos) = angle.sin_cos();
                let (real, imaginary) = values[offset + position + half];
                let rotated = (
                    real.mul_add(cos, -(imaginary * sin)),
                    real.mul_add(sin, imaginary * cos),
                );
                let (base_real, base_imaginary) = values[offset + position];
                values[offset + position] = (base_real + rotated.0, base_imaginary + rotated.1);
                values[offset + position + half] =
                    (base_real - rotated.0, base_imaginary - rotated.1);
            }
        }
        width *= 2;
    }
    Ok(values[..=count / 2]
        .iter()
        .map(|(real, imaginary)| real * real + imaginary * imaginary)
        .collect())
}

/// Conservative simultaneous bound for independent unbiased +/-1 samples.
///
/// Hoeffding bounds each real/imaginary projection by 2 exp(-t²/(2N)).
/// If |DFT|² >= E, at least one projection has squared magnitude >= E/2.
/// The union over both projections and all bins is <= 4*B*exp(-E/(4N)).
/// This bound diagnoses gross periodicity, not cryptographic unpredictability.
pub fn simultaneous_energy_bound(count: u32, bins: u32, false_alarm: f64) -> f64 {
    4.0 * f64::from(count) * (4.0 * f64::from(bins) / false_alarm).ln()
}
