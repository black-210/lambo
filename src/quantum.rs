use anyhow::{Result, bail};
use num_complex::Complex64;
use serde_json::{Value, json};
use std::f64::consts::FRAC_1_SQRT_2;

type Matrix = [[Complex64; 2]; 2];

fn gate(name: &str) -> Option<Matrix> {
    let zero = Complex64::new(0.0, 0.0);
    let one = Complex64::new(1.0, 0.0);
    let negative_one = Complex64::new(-1.0, 0.0);
    let imaginary = Complex64::new(0.0, 1.0);
    let negative_imaginary = Complex64::new(0.0, -1.0);
    Some(match name {
        "H" => [
            [
                Complex64::new(FRAC_1_SQRT_2, 0.0),
                Complex64::new(FRAC_1_SQRT_2, 0.0),
            ],
            [
                Complex64::new(FRAC_1_SQRT_2, 0.0),
                Complex64::new(-FRAC_1_SQRT_2, 0.0),
            ],
        ],
        "X" => [[zero, one], [one, zero]],
        "Y" => [[zero, negative_imaginary], [imaginary, zero]],
        "Z" => [[one, zero], [zero, negative_one]],
        "S" => [[one, zero], [zero, imaginary]],
        "T" => [
            [one, zero],
            [
                zero,
                Complex64::from_polar(1.0, std::f64::consts::FRAC_PI_4),
            ],
        ],
        _ => return None,
    })
}

pub fn simulate_qubit(gates: &[String], theta: f64, phi: f64) -> Result<Value> {
    if !theta.is_finite() || !phi.is_finite() {
        bail!("Initial-state angles must be finite numbers.");
    }
    let mut state = [
        Complex64::new((theta / 2.0).cos(), 0.0),
        Complex64::from_polar((theta / 2.0).sin(), phi),
    ];
    let mut normalized_gates = Vec::with_capacity(gates.len());
    for name in gates {
        let name = name.trim().to_ascii_uppercase();
        let matrix = gate(&name).ok_or_else(|| {
            anyhow::anyhow!("Unsupported gate {name:?}; choose H, X, Y, Z, S, or T.")
        })?;
        state = [
            matrix[0][0] * state[0] + matrix[0][1] * state[1],
            matrix[1][0] * state[0] + matrix[1][1] * state[1],
        ];
        normalized_gates.push(name);
    }
    let norm = (state[0].norm_sqr() + state[1].norm_sqr()).sqrt();
    if !norm.is_finite() || norm == 0.0 {
        bail!("Simulation produced an invalid state vector.");
    }
    state[0] /= norm;
    state[1] /= norm;
    Ok(json!({
        "schema_version": 1,
        "analysis": "educational_single_qubit_state_vector",
        "gates": normalized_gates,
        "state": {
            "0": {"real": state[0].re, "imag": state[0].im},
            "1": {"real": state[1].re, "imag": state[1].im}
        },
        "probabilities": {
            "0": state[0].norm_sqr(),
            "1": state[1].norm_sqr()
        },
        "limitations": [
            "This is a small idealized one-qubit state-vector simulation.",
            "It does not model noise, hardware, many-body systems, or prove physical properties."
        ]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hadamard_produces_equal_probabilities() {
        let report = simulate_qubit(&["h".to_owned()], 0.0, 0.0).unwrap();
        assert!((report["probabilities"]["0"].as_f64().unwrap() - 0.5).abs() < 1e-12);
        assert!((report["probabilities"]["1"].as_f64().unwrap() - 0.5).abs() < 1e-12);
    }

    #[test]
    fn rejects_unknown_gate() {
        assert!(simulate_qubit(&["BAD".to_owned()], 0.0, 0.0).is_err());
    }
}
