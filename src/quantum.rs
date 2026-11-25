//! # Quantum Research & Simulation Engine
//!
//! Pure-Rust, from-scratch state-vector simulator supporting:
//! - Backward-compatible single-qubit simulator (`simulate_qubit`)
//! - Multi-qubit universal gate engine up to 8 qubits (`simulate_circuit`: H, X, Y, Z, S, T, RX, RY, RZ, CNOT, CZ, SWAP, TOFFOLI, QFT)
//! - BB84 Quantum Key Distribution eavesdropper QBER evaluation (`simulate_bb84`)

use anyhow::{Context, Result, bail};
use num_complex::Complex64;
use serde_json::{Value, json};
use std::f64::consts::{FRAC_1_SQRT_2, PI};

type Matrix = [[Complex64; 2]; 2];

fn single_gate(name: &str) -> Option<Matrix> {
    let zero = Complex64::new(0.0, 0.0);
    let one = Complex64::new(1.0, 0.0);
    let negative_one = Complex64::new(-1.0, 0.0);
    let imaginary = Complex64::new(0.0, 1.0);
    let negative_imaginary = Complex64::new(0.0, -1.0);

    if let Some(arg) = name
        .strip_prefix("RX(")
        .and_then(|s| s.strip_suffix(')'))
        .and_then(|s| s.trim().parse::<f64>().ok())
    {
        let c = Complex64::new((arg / 2.0).cos(), 0.0);
        let s = Complex64::new(0.0, -(arg / 2.0).sin());
        return Some([[c, s], [s, c]]);
    }
    if let Some(arg) = name
        .strip_prefix("RY(")
        .and_then(|s| s.strip_suffix(')'))
        .and_then(|s| s.trim().parse::<f64>().ok())
    {
        let c = Complex64::new((arg / 2.0).cos(), 0.0);
        let s = Complex64::new((arg / 2.0).sin(), 0.0);
        return Some([[c, -s], [s, c]]);
    }
    if let Some(arg) = name
        .strip_prefix("RZ(")
        .and_then(|s| s.strip_suffix(')'))
        .and_then(|s| s.trim().parse::<f64>().ok())
    {
        return Some([
            [Complex64::from_polar(1.0, -arg / 2.0), zero],
            [zero, Complex64::from_polar(1.0, arg / 2.0)],
        ]);
    }

    Some(match name {
        "I" => [[one, zero], [zero, one]],
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
        let matrix = single_gate(&name).ok_or_else(|| {
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
            "Idealized unitary single-qubit state-vector evaluation without physical decoherence."
        ]
    }))
}

fn apply_single_qubit_gate(state: &mut [Complex64], num_qubits: usize, target: usize, m: Matrix) {
    let dim = 1usize << num_qubits;
    let bit = 1usize << (num_qubits - 1 - target);
    for idx in 0..dim {
        if idx & bit == 0 {
            let a = state[idx];
            let b = state[idx | bit];
            state[idx] = m[0][0] * a + m[0][1] * b;
            state[idx | bit] = m[1][0] * a + m[1][1] * b;
        }
    }
}

fn apply_cnot(state: &mut [Complex64], num_qubits: usize, ctrl: usize, targ: usize) {
    let dim = 1usize << num_qubits;
    let c_bit = 1usize << (num_qubits - 1 - ctrl);
    let t_bit = 1usize << (num_qubits - 1 - targ);
    for idx in 0..dim {
        if (idx & c_bit != 0) && (idx & t_bit == 0) {
            state.swap(idx, idx | t_bit);
        }
    }
}

fn apply_cphase(state: &mut [Complex64], num_qubits: usize, ctrl: usize, targ: usize, angle: f64) {
    let dim = 1usize << num_qubits;
    let c_bit = 1usize << (num_qubits - 1 - ctrl);
    let t_bit = 1usize << (num_qubits - 1 - targ);
    let phase = Complex64::from_polar(1.0, angle);
    for (idx, amp) in state.iter_mut().enumerate().take(dim) {
        if (idx & c_bit != 0) && (idx & t_bit != 0) {
            *amp *= phase;
        }
    }
}

fn apply_toffoli(state: &mut [Complex64], num_qubits: usize, c1: usize, c2: usize, targ: usize) {
    let dim = 1usize << num_qubits;
    let b1 = 1usize << (num_qubits - 1 - c1);
    let b2 = 1usize << (num_qubits - 1 - c2);
    let bt = 1usize << (num_qubits - 1 - targ);
    for idx in 0..dim {
        if (idx & b1 != 0) && (idx & b2 != 0) && (idx & bt == 0) {
            state.swap(idx, idx | bt);
        }
    }
}

/// Multi-qubit circuit evaluator (`num_qubits` in 1..=8) supporting operations such as:
/// `"H 0"`, `"X 1"`, `"CNOT 0 1"`, `"CZ 0 1"`, `"SWAP 0 1"`, `"TOFFOLI 0 1 2"`, `"QFT"`.
pub fn simulate_circuit(num_qubits: usize, ops: &[String]) -> Result<Value> {
    if !(1..=8).contains(&num_qubits) {
        bail!("Multi-qubit simulator supports 1 to 8 qubits.");
    }
    let dim = 1usize << num_qubits;
    let mut state = vec![Complex64::new(0.0, 0.0); dim];
    state[0] = Complex64::new(1.0, 0.0);

    for raw in ops {
        let tokens: Vec<&str> = raw.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        let op = tokens[0].to_ascii_uppercase();
        match op.as_str() {
            "QFT" => {
                let h = single_gate("H").unwrap();
                for i in 0..num_qubits {
                    apply_single_qubit_gate(&mut state, num_qubits, i, h);
                    for j in (i + 1)..num_qubits {
                        let angle = PI / (1usize << (j - i)) as f64;
                        apply_cphase(&mut state, num_qubits, j, i, angle);
                    }
                }
                for i in 0..(num_qubits / 2) {
                    let opp = num_qubits - 1 - i;
                    apply_cnot(&mut state, num_qubits, i, opp);
                    apply_cnot(&mut state, num_qubits, opp, i);
                    apply_cnot(&mut state, num_qubits, i, opp);
                }
            }
            "CNOT" | "CX" => {
                if tokens.len() != 3 {
                    bail!("CNOT requires two qubit indices.");
                }
                let c: usize = tokens[1].parse().context("Invalid CNOT control")?;
                let t: usize = tokens[2].parse().context("Invalid CNOT target")?;
                if c >= num_qubits || t >= num_qubits || c == t {
                    bail!("Invalid CNOT qubit indices.");
                }
                apply_cnot(&mut state, num_qubits, c, t);
            }
            "CZ" => {
                if tokens.len() != 3 {
                    bail!("CZ requires two qubit indices.");
                }
                let c: usize = tokens[1].parse()?;
                let t: usize = tokens[2].parse()?;
                if c >= num_qubits || t >= num_qubits || c == t {
                    bail!("Invalid CZ qubit indices.");
                }
                apply_cphase(&mut state, num_qubits, c, t, PI);
            }
            "SWAP" => {
                if tokens.len() != 3 {
                    bail!("SWAP requires two qubit indices.");
                }
                let a: usize = tokens[1].parse()?;
                let b: usize = tokens[2].parse()?;
                if a >= num_qubits || b >= num_qubits || a == b {
                    bail!("Invalid SWAP qubit indices.");
                }
                apply_cnot(&mut state, num_qubits, a, b);
                apply_cnot(&mut state, num_qubits, b, a);
                apply_cnot(&mut state, num_qubits, a, b);
            }
            "TOFFOLI" | "CCX" => {
                if tokens.len() != 4 {
                    bail!("TOFFOLI requires three qubit indices.");
                }
                let c1: usize = tokens[1].parse()?;
                let c2: usize = tokens[2].parse()?;
                let t: usize = tokens[3].parse()?;
                if c1 >= num_qubits || c2 >= num_qubits || t >= num_qubits || c1 == c2 || c1 == t || c2 == t {
                    bail!("Invalid TOFFOLI qubit indices.");
                }
                apply_toffoli(&mut state, num_qubits, c1, c2, t);
            }
            _ => {
                let m = single_gate(&op)
                    .with_context(|| format!("Unsupported gate operation {raw:?}"))?;
                let targ: usize = tokens
                    .get(1)
                    .context("Single-qubit gate requires target index in multi-qubit circuit.")?
                    .parse()?;
                if targ >= num_qubits {
                    bail!("Target qubit index {targ} out of bounds for {num_qubits} qubits.");
                }
                apply_single_qubit_gate(&mut state, num_qubits, targ, m);
            }
        }
    }

    let probabilities: Vec<Value> = state
        .iter()
        .enumerate()
        .filter(|&(_, a)| a.norm_sqr() > 1e-9)
        .map(|(idx, a)| {
            let ket = format!("{idx:0width$b}", width = num_qubits);
            json!({
                "ket": format!("|{ket}>"),
                "probability": a.norm_sqr(),
                "real": a.re,
                "imag": a.im
            })
        })
        .collect();

    Ok(json!({
        "schema_version": 2,
        "analysis": "multi_qubit_state_vector_circuit",
        "num_qubits": num_qubits,
        "dimension": dim,
        "operations_executed": ops.len(),
        "non_zero_states": probabilities
    }))
}

/// Deterministic PRNG helper for repeatable BB84 QKD channel security analysis.
pub fn simulate_bb84(num_photons: usize, eve_intercept_ratio: f64) -> Result<Value> {
    if !(16..=10_000).contains(&num_photons) {
        bail!("BB84 simulation supports 16..=10,000 photons.");
    }
    let ratio = eve_intercept_ratio.clamp(0.0, 1.0);
    let mut seed: u64 = 0x5EED_CAFE_BABE_1234;
    let mut next_u64 = || -> u64 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    let mut sifted = 0usize;
    let mut errors = 0usize;
    for i in 0..num_photons {
        let alice_bit = (next_u64() & 1) as u8;
        let alice_basis = (next_u64() & 1) as u8;
        let bob_basis = (next_u64() & 1) as u8;

        let eve_active = ((i as f64) / num_photons as f64) < ratio;
        let transmitted_bit = if eve_active {
            let eve_basis = (next_u64() & 1) as u8;
            if eve_basis == alice_basis {
                alice_bit
            } else {
                (next_u64() & 1) as u8
            }
        } else {
            alice_bit
        };

        let bob_bit = if eve_active && bob_basis == alice_basis {
            // If Eve chose wrong basis, qubit collapsed into Eve's basis -> Bob measures random bit 50% of time
            transmitted_bit
        } else if bob_basis == alice_basis {
            alice_bit
        } else {
            (next_u64() & 1) as u8
        };

        if alice_basis == bob_basis {
            sifted += 1;
            if bob_bit != alice_bit {
                errors += 1;
            }
        }
    }

    let qber = if sifted > 0 {
        errors as f64 / sifted as f64
    } else {
        0.0
    };

    Ok(json!({
        "schema_version": 1,
        "analysis": "bb84_qkd_eavesdropper_qber_screen",
        "photons_transmitted": num_photons,
        "sifted_key_bits": sifted,
        "bit_errors": errors,
        "qber": qber,
        "eve_intercept_ratio": ratio,
        "eavesdropper_detected": qber > 0.11
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

    #[test]
    fn bell_state_entangles_00_and_11() {
        let ops = vec!["H 0".to_owned(), "CNOT 0 1".to_owned()];
        let out = simulate_circuit(2, &ops).unwrap();
        let states = out["non_zero_states"].as_array().unwrap();
        assert_eq!(states.len(), 2);
        assert_eq!(states[0]["ket"], "|00>");
        assert_eq!(states[1]["ket"], "|11>");
    }

    #[test]
    fn bb84_detects_eavesdropping_via_qber() {
        let clean = simulate_bb84(1000, 0.0).unwrap();
        assert_eq!(clean["eavesdropper_detected"], false);
        let tapped = simulate_bb84(1000, 1.0).unwrap();
        assert_eq!(tapped["eavesdropper_detected"], true);
    }
}
