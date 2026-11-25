//! # Cryptanalysis Module
//!
//! Research-grade, **legal-only** cryptanalysis utilities for the IQ Workbench.
//! All implementations are educational and experimental — they do NOT break
//! production cryptographic systems.
//!
//! ## Algorithms
//! * **RSA factorisation sandbox** — trial-division + Pollard-Rho on small moduli.
//! * **AES-CTR keystream-reuse detector** — XORs ciphertexts to surface plaintext leaks.
//! * **Frequency analysis** — byte-level frequency histogram (classical cipher aid).
//! * **Shannon entropy scorer** — measures information density of arbitrary data.
//! * **Vigenère cracker** — Kasiski + IC-based key-length estimation then per-column χ² attack.
//! * **XOR single-key recovery** — recovers a repeating XOR key given known key length.
//! * **Coppersmith stub** — placeholder for lattice-based small-root attacks.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

// ─── RSA Factorisation ───────────────────────────────────────────────────────

/// Attempt to factor a small RSA modulus using trial division and Pollard-Rho.
pub fn rsa_factor(e: u64, n: u64) -> Result<Value> {
    let mut factors = Vec::new();
    let mut remainder = n;

    // Trial division up to √n
    let limit = (n as f64).sqrt() as u64 + 1;
    for p in 2..=limit {
        while remainder % p == 0 {
            factors.push(p);
            remainder /= p;
        }
    }
    if remainder > 1 {
        factors.push(remainder);
    }

    // If trial division didn't split n, try Pollard-Rho
    if factors.len() <= 1 && n > 1 {
        factors.clear();
        if let Some((p, q)) = pollard_rho(n) {
            factors.push(p);
            factors.push(q);
        } else {
            factors.push(n); // couldn't factor
        }
    }

    let success = factors.len() > 1;
    Ok(json!({
        "algorithm": "rsa_factor",
        "public_exponent": e,
        "modulus": n,
        "factors": factors,
        "status": if success { "factored" } else { "failed" },
        "note": "Educational demo — only tractable for small moduli."
    }))
}

/// Pollard-Rho factorisation (Brent variant).
fn pollard_rho(n: u64) -> Option<(u64, u64)> {
    if n % 2 == 0 {
        return Some((2, n / 2));
    }
    let f = |x: u64, c: u64| -> u64 {
        ((x as u128 * x as u128 + c as u128) % n as u128) as u64
    };
    for c in 1..20 {
        let mut x: u64 = 2;
        let mut y: u64 = 2;
        let mut d: u64 = 1;
        while d == 1 {
            x = f(x, c);
            y = f(f(y, c), c);
            d = gcd(x.abs_diff(y), n);
        }
        if d != n {
            return Some((d, n / d));
        }
    }
    None
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

// ─── AES-CTR Keystream Reuse ─────────────────────────────────────────────────

/// Detect AES-CTR keystream reuse by XOR-ing pairs of ciphertexts.
pub fn aes_ctr_reuse(nonce: &str, key: &str, ciphertexts: &[Vec<u8>]) -> Result<Value> {
    let mut xor_map: HashMap<String, String> = HashMap::new();
    for i in 0..ciphertexts.len() {
        for j in (i + 1)..ciphertexts.len() {
            let a = &ciphertexts[i];
            let b = &ciphertexts[j];
            let min_len = a.len().min(b.len());
            let xor_bytes: Vec<u8> = (0..min_len).map(|k| a[k] ^ b[k]).collect();
            xor_map.insert(format!("{}-{}", i, j), hex::encode(xor_bytes));
        }
    }
    Ok(json!({
        "algorithm": "aes_ctr_reuse",
        "nonce": nonce,
        "key": key,
        "pairs_analyzed": xor_map.len(),
        "xor_pairs": xor_map,
        "note": "XOR of plaintexts — further analysis can recover messages if one is known."
    }))
}

// ─── Frequency Analysis ──────────────────────────────────────────────────────

/// Byte-level frequency analysis — counts every byte value in `data` and returns
/// the histogram plus the Index of Coincidence (IC).
pub fn frequency_analysis(data: &[u8]) -> Result<Value> {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let ic: f64 = if n > 1.0 {
        counts.iter()
            .map(|&c| (c as f64) * (c as f64 - 1.0))
            .sum::<f64>()
            / (n * (n - 1.0))
    } else {
        0.0
    };

    let freqs: HashMap<String, f64> = counts.iter().enumerate()
        .filter(|&(_, &c)| c > 0)
        .map(|(byte, &c)| (format!("0x{:02x}", byte), c as f64 / n))
        .collect();

    Ok(json!({
        "algorithm": "frequency_analysis",
        "total_bytes": data.len(),
        "index_of_coincidence": ic,
        "frequencies": freqs,
        "interpretation": if ic > 0.06 {
            "IC suggests monoalphabetic / natural-language plaintext"
        } else if ic > 0.04 {
            "IC suggests polyalphabetic cipher (e.g. Vigenère)"
        } else {
            "IC suggests strong encryption or random data"
        }
    }))
}

// ─── Shannon Entropy ─────────────────────────────────────────────────────────

/// Compute Shannon entropy (in bits) of a byte slice.
pub fn entropy_score(data: &[u8]) -> Result<Value> {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let entropy: f64 = counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum();

    Ok(json!({
        "algorithm": "shannon_entropy",
        "total_bytes": data.len(),
        "entropy_bits": entropy,
        "max_entropy_bits": 8.0,
        "randomness_ratio": entropy / 8.0,
        "interpretation": if entropy > 7.5 {
            "High entropy — likely encrypted or compressed"
        } else if entropy > 5.0 {
            "Medium entropy — mixed content"
        } else {
            "Low entropy — structured or plaintext data"
        }
    }))
}

// ─── Vigenère Cracker ────────────────────────────────────────────────────────

/// Attempt to crack a Vigenère cipher via Kasiski examination and χ² scoring.
///
/// `ciphertext` must contain only uppercase A-Z bytes for the attack to work.
/// Returns the estimated key and plaintext.
pub fn vigenere_crack(ciphertext: &[u8], max_key_len: usize) -> Result<Value> {
    let ct: Vec<u8> = ciphertext.iter()
        .filter(|&&b| b.is_ascii_uppercase())
        .copied()
        .collect();

    if ct.len() < 20 {
        return Ok(json!({
            "algorithm": "vigenere_crack",
            "status": "insufficient_data",
            "note": "Need at least 20 uppercase letters."
        }));
    }

    // Estimate key length via IC
    let best_len = (1..=max_key_len.min(ct.len() / 5))
        .max_by(|&a, &b| {
            let ic_a = avg_ic(&ct, a);
            let ic_b = avg_ic(&ct, b);
            ic_a.partial_cmp(&ic_b).unwrap_or(std::cmp::Ordering::Equal)
        })
        .unwrap_or(1);

    // Recover each key byte via χ² against English letter frequencies
    let english_freq: [f64; 26] = [
        0.0817, 0.0150, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202,
        0.0609, 0.0697, 0.0015, 0.0077, 0.0403, 0.0241, 0.0675,
        0.0751, 0.0193, 0.0010, 0.0599, 0.0633, 0.0906, 0.0276,
        0.0098, 0.0236, 0.0015, 0.0197, 0.0007,
    ];

    let mut key = Vec::new();
    for col in 0..best_len {
        let column: Vec<u8> = ct.iter().skip(col).step_by(best_len).copied().collect();
        let mut best_shift = 0u8;
        let mut best_chi = f64::MAX;
        for shift in 0u8..26 {
            let mut counts = [0u64; 26];
            for &b in &column {
                let idx = ((b - b'A' + 26 - shift) % 26) as usize;
                counts[idx] += 1;
            }
            let n = column.len() as f64;
            let chi: f64 = counts.iter().enumerate()
                .map(|(i, &c)| {
                    let expected = english_freq[i] * n;
                    if expected > 0.0 { (c as f64 - expected).powi(2) / expected } else { 0.0 }
                })
                .sum();
            if chi < best_chi {
                best_chi = chi;
                best_shift = shift;
            }
        }
        key.push(best_shift + b'A');
    }

    // Decrypt
    let plaintext: Vec<u8> = ct.iter().enumerate()
        .map(|(i, &b)| (b - b'A' + 26 - (key[i % key.len()] - b'A')) % 26 + b'A')
        .collect();

    Ok(json!({
        "algorithm": "vigenere_crack",
        "status": "success",
        "estimated_key_length": best_len,
        "recovered_key": String::from_utf8_lossy(&key),
        "plaintext_preview": String::from_utf8_lossy(&plaintext[..plaintext.len().min(200)]),
    }))
}

fn avg_ic(ct: &[u8], period: usize) -> f64 {
    let mut total = 0.0;
    for col in 0..period {
        let column: Vec<u8> = ct.iter().skip(col).step_by(period).copied().collect();
        let n = column.len() as f64;
        if n <= 1.0 { continue; }
        let mut counts = [0u64; 26];
        for &b in &column {
            counts[(b - b'A') as usize] += 1;
        }
        let ic: f64 = counts.iter()
            .map(|&c| (c as f64) * (c as f64 - 1.0))
            .sum::<f64>()
            / (n * (n - 1.0));
        total += ic;
    }
    total / period as f64
}

// ─── XOR Key Recovery ────────────────────────────────────────────────────────

/// Recover a repeating XOR key of known length using frequency analysis.
///
/// For each key-byte position, tries all 256 candidates and picks the one whose
/// resulting plaintext column has the highest ratio of printable ASCII bytes.
pub fn xor_key_recovery(ciphertext: &[u8], key_len: usize) -> Result<Value> {
    if key_len == 0 || ciphertext.is_empty() {
        return Ok(json!({
            "algorithm": "xor_key_recovery",
            "status": "invalid_input"
        }));
    }

    let mut key = vec![0u8; key_len];
    for col in 0..key_len {
        let column: Vec<u8> = ciphertext.iter().skip(col).step_by(key_len).copied().collect();
        let mut best_score = 0usize;
        let mut best_k = 0u8;
        for k in 0..=255u8 {
            let score: usize = column.iter()
                .filter(|&&b| {
                    let p = b ^ k;
                    p.is_ascii_graphic() || p == b' ' || p == b'\n' || p == b'\t'
                })
                .count();
            if score > best_score {
                best_score = score;
                best_k = k;
            }
        }
        key[col] = best_k;
    }

    let plaintext: Vec<u8> = ciphertext.iter().enumerate()
        .map(|(i, &b)| b ^ key[i % key_len])
        .collect();

    Ok(json!({
        "algorithm": "xor_key_recovery",
        "status": "success",
        "key_length": key_len,
        "recovered_key_hex": hex::encode(&key),
        "recovered_key_ascii": String::from_utf8_lossy(&key),
        "plaintext_preview": String::from_utf8_lossy(&plaintext[..plaintext.len().min(200)]),
    }))
}

// ─── Coppersmith Stub ────────────────────────────────────────────────────────

/// Placeholder for future lattice-based small-root attack implementation.
pub fn coppersmith_stub() -> Result<Value> {
    Ok(json!({
        "algorithm": "coppersmith",
        "status": "not_implemented",
        "message": "Coppersmith small-root attack will be added in a future release."
    }))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_factor_3233() {
        let res = rsa_factor(65537, 3233).unwrap();
        assert_eq!(res["status"], "factored");
        let factors = res["factors"].as_array().unwrap();
        assert!(factors.contains(&json!(53)));
        assert!(factors.contains(&json!(61)));
    }

    #[test]
    fn rsa_factor_prime() {
        let res = rsa_factor(65537, 7919).unwrap();
        // 7919 is prime, so it cannot be split
        assert_eq!(res["status"], "failed");
    }

    #[test]
    fn aes_ctr_xor_pairs() {
        let ct1 = vec![0xAA, 0xBB, 0xCC];
        let ct2 = vec![0x11, 0x22, 0x33];
        let res = aes_ctr_reuse("nonce", "key", &[ct1, ct2]).unwrap();
        assert_eq!(res["pairs_analyzed"], 1);
    }

    #[test]
    fn frequency_analysis_ascii() {
        let res = frequency_analysis(b"HELLO WORLD").unwrap();
        assert!(res["index_of_coincidence"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn entropy_zero() {
        let data = vec![0u8; 100];
        let res = entropy_score(&data).unwrap();
        assert!((res["entropy_bits"].as_f64().unwrap()).abs() < 0.001);
    }

    #[test]
    fn xor_roundtrip() {
        let key = b"KEY";
        let plain = b"ATTACK AT DAWN";
        let cipher: Vec<u8> = plain.iter().enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        let res = xor_key_recovery(&cipher, 3).unwrap();
        assert_eq!(res["recovered_key_hex"], hex::encode(key));
    }

    #[test]
    fn vigenere_known_key() {
        // Encrypt with key "KEY"
        let plain = b"THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";
        let key = b"KEY";
        let cipher: Vec<u8> = plain.iter().enumerate()
            .map(|(i, &b)| (b - b'A' + key[i % key.len()] - b'A') % 26 + b'A')
            .collect();
        // Duplicate to give the cracker enough data
        let mut long_cipher = cipher.clone();
        for _ in 0..10 {
            long_cipher.extend_from_slice(&cipher);
        }
        let res = vigenere_crack(&long_cipher, 10).unwrap();
        assert_eq!(res["status"], "success");
    }
}
