//! Electromagnetic (EM / HEMP / TEMPEST) & Nuclear/Radiation Hardware Effects Engine.
//!
//! Provides rigorous physics models for:
//! 1. **Maxwell Skin Depth & Faraday Shielding Effectiveness (SE)**
//! 2. **IEC 61000-2-9 HEMP E1/E2/E3 Double-Exponential Pulse & PCB Coupling**
//! 3. **TEMPEST / Van Eck Unintentional EM Emanation SNR & Detectability**
//! 4. **Single-Event Effects (SEU / SEL) Weibull Cross-Section & Soft Error Rate (FIT)**
//! 5. **Total Ionizing Dose (TID) MOSFET Threshold Shift & Critical Charge ($Q_{crit}$)**

use serde::Serialize;
use std::f64::consts::PI;

const MU_0: f64 = 4.0 * PI * 1e-7; // Vacuum permeability (H/m)
const EPS_0: f64 = 8.854_187_817e-12; // Vacuum permittivity (F/m)
const Z_0: f64 = 376.730_313_668; // Free-space wave impedance (Ohms)

// ═══════════════════════════════════════════════════════════════════
//  1. Maxwell Skin Depth & Faraday Shielding Effectiveness
// ═══════════════════════════════════════════════════════════════════

/// Electromagnetic skin depth δ = √(2 / (ω · μ · σ)) in meters.
pub fn skin_depth_m(freq_hz: f64, rel_permeability: f64, conductivity_s_m: f64) -> f64 {
    if freq_hz <= 0.0 || rel_permeability <= 0.0 || conductivity_s_m <= 0.0 {
        return f64::INFINITY;
    }
    let omega = 2.0 * PI * freq_hz;
    let mu = MU_0 * rel_permeability;
    (2.0 / (omega * mu * conductivity_s_m)).sqrt()
}

/// Faraday shield effectiveness (SE in dB) = Absorption (A) + Reflection (R) + Multiple-Reflection (B).
/// Models a conductive barrier of `thickness_m` against a plane wave at `freq_hz`.
#[derive(Debug, Clone, Serialize)]
pub struct ShieldingResult {
    pub skin_depth_mm: f64,
    pub absorption_db: f64,
    pub reflection_db: f64,
    pub multi_reflection_db: f64,
    pub total_se_db: f64,
}

pub fn faraday_shielding_db(
    freq_hz: f64,
    thickness_m: f64,
    rel_permeability: f64,
    conductivity_s_m: f64,
) -> ShieldingResult {
    let delta = skin_depth_m(freq_hz, rel_permeability, conductivity_s_m);
    let absorption_db = if delta.is_finite() && delta > 0.0 {
        8.686 * (thickness_m / delta)
    } else {
        0.0
    };
    // Plane-wave reflection loss: R = 168 + 10*log10(sigma_r / (mu_r * f))
    let sigma_cu = 5.8e7_f64;
    let sigma_r = conductivity_s_m / sigma_cu;
    let reflection_db = if freq_hz > 0.0 && sigma_r > 0.0 {
        168.0 + 10.0 * (sigma_r / (rel_permeability * freq_hz)).log10()
    } else {
        0.0
    };
    // Correction factor B for electrically thin shields (A < 15 dB)
    let multi_reflection_db = if absorption_db < 15.0 && delta.is_finite() && delta > 0.0 {
        20.0 * (1.0 - (-2.0 * thickness_m / delta).exp()).abs().max(1e-12).log10()
    } else {
        0.0
    };
    ShieldingResult {
        skin_depth_mm: delta * 1000.0,
        absorption_db,
        reflection_db,
        multi_reflection_db,
        total_se_db: (absorption_db + reflection_db + multi_reflection_db).max(0.0),
    }
}

// ═══════════════════════════════════════════════════════════════════
//  2. HEMP (IEC 61000-2-9) Double-Exponential Pulse & PCB Coupling
// ═══════════════════════════════════════════════════════════════════

/// IEC 61000-2-9 E1 HEMP electric field at time t (seconds):
///   E(t) = E₀ · k · (e^(-α·t) − e^(-β·t))
/// Standard E1 parameters: E₀ = 50_000 V/m, k = 1.3, α = 4e7 s⁻¹, β = 6e8 s⁻¹.
pub fn hemp_e1_field_v_m(t_sec: f64, e0_v_m: f64, k: f64, alpha: f64, beta: f64) -> f64 {
    if t_sec < 0.0 {
        return 0.0;
    }
    e0_v_m * k * ((-alpha * t_sec).exp() - (-beta * t_sec).exp())
}

/// Peak induced transient voltage on an unshielded PCB loop/trace exposed to HEMP E1:
///   V_ind_peak ≈ E_peak · L_eff · (1 - 10^(-SE/20)) + A_loop · μ₀ · (dH/dt)_max
pub fn hemp_induced_pcb_voltage(
    e0_v_m: f64,
    trace_len_m: f64,
    loop_area_m2: f64,
    shield_se_db: f64,
    rise_time_s: f64,
) -> f64 {
    let atten = 10.0_f64.powf(-shield_se_db / 20.0);
    let e_eff = e0_v_m * atten;
    let h_peak = e_eff / Z_0;
    let dh_dt = if rise_time_s > 0.0 { h_peak / rise_time_s } else { 0.0 };
    (e_eff * trace_len_m) + (loop_area_m2 * MU_0 * dh_dt)
}

// ═══════════════════════════════════════════════════════════════════
//  3. TEMPEST / Van Eck Electromagnetic Emanation Model
// ═══════════════════════════════════════════════════════════════════

/// Near-field / far-field boundary (radiansphere): r = λ / (2π).
pub fn radiansphere_m(freq_hz: f64) -> f64 {
    if freq_hz <= 0.0 { return 0.0; }
    let lambda = 299_792_458.0 / freq_hz;
    lambda / (2.0 * PI)
}

/// Estimates TEMPEST eavesdropping SNR (dB) at distance `d_m` from a radiating
/// bus/clock trace with harmonic current `i_harm_a`, trace length `l_m`,
/// enclosure shielding `se_db`, receiver bandwidth `bw_hz`, and noise figure `nf_db`.
pub fn tempest_eavesdrop_snr_db(
    freq_hz: f64,
    i_harm_a: f64,
    trace_len_m: f64,
    distance_m: f64,
    shield_se_db: f64,
    rx_bw_hz: f64,
    rx_nf_db: f64,
) -> f64 {
    let e_unshielded = (Z_0 * i_harm_a * freq_hz * trace_len_m)
        / (2.0 * 299_792_458.0 * distance_m.max(0.01));
    let e_rx = e_unshielded * 10.0_f64.powf(-shield_se_db / 20.0);
    // Effective aperture of half-wave dipole: A_e ≈ 0.13 * λ²
    let lambda = 299_792_458.0 / freq_hz.max(1.0);
    let p_rx_w = (e_rx.powi(2) / Z_0) * (0.13 * lambda.powi(2));
    let p_rx_dbm = 10.0 * (p_rx_w * 1000.0).max(1e-30).log10();
    // Thermal noise floor: -174 dBm/Hz + 10*log10(BW) + NF
    let noise_dbm = -174.0 + 10.0 * rx_bw_hz.max(1.0).log10() + rx_nf_db;
    p_rx_dbm - noise_dbm
}

// ═══════════════════════════════════════════════════════════════════
//  4. Nuclear / Radiation Hardware Effects (SEU, SEL, TID, FIT)
// ═══════════════════════════════════════════════════════════════════

/// Weibull Single-Event Upset (SEU) / Latchup (SEL) cross-section σ(LET):
///   σ(L) = σ_sat · [1 − exp( −((L − L_th) / W)^s )]   for L > L_th
/// Returns cross-section in cm²/bit (or cm²/device).
pub fn weibull_see_cross_section(
    let_mev_cm2_mg: f64,
    sigma_sat: f64,
    let_threshold: f64,
    width_w: f64,
    shape_s: f64,
) -> f64 {
    if let_mev_cm2_mg <= let_threshold || width_w <= 0.0 {
        return 0.0;
    }
    let ratio = (let_mev_cm2_mg - let_threshold) / width_w;
    sigma_sat * (1.0 - (-ratio.powf(shape_s)).exp())
}

/// Soft Error Rate (SER) in FIT (Failures In Time = failures per 10⁹ device-hours)
/// given particle flux (particles / cm² / s), Weibull cross-section (cm²/bit), and `num_bits`.
pub fn soft_error_rate_fit(flux_cm2_s: f64, sigma_cm2_bit: f64, num_bits: u64) -> f64 {
    let rate_per_sec = flux_cm2_s * sigma_cm2_bit * (num_bits as f64);
    rate_per_sec * 3600.0 * 1e9
}

/// Critical charge Q_crit (fC) required to flip an SRAM/logic node vs node capacitance (fF) and Vdd (V):
///   Q_crit ≈ C_node · V_dd / 2   (first-order charge collection threshold)
/// Also converts deposited energy from Linear Energy Transfer (LET in MeV·cm²/mg) over path `t_si_um`:
///   Q_dep (fC) ≈ 10.35 · LET · t_si_um  (in Silicon: 1 MeV·cm²/mg ≈ 10.35 fC/µm)
#[derive(Debug, Clone, Serialize)]
pub struct RadiationBitFlipAssessment {
    pub q_crit_fc: f64,
    pub q_deposited_fc: f64,
    pub bit_flip_possible: bool,
    pub safety_margin_ratio: f64,
}

pub fn assess_radiation_bit_flip(
    node_cap_ff: f64,
    v_dd: f64,
    let_mev_cm2_mg: f64,
    silicon_collection_um: f64,
) -> RadiationBitFlipAssessment {
    let q_crit_fc = 0.5 * node_cap_ff * v_dd;
    let q_deposited_fc = 10.35 * let_mev_cm2_mg * silicon_collection_um;
    let safety_margin_ratio = if q_deposited_fc > 0.0 { q_crit_fc / q_deposited_fc } else { f64::INFINITY };
    RadiationBitFlipAssessment {
        q_crit_fc,
        q_deposited_fc,
        bit_flip_possible: q_deposited_fc >= q_crit_fc,
        safety_margin_ratio,
    }
}

/// Total Ionizing Dose (TID) MOSFET threshold voltage shift ΔV_th (Volts):
///   ΔV_th ≈ -k_tid · D_rad^α   (oxide trapped hole charge + interface states)
/// `dose_krad`: accumulated dose in krad(Si); `k_tid`: process sensitivity (V/krad^α).
pub fn tid_threshold_shift_v(dose_krad: f64, k_tid: f64, alpha: f64) -> f64 {
    if dose_krad <= 0.0 { return 0.0; }
    -k_tid * dose_krad.powf(alpha)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copper_skin_depth_at_1ghz() {
        // Copper: sigma = 5.8e7 S/m, mu_r = 1 -> delta ~ 2.09 um
        let d = skin_depth_m(1e9, 1.0, 5.8e7);
        assert!(d > 1.5e-6 && d < 3.0e-6);
    }

    #[test]
    fn faraday_shield_attenuates_high_freq() {
        let se = faraday_shielding_db(1e9, 0.001, 1.0, 5.8e7);
        assert!(se.total_se_db > 100.0);
    }

    #[test]
    fn hemp_pulse_peaks_and_decays() {
        let e_early = hemp_e1_field_v_m(4e-9, 50_000.0, 1.3, 4e7, 6e8);
        let e_late = hemp_e1_field_v_m(1e-6, 50_000.0, 1.3, 4e7, 6e8);
        assert!(e_early > 30_000.0);
        assert!(e_late < 1.0);
    }

    #[test]
    fn radiation_seu_assessment() {
        let res = assess_radiation_bit_flip(2.0, 1.2, 15.0, 1.0);
        assert!(res.bit_flip_possible);
        let fit = soft_error_rate_fit(0.01, weibull_see_cross_section(15.0, 1e-8, 2.0, 10.0, 1.5), 1_000_000);
        assert!(fit > 0.0);
    }

    #[test]
    fn nano_cmos_and_lfi_models() {
        let cg = cmos_gate_capacitance_ff(5.0, 20.0, 1.2, 3.9);
        assert!(cg > 0.0);
        let mttf = electromigration_mttf_hours(1e6, 2.0, 0.7, 350.0, 1e12);
        assert!(mttf > 0.0);
        let lfi = laser_fault_spot_irradiance_w_cm2(1e-3, 10e-9, 2.0);
        assert!(lfi > 1e6);
    }
}

// ═══════════════════════════════════════════════════════════════════
//  5. Nanometer / Micrometer Silicon, LFI & Power-Rail RLC Models
// ═══════════════════════════════════════════════════════════════════

/// Nanometer-scale MOSFET gate capacitance (in femtofarads, fF):
///   C_g = ε_0 · ε_r · (W_nm · L_nm) / t_ox_nm · 1e-9 · 1e15
pub fn cmos_gate_capacitance_ff(l_gate_nm: f64, w_gate_nm: f64, t_ox_nm: f64, eps_r: f64) -> f64 {
    if t_ox_nm <= 0.0 { return 0.0; }
    let area_m2 = (l_gate_nm * 1e-9) * (w_gate_nm * 1e-9);
    let t_m = t_ox_nm * 1e-9;
    (EPS_0 * eps_r * area_m2 / t_m) * 1e15
}

/// Black's Equation for Electromigration Mean-Time-To-Failure (MTTF in hours) on nm/µm power rails:
///   MTTF = A · J^(-n) · exp(E_a / (k_B · T))
pub fn electromigration_mttf_hours(
    current_density_a_cm2: f64,
    n_exp: f64,
    activation_energy_ev: f64,
    temp_kelvin: f64,
    material_const_a: f64,
) -> f64 {
    if current_density_a_cm2 <= 0.0 || temp_kelvin <= 0.0 { return f64::INFINITY; }
    let k_b_ev_k = 8.617_333_262e-5_f64;
    material_const_a
        * current_density_a_cm2.powf(-n_exp)
        * (activation_energy_ev / (k_b_ev_k * temp_kelvin)).exp()
}

/// Focused Laser Fault Injection (LFI) peak irradiance (W/cm²) for micrometer spot diameter:
///   I_peak = (E_pulse / τ_pulse) / (π · (d_spot_µm / 2)²)
pub fn laser_fault_spot_irradiance_w_cm2(
    pulse_energy_j: f64,
    pulse_width_s: f64,
    spot_diameter_um: f64,
) -> f64 {
    if pulse_width_s <= 0.0 || spot_diameter_um <= 0.0 { return 0.0; }
    let p_peak_w = pulse_energy_j / pulse_width_s;
    let r_cm = (spot_diameter_um * 1e-4) / 2.0;
    let area_cm2 = PI * r_cm * r_cm;
    p_peak_w / area_cm2
}

/// Power-rail RLC crowbar glitch transient voltage V(t) underdamped ring-down (Volts):
///   V(t) = V_dd - ΔV · e^(-ζ·ω_0·t) · cos(ω_d·t)
pub fn power_rail_rlc_transient_v(
    t_sec: f64,
    v_dd: f64,
    delta_v: f64,
    r_ohm: f64,
    l_henry: f64,
    c_farad: f64,
) -> f64 {
    if t_sec < 0.0 || l_henry <= 0.0 || c_farad <= 0.0 { return v_dd; }
    let omega_0 = 1.0 / (l_henry * c_farad).sqrt();
    let alpha = r_ohm / (2.0 * l_henry);
    let omega_d = (omega_0 * omega_0 - alpha * alpha).max(0.0).sqrt();
    v_dd - delta_v * (-alpha * t_sec).exp() * (omega_d * t_sec).cos()
}
