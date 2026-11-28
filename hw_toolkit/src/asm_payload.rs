//! Low-Level Multi-Architecture Inline Assembly (`core::arch::asm!`) Engine.
//!
//! Supports **x86_64** (Intel/AMD) and **aarch64** (ARM64 Mobile/Embedded CPUs).
//! - Timing & Speculative Cache-Side-Channel Oracles (`rdtscp` / `cntvct_el0`)
//! - Raw Hardware Security Feature Enumeration (`cpuid` / `id_aa64isar0_el1`)
//! - Cycle-Accurate Glitch Window Calibrator
//! - Direct Port I/O UART Bit-Banging (requires `#[cfg(feature = "asm")]` + Ring-0/IOPM)

use core::arch::asm;
use serde::Serialize;

// ═══════════════════════════════════════════════════════════════════
//  x86_64 Inline Assembly Primitives
// ═══════════════════════════════════════════════════════════════════

#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone, Serialize)]
pub struct X86HardwareSecurityCaps {
    pub vendor: String,
    pub max_leaf: u32,
    pub has_aes_ni: bool,
    pub has_rdrand: bool,
    pub has_avx: bool,
    pub has_avx2: bool,
    pub has_sgx: bool,
    pub has_smep: bool,
    pub has_smap: bool,
    pub hypervisor_present: bool,
}

/// Executes raw `cpuid` instructions via inline ASM to fingerprint CPU security extensions.
#[cfg(target_arch = "x86_64")]
pub fn asm_cpuid_security_caps() -> X86HardwareSecurityCaps {
    let (max_leaf, ebx0, ecx0, edx0) = raw_cpuid(0, 0);
    let mut vendor_bytes = [0u8; 12];
    vendor_bytes[0..4].copy_from_slice(&ebx0.to_le_bytes());
    vendor_bytes[4..8].copy_from_slice(&edx0.to_le_bytes());
    vendor_bytes[8..12].copy_from_slice(&ecx0.to_le_bytes());
    let vendor = String::from_utf8_lossy(&vendor_bytes).to_string();

    let (_, _, ecx1, _) = if max_leaf >= 1 { raw_cpuid(1, 0) } else { (0, 0, 0, 0) };
    let (_, ebx7, _, _) = if max_leaf >= 7 { raw_cpuid(7, 0) } else { (0, 0, 0, 0) };

    X86HardwareSecurityCaps {
        vendor,
        max_leaf,
        has_aes_ni: (ecx1 & (1 << 25)) != 0,
        has_avx: (ecx1 & (1 << 28)) != 0,
        has_rdrand: (ecx1 & (1 << 30)) != 0,
        hypervisor_present: (ecx1 & (1 << 31)) != 0,
        has_sgx: (ebx7 & (1 << 2)) != 0,
        has_avx2: (ebx7 & (1 << 5)) != 0,
        has_smep: (ebx7 & (1 << 7)) != 0,
        has_smap: (ebx7 & (1 << 20)) != 0,
    }
}

/// Raw `cpuid` wrapper preserving `rbx` (required by LLVM on x86_64).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn raw_cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            inout("ecx") subleaf => ecx,
            ebx_out = out(reg) ebx,
            lateout("edx") edx,
            options(nostack, preserves_flags),
        );
    }
    (eax, ebx, ecx, edx)
}

/// Serialized cycle-accurate timestamp using `mfence; lfence; rdtscp`.
/// Used for cache Flush+Reload / Spectre timing side-channel measurements.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn asm_rdtscp_serialized() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        asm!(
            "mfence",
            "lfence",
            "rdtscp",
            "lfence",
            out("eax") lo,
            out("edx") hi,
            out("ecx") _,
            options(nomem, nostack),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Measures memory-access latency (cycles) for a pointer, flushing its cache line first
/// via `clflush` — core primitive of Flush+Reload cache side-channel analysis.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
pub unsafe fn asm_flush_and_probe_cycles(addr: *const u8) -> u64 {
    asm!("clflush [{0}]", "mfence", in(reg) addr, options(nostack));
    let t0 = asm_rdtscp_serialized();
    let _val: u8;
    asm!("mov {0}, byte ptr [{1}]", out(reg_byte) _val, in(reg) addr, options(readonly, nostack));
    let t1 = asm_rdtscp_serialized();
    t1.saturating_sub(t0)
}

/// Measures cached vs uncached memory-access threshold on the host CPU.
#[cfg(target_arch = "x86_64")]
pub fn calibrate_cache_timing_threshold() -> (u64, u64) {
    let probe: u8 = 0x42;
    let ptr = &probe as *const u8;
    // Warm hit
    let t0 = asm_rdtscp_serialized();
    let _ = unsafe { core::ptr::read_volatile(ptr) };
    let hit_cycles = asm_rdtscp_serialized().saturating_sub(t0);
    // Cold miss after clflush
    let miss_cycles = unsafe { asm_flush_and_probe_cycles(ptr) };
    (hit_cycles, miss_cycles)
}

/// Cycle-accurate busy-wait spin loop using `rdtsc` for glitch-pulse windowing.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn asm_spin_cycles(cycles: u64) {
    let start = asm_rdtscp_serialized();
    while asm_rdtscp_serialized().saturating_sub(start) < cycles {
        unsafe { asm!("pause", options(nomem, nostack)) };
    }
}

/// Bit-bang a UART payload over an x86 I/O port (`out dx, al`).
///
/// *Safety*: Direct port I/O requires Ring-0 or granted I/O permission bitmap.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub unsafe fn inject_uart_io_port(payload: &[u8], tx_port: u16, cycles_per_bit: u64) {
    for &b in payload {
        asm!("out dx, al", in("dx") tx_port, in("al") 0u8, options(nomem, nostack));
        asm_spin_cycles(cycles_per_bit);
        for i in 0..8 {
            let bit = (b >> i) & 1;
            asm!("out dx, al", in("dx") tx_port, in("al") bit, options(nomem, nostack));
            asm_spin_cycles(cycles_per_bit);
        }
        asm!("out dx, al", in("dx") tx_port, in("al") 1u8, options(nomem, nostack));
        asm_spin_cycles(cycles_per_bit);
    }
}

// ═══════════════════════════════════════════════════════════════════
//  ARM64 (aarch64 Mobile / Embedded) Inline Assembly Primitives
// ═══════════════════════════════════════════════════════════════════

#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn asm_arm64_cntvct() -> u64 {
    let cnt: u64;
    unsafe {
        asm!(
            "isb",
            "mrs {0}, cntvct_el0",
            "isb",
            out(reg) cnt,
            options(nomem, nostack),
        );
    }
    cnt
}

#[cfg(target_arch = "aarch64")]
#[inline(never)]
pub unsafe fn asm_arm64_flush_and_probe(addr: *const u8) -> u64 {
    asm!("dc civac, {0}", "dsb sy", "isb", in(reg) addr, options(nostack));
    let t0 = asm_arm64_cntvct();
    let _val: u8;
    asm!("ldrb {0:w}, [{1}]", out(reg) _val, in(reg) addr, options(readonly, nostack));
    let t1 = asm_arm64_cntvct();
    t1.saturating_sub(t0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn cpuid_returns_valid_vendor() {
        let caps = asm_cpuid_security_caps();
        assert_eq!(caps.vendor.len(), 12);
        assert!(caps.max_leaf >= 1);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn rdtscp_is_monotonic() {
        let t0 = asm_rdtscp_serialized();
        asm_spin_cycles(500);
        let t1 = asm_rdtscp_serialized();
        assert!(t1 > t0);
    }

    #[test]
    fn glitch_pulse_plan_builds() {
        let seq = build_nanosecond_glitch_sequence(3_000_000_000.0, 25.0, 100.0);
        assert_eq!(seq.pulse_cycles, 75);
        assert_eq!(seq.cooldown_cycles, 300);
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Nanosecond Power-Rail Glitch Sequencer & Multi-Arch ASM Payloads
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct GlitchCycleTiming {
    pub cpu_freq_hz: f64,
    pub pulse_ns: f64,
    pub cooldown_ns: f64,
    pub pulse_cycles: u64,
    pub cooldown_cycles: u64,
}

/// Converts nanosecond glitch-pulse & cooldown widths into exact CPU clock cycles.
pub fn build_nanosecond_glitch_sequence(
    cpu_freq_hz: f64,
    pulse_ns: f64,
    cooldown_ns: f64,
) -> GlitchCycleTiming {
    let pulse_cycles = ((cpu_freq_hz * pulse_ns * 1e-9).round() as u64).max(1);
    let cooldown_cycles = ((cpu_freq_hz * cooldown_ns * 1e-9).round() as u64).max(1);
    GlitchCycleTiming {
        cpu_freq_hz,
        pulse_ns,
        cooldown_ns,
        pulse_cycles,
        cooldown_cycles,
    }
}

/// Executes a nanosecond-calibrated crowbar glitch pulse over an x86 I/O power-control port.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub unsafe fn asm_power_rail_crowbar_pulse(ctrl_port: u16, assert_val: u8, release_val: u8, timing: &GlitchCycleTiming) {
    asm!("out dx, al", in("dx") ctrl_port, in("al") assert_val, options(nomem, nostack));
    asm_spin_cycles(timing.pulse_cycles);
    asm!("out dx, al", in("dx") ctrl_port, in("al") release_val, options(nomem, nostack));
    asm_spin_cycles(timing.cooldown_cycles);
}

/// Target architecture for raw ASM diagnostic/testbench payload generation.
#[derive(Debug, Clone, Copy, Serialize)]
pub enum TargetArch {
    X86_64,
    Aarch64,
    ArmThumb2CortexM,
}

/// Generates cycle-accurate ASM diagnostic / fault-harness byte sequences for lab targets.
pub fn generate_asm_test_stub(arch: TargetArch, iterations: u8) -> Vec<u8> {
    match arch {
        // x86_64: rdtscp + mfence + nop sled + ret
        TargetArch::X86_64 => {
            let mut code = vec![0x0F, 0xAE, 0xF0, 0x0F, 0x01, 0xF9]; // mfence; rdtscp
            code.extend(std::iter::repeat_n(0x90, iterations as usize)); // nop sled
            code.push(0xC3); // ret
            code
        }
        // aarch64: isb; mrs x0, cntvct_el0; nop...; ret
        TargetArch::Aarch64 => {
            let mut code = vec![0xDF, 0x3F, 0x03, 0xD5, 0x00, 0xE0, 0x3B, 0xD5];
            for _ in 0..iterations {
                code.extend_from_slice(&[0x1F, 0x20, 0x03, 0xD5]); // nop
            }
            code.extend_from_slice(&[0xC0, 0x03, 0x5F, 0xD6]); // ret
            code
        }
        // ARM Thumb-2 (Cortex-M): dsb; isb; nop...; bx lr
        TargetArch::ArmThumb2CortexM => {
            let mut code = vec![0xBF, 0xF3, 0x4F, 0x8F, 0xBF, 0xF3, 0x6F, 0x8F];
            for _ in 0..iterations {
                code.extend_from_slice(&[0x00, 0xBF]); // nop
            }
            code.extend_from_slice(&[0x70, 0x47]); // bx lr
            code
        }
    }
}
