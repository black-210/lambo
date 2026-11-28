use serde::Serialize;

// ═══════════════════════════════════════════════════════════════════
//  Hardware Vulnerability Database
//  Covers: Physical, Software, RF, Protocol, Architecture
// ═══════════════════════════════════════════════════════════════════

/// Severity classification following CVSS v3.1 ranges.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum Severity {
    Critical,   // 9.0 – 10.0
    High,       // 7.0 – 8.9
    Medium,     // 4.0 – 6.9
    Low,        // 0.1 – 3.9
    Info,       // 0.0
}

/// Category of hardware vulnerability.
#[derive(Debug, Clone, Serialize)]
pub enum VulnCategory {
    Physical,       // Fault injection, probing, decapping
    SideChannel,    // Power, EM, timing, acoustic
    RF,             // Wireless jamming, replay, replay, injection
    Protocol,       // Bus (JTAG, UART, SPI, I2C, USB) exploitation
    Firmware,       // Bootloader, flash, microcode
    Architecture,   // Spectre, Meltdown, SGX, TrustZone
    Supply,         // Counterfeit, trojan, tampering
}

/// A single vulnerability entry in the database.
#[derive(Debug, Clone, Serialize)]
pub struct HardwareVuln {
    pub id: &'static str,
    pub name: &'static str,
    pub category: VulnCategory,
    pub severity: Severity,
    pub cvss_score: f32,
    pub description: &'static str,
    pub affected_targets: &'static [&'static str],
    pub attack_vector: &'static str,
    pub mitigation: &'static str,
    pub references: &'static [&'static str],
}

/// Full static vulnerability database.
pub fn vuln_database() -> Vec<HardwareVuln> {
    vec![
        // ── Physical Fault Injection ─────────────────────────────
        HardwareVuln {
            id: "HW-PHYS-001",
            name: "Voltage Glitch Fault Injection",
            category: VulnCategory::Physical,
            severity: Severity::Critical,
            cvss_score: 9.3,
            description: "An attacker applies a sharp voltage drop (typically 50–500 mV, \
                1–100 ns width) on the VDD rail, causing the CPU to skip an instruction \
                or corrupt register state. Can bypass secure‑boot signature checks.",
            affected_targets: &["STM32", "ESP32", "ARM Cortex-M", "AVR", "FPGA"],
            attack_vector: "Physical access to power rail (via capacitor removal or \
                crowbar circuit on VDD)",
            mitigation: "Voltage supervisor IC, power-rail filtering caps, VDD \
                sensor + secure lockdown firmware",
            references: &[
                "https://tches.iacr.org/index.php/TCHES/article/view/9312",
                "https://doi.org/10.1109/HST.2019.8740836",
            ],
        },
        HardwareVuln {
            id: "HW-PHYS-002",
            name: "Clock Glitch Fault Injection",
            category: VulnCategory::Physical,
            severity: Severity::Critical,
            cvss_score: 9.1,
            description: "Injecting a spurious clock pulse (or stretching/compressing \
                the clock period) causes the CPU pipeline to malfunction, potentially \
                producing incorrect branch decisions or skipping instructions.",
            affected_targets: &["All synchronous digital ICs"],
            attack_vector: "Physical clock line access; clock edge manipulation via \
                FPGA glitcher or dedicated ChipWhisperer hardware",
            mitigation: "Clock integrity monitoring, internal RC oscillator \
                (no external clock pin), code-based detection guards",
            references: &["https://link.springer.com/chapter/10.1007/978-3-030-51280-4_7"],
        },
        HardwareVuln {
            id: "HW-PHYS-003",
            name: "Laser Fault Injection (LFI)",
            category: VulnCategory::Physical,
            severity: Severity::Critical,
            cvss_score: 9.5,
            description: "A focused laser beam aimed at decapped or thinned silicon \
                induces transient faults in specific logic gates or SRAM cells. \
                Sub-micron targeting allows arbitrary bit manipulation.",
            affected_targets: &["Smart cards", "HSMs", "Secure elements", "MCUs"],
            attack_vector: "Laser workstation, optical microscope; requires die \
                exposure (decapping or backside thinning)",
            mitigation: "Light sensors, active shield mesh, dummy decoy logic",
            references: &["https://doi.org/10.1109/ACCESS.2021.3060619"],
        },
        HardwareVuln {
            id: "HW-PHYS-004",
            name: "EM Fault Injection (EMFI)",
            category: VulnCategory::Physical,
            severity: Severity::High,
            cvss_score: 8.5,
            description: "A pulsed electromagnetic field applied near the IC surface \
                induces transient currents in internal conductors, causing logic faults \
                similar to voltage or clock glitching without direct contact.",
            affected_targets: &["All ICs", "especially surface-exposed MCUs"],
            attack_vector: "EM probe coil (25–200 mm²) + pulser, 1–50 mm distance",
            mitigation: "Metal shielding/Faraday cage, EM-aware routing, power filters",
            references: &["https://tches.iacr.org/index.php/TCHES/article/view/9318"],
        },
        // ── Side Channel ────────────────────────────────────────────
        HardwareVuln {
            id: "HW-SC-001",
            name: "Simple Power Analysis (SPA)",
            category: VulnCategory::SideChannel,
            severity: Severity::High,
            cvss_score: 7.5,
            description: "Direct visual inspection of power consumption waveforms reveals \
                secret key bits by identifying branch-dependent power patterns in \
                cryptographic algorithms (RSA, ECC square-and-multiply).",
            affected_targets: &["RSA", "ECC", "DES", "unprotected AES"],
            attack_vector: "Current‑sensing resistor (0.5–10 Ω) or EM probe on power pin",
            mitigation: "Constant-time / data-independent implementations, \
                power-noise injection",
            references: &["https://link.springer.com/article/10.1007/s001459900030"],
        },
        HardwareVuln {
            id: "HW-SC-002",
            name: "Differential Power Analysis (DPA)",
            category: VulnCategory::SideChannel,
            severity: Severity::Critical,
            cvss_score: 9.0,
            description: "Statistical analysis of hundreds to thousands of power traces \
                using Pearson correlation or difference‑of‑means reveals AES, DES, \
                or other block cipher keys with minimal physical access.",
            affected_targets: &["AES-128", "AES-256", "DES", "3DES", "SM4"],
            attack_vector: "Oscilloscope ≥ 500 MHz, 50–10,000 power traces, \
                known plaintexts",
            mitigation: "Masking schemes, shuffling, threshold implementations, \
                SIKE side‑channel countermeasures",
            references: &["https://link.springer.com/chapter/10.1007/3-540-48405-1_25"],
        },
        HardwareVuln {
            id: "HW-SC-003",
            name: "Electromagnetic Side‑Channel (EMA)",
            category: VulnCategory::SideChannel,
            severity: Severity::High,
            cvss_score: 8.0,
            description: "Local EM emissions from switching transistors leak key-dependent \
                information. EM probes can achieve finer spatial resolution than power \
                measurements, enabling attacks on specific logic blocks.",
            affected_targets: &["All CMOS ICs", "especially BGAs and QFNs"],
            attack_vector: "Near-field EM probe (H-field, 1–5 mm loop) + oscilloscope",
            mitigation: "On-chip metal shielding, balanced logic styles, \
                EM-aware floorplanning",
            references: &["https://www.iacr.org/archive/ches2001/21040251.pdf"],
        },
        HardwareVuln {
            id: "HW-SC-004",
            name: "Timing Side‑Channel",
            category: VulnCategory::SideChannel,
            severity: Severity::High,
            cvss_score: 7.8,
            description: "Data-dependent execution time of cryptographic operations (early \
                exit, table lookup latency, branch prediction) allows remote or local \
                key recovery without any physical access.",
            affected_targets: &["OpenSSL RSA", "AES T-table", "modular exponentiation"],
            attack_vector: "High-precision timer (rdtsc, performance counters), \
                statistical analysis of millions of measurements",
            mitigation: "Constant-time implementations, blinding, \
                clock randomisation",
            references: &["https://cr.yp.to/antiforgery/cachetiming-20050414.pdf"],
        },
        // ── Architecture ─────────────────────────────────────────────
        HardwareVuln {
            id: "HW-ARCH-001",
            name: "Spectre v1 (Bounds Check Bypass)",
            category: VulnCategory::Architecture,
            severity: Severity::High,
            cvss_score: 8.1,
            description: "Speculative execution past a bounds check allows an attacker \
                to infer out-of-bounds memory contents via cache timing, breaking \
                process isolation on x86 and ARM.",
            affected_targets: &["Intel Core (all gen)", "AMD Zen", "ARM Cortex-A"],
            attack_vector: "Unprivileged code execution on shared CPU core",
            mitigation: "Serialising barriers (LFENCE), index masking, \
                array_index_mask_nospec()",
            references: &["https://spectreattack.com/spectre.pdf"],
        },
        HardwareVuln {
            id: "HW-ARCH-002",
            name: "Meltdown (Rogue Data Cache Load)",
            category: VulnCategory::Architecture,
            severity: Severity::Critical,
            cvss_score: 9.8,
            description: "Exploits out-of-order execution to read kernel memory from \
                user space. Affects Intel CPUs and some ARM Cortex-A cores without \
                KPTI mitigation.",
            affected_targets: &["Intel Core pre-2018", "ARM Cortex-A75"],
            attack_vector: "Unprivileged user process",
            mitigation: "KPTI (Kernel Page Table Isolation), microcode update",
            references: &["https://meltdownattack.com/meltdown.pdf"],
        },
        HardwareVuln {
            id: "HW-ARCH-003",
            name: "Rowhammer DRAM Bit Flip",
            category: VulnCategory::Architecture,
            severity: Severity::High,
            cvss_score: 8.1,
            description: "Repeatedly reading adjacent DRAM rows causes bit flips in \
                target rows due to capacitive coupling, allowing privilege escalation \
                or cryptographic key corruption.",
            affected_targets: &["LPDDR3", "LPDDR4", "DDR3", "DDR4 (TRR bypass)"],
            attack_vector: "Unprivileged memory access patterns (clflush + mov)",
            mitigation: "ECC DRAM, LPDDR4X TRR (Target Row Refresh), \
                memory controller mitigations",
            references: &["https://users.ece.cmu.edu/~yoonguk/papers/kim-isca14.pdf"],
        },
        HardwareVuln {
            id: "HW-ARCH-004",
            name: "Intel SGX Side‑Channel (SGAxe / CacheOut)",
            category: VulnCategory::Architecture,
            severity: Severity::Critical,
            cvss_score: 9.0,
            description: "Cache-based side channels break Intel SGX enclave confidentiality, \
                allowing the extraction of AES keys and RSA private keys from enclaves.",
            affected_targets: &["Intel SGX (all versions)"],
            attack_vector: "Privileged attacker or co-located hypervisor",
            mitigation: "Microcode update, SGX version 2 attestation, \
                constant-time enclave code",
            references: &[
                "https://sgaxe.com/files/SGAxe.pdf",
                "https://cacheoutattack.com/CacheOut.pdf",
            ],
        },
        // ── Protocol / Bus ───────────────────────────────────────────
        HardwareVuln {
            id: "HW-PROTO-001",
            name: "Unlocked JTAG Debug Interface",
            category: VulnCategory::Protocol,
            severity: Severity::Critical,
            cvss_score: 9.6,
            description: "An enabled JTAG interface without authentication allows an \
                attacker to halt the CPU, read/write memory, extract firmware, \
                set breakpoints, and bypass secure boot.",
            affected_targets: &["All JTAG-equipped MCUs and SoCs"],
            attack_vector: "Physical access to JTAG header (4‑pin)",
            mitigation: "Disable JTAG fuse in production firmware, \
                challenge-response JTAG authentication (SPIFFS/IEEE 1149.7)",
            references: &["https://www.nxp.com/docs/en/application-note/AN5262.pdf"],
        },
        HardwareVuln {
            id: "HW-PROTO-002",
            name: "Unauthenticated UART Bootloader",
            category: VulnCategory::Protocol,
            severity: Severity::Critical,
            cvss_score: 9.4,
            description: "Many MCUs expose a ROM-resident UART bootloader (STM32 BOOT0 \
                pin, ESP32 serial programming mode) that accepts firmware uploads \
                without authentication or signature verification.",
            affected_targets: &["STM32", "ESP32", "LPC", "NXP i.MX RT"],
            attack_vector: "UART TX/RX lines (physical), boot-mode pin manipulation",
            mitigation: "RDP Level 2 (STM32), eFuse burning (ESP32), \
                signed firmware verification",
            references: &["https://www.st.com/resource/en/application_note/an2606.pdf"],
        },
        HardwareVuln {
            id: "HW-PROTO-003",
            name: "SPI Flash Read‑Back without Protection",
            category: VulnCategory::Protocol,
            severity: Severity::High,
            cvss_score: 8.0,
            description: "External SPI NOR flash storing firmware or keys can be read \
                directly by clipping onto the flash SPI lines, bypassing any OS-level \
                access controls.",
            affected_targets: &["Routers", "IoT devices", "embedded Linux boards"],
            attack_vector: "SPI clip or bus pirate on flash pins",
            mitigation: "On-the-fly firmware encryption, secure element for keys, \
                internal flash only",
            references: &["https://www.flashback.team/papers/spi_attack_2022.pdf"],
        },
        HardwareVuln {
            id: "HW-PROTO-004",
            name: "I2C/SMBus Enumeration and Register Manipulation",
            category: VulnCategory::Protocol,
            severity: Severity::Medium,
            cvss_score: 6.8,
            description: "Unprotected I2C/SMBus buses expose power management ICs, \
                sensors, and crypto chips to arbitrary register reads/writes, allowing \
                power-off attacks, sensor spoofing, or key extraction.",
            affected_targets: &["PMIC", "Secure elements (ATSHA204)", "Baseboard Management Controllers"],
            attack_vector: "Physical I2C bus access (SDA/SCL probes)",
            mitigation: "CRC/MAC authentication on I2C (NXP SE05x), bus isolation",
            references: &[],
        },
        // ── RF ────────────────────────────────────────────────────────
        HardwareVuln {
            id: "HW-RF-001",
            name: "RF Replay Attack (Rolljam / TPMS)",
            category: VulnCategory::RF,
            severity: Severity::High,
            cvss_score: 7.5,
            description: "Recording rolling-code RF signals and injecting the replay \
                while jamming the original allows bypassing one-time-code protections \
                in car keyless entry and tyre pressure sensors.",
            affected_targets: &["Automotive PKES", "TPMS", "Garage door openers"],
            attack_vector: "SDR (HackRF / RTL-SDR), jamming + replay",
            mitigation: "Ultra‑wideband (UWB) ranging, timestamp validation, \
                AES-128 rolling code with sync counter",
            references: &["https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/garcia"],
        },
        HardwareVuln {
            id: "HW-RF-002",
            name: "BLE Passive Eavesdropping",
            category: VulnCategory::RF,
            severity: Severity::Medium,
            cvss_score: 6.5,
            description: "BLE advertising and unencrypted connection data can be \
                passively captured over distances up to 100 m with a commodity SDR, \
                leaking device identifiers, sensor readings, and pairing parameters.",
            affected_targets: &["BLE 4.0/4.2 without LE Privacy", "BLE devices without pairing"],
            attack_vector: "Ubertooth One, nRF Sniffer, RTL-SDR + gr-bluetooth",
            mitigation: "BLE 5 LE Privacy (resolvable private addresses), \
                SC pairing (Secure Connections), mandatory encryption",
            references: &[],
        },
        HardwareVuln {
            id: "HW-RF-003",
            name: "GPS Spoofing",
            category: VulnCategory::RF,
            severity: Severity::Critical,
            cvss_score: 9.2,
            description: "A software-defined radio transmitting a counterfeit GPS signal \
                can cause navigation systems, IoT devices, and infrastructure to adopt \
                a false position or timestamp, enabling timing attacks on financial \
                networks or misdirecting autonomous vehicles.",
            affected_targets: &["All civilian GPS receivers", "NTP servers using GPS PPS"],
            attack_vector: "SDR (USRP / HackRF) + GPS‑SDR-SIM software",
            mitigation: "Multi‑constellation GNSS (GPS + Galileo + BeiDou), \
                cryptographic GNSS authentication (Galileo OSNMA), \
                IMU sensor fusion",
            references: &["https://www.usenix.org/conference/usenixsecurity19/presentation/meng"],
        },
        // ── Firmware ─────────────────────────────────────────────────
        HardwareVuln {
            id: "HW-FW-001",
            name: "Unsigned Firmware Update",
            category: VulnCategory::Firmware,
            severity: Severity::Critical,
            cvss_score: 9.5,
            description: "A firmware update mechanism lacking cryptographic signature \
                verification allows an attacker to flash arbitrary malicious firmware, \
                turning the device into a persistent implant.",
            affected_targets: &["All embedded devices with OTA/UART firmware update"],
            attack_vector: "Physical UART/JTAG, network OTA endpoint, USB DFU",
            mitigation: "ECDSA-P256 or Ed25519 firmware signature, \
                hardware Root of Trust (RoT), secure boot chain",
            references: &[],
        },
        HardwareVuln {
            id: "HW-FW-002",
            name: "Hardcoded Credentials in Firmware",
            category: VulnCategory::Firmware,
            severity: Severity::Critical,
            cvss_score: 9.8,
            description: "Static passwords, API keys, or private keys embedded in \
                firmware images are trivially extracted from flash dumps, \
                enabling remote device compromise at scale.",
            affected_targets: &["IoT devices", "routers", "IP cameras"],
            attack_vector: "Firmware extraction via UART/JTAG/SPI, then \
                binwalk + strings analysis",
            mitigation: "Unique per-device provisioning, secure element storage, \
                trusted execution environment (TEE)",
            references: &[],
        },
        // ── Supply Chain ──────────────────────────────────────────────
        HardwareVuln {
            id: "HW-SUPPLY-001",
            name: "Counterfeit / Trojaned IC",
            category: VulnCategory::Supply,
            severity: Severity::Critical,
            cvss_score: 10.0,
            description: "Counterfeit ICs or hardware trojans inserted in the supply chain \
                can introduce backdoors that activate on specific trigger conditions, \
                leaking keys, disabling security features, or sabotaging operation.",
            affected_targets: &["All ICs sourced from untrusted vendors"],
            attack_vector: "Supply chain interception; die-level hardware trojan",
            mitigation: "Trusted supplier qualification, IC authentication \
                (physically unclonable functions / PUF), silicon lifecycle management",
            references: &[
                "https://www.darpa.mil/program/supply-chain-hardware-integrity-for-electronics-defense",
            ],
        },
        // ── Electromagnetic / HEMP / Nuclear-Hardware ────────────────
        HardwareVuln {
            id: "HW-EMP-001",
            name: "HEMP E1 / Intentional EMI Transient Coupling",
            category: VulnCategory::Physical,
            severity: Severity::Critical,
            cvss_score: 9.4,
            description: "Fast-rise high-altitude EMP (E1, <10 ns rise time, up to 50 kV/m) \
                or directed IEMI induces multi-kilovolt transients on unshielded PCB traces \
                and power rails, causing gate-oxide breakdown, latchup, or bit-flips.",
            affected_targets: &["Unshielded industrial controllers", "RF front-ends", "Automotive ECUs"],
            attack_vector: "Directed high-power microwave / pulse generator / HEMP E1",
            mitigation: "Multi-layer Faraday enclosure, TVS/MOV surge arrestors, \
                differential signalling, skin-depth compliant shielding",
            references: &["https://webstore.iec.ch/publication/4193"],
        },
        HardwareVuln {
            id: "HW-RAD-001",
            name: "Single Event Upset (SEU) & Latchup (SEL) in SRAM/DRAM",
            category: VulnCategory::Physical,
            severity: Severity::High,
            cvss_score: 8.2,
            description: "Ionizing particles or high-energy neutrons deposit charge exceeding \
                the node critical charge Q_crit, flipping SRAM/register bits or triggering \
                parasitic thyristor latchup (SEL) that corrupts keys or halts execution.",
            affected_targets: &["Aerospace MCUs", "High-density SRAM/LPDDR4", "FPGAs"],
            attack_vector: "Alpha/neutron/heavy-ion flux or focused X-ray/laser fault injection",
            mitigation: "Triple Modular Redundancy (TMR), EDAC/ECC memory, \
                current-limiting SEL protection, SOI process",
            references: &["https://radhome.gsfc.nasa.gov/"],
        },
        HardwareVuln {
            id: "HW-RF-004",
            name: "TEMPEST / Van Eck Electromagnetic Emanation Leakage",
            category: VulnCategory::RF,
            severity: Severity::High,
            cvss_score: 7.9,
            description: "Unintentional RF harmonics from display buses, USB/SPI clocks, \
                and cryptographic cores radiate through unshielded enclosures, allowing \
                distant passive reconstruction of screen buffers or secret keys.",
            affected_targets: &["HDMI/LVDS displays", "USB keyboards", "Unshielded HSMs"],
            attack_vector: "Directional wideband antenna + high-gain LNA + SDR + cyclostationary DSP",
            mitigation: "NATO SDIP-27 / TEMPEST zoning, spread-spectrum clocking, \
                ferrite chokes and continuous conductive gaskets",
            references: &["https://www.cl.cam.ac.uk/~mgk25/ih98-tempest.pdf"],
        },
    ]
}

/// Filter vulnerabilities by category.
pub fn filter_by_category<'a>(db: &'a [HardwareVuln], cat: &str) -> Vec<&'a HardwareVuln> {
    let q = cat.to_lowercase();
    db.iter().filter(|v| format!("{:?}", v.category).to_lowercase().contains(&q)).collect()
}

/// Filter vulnerabilities by minimum CVSS score.
pub fn filter_by_severity(db: &[HardwareVuln], min_cvss: f32) -> Vec<&HardwareVuln> {
    db.iter().filter(|v| v.cvss_score >= min_cvss).collect()
}

/// Search vulnerabilities by keyword in name or description.
pub fn search_vulns<'a>(db: &'a [HardwareVuln], query: &str) -> Vec<&'a HardwareVuln> {
    let q = query.to_lowercase();
    db.iter().filter(|v| {
        v.name.to_lowercase().contains(&q) || v.description.to_lowercase().contains(&q)
    }).collect()
}

/// Export the database to JSON.
pub fn export_json(db: &[HardwareVuln]) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(db)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_has_entries() {
        let db = vuln_database();
        assert!(!db.is_empty());
    }

    #[test]
    fn filter_physical() {
        let db = vuln_database();
        let physical = filter_by_category(&db, "physical");
        assert!(!physical.is_empty());
        for v in &physical { assert!(format!("{:?}", v.category).to_lowercase().contains("physical")); }
    }

    #[test]
    fn filter_critical() {
        let db = vuln_database();
        let critical = filter_by_severity(&db, 9.0);
        for v in &critical { assert!(v.cvss_score >= 9.0); }
    }

    #[test]
    fn search_works() {
        let db = vuln_database();
        let res = search_vulns(&db, "glitch");
        assert!(!res.is_empty());
    }

    #[test]
    fn json_export() {
        let db = vuln_database();
        let json = export_json(&db).unwrap();
        assert!(json.contains("HW-PHYS-001"));
    }
}
