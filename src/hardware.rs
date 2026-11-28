//! # Hardware Integration, Passive Device Discovery & Logic Bus Decoders
//!
//! Provides:
//! 1. **`HardwareCaptureSource` library trait**: Clean Rust abstraction allowing applications
//!    and hardware testbench drivers (SDRs, oscilloscopes, logic analyzers) to stream IQ,
//!    power/EM, or digital logic captures directly into the workbench.
//! 2. **Passive Read-Only Device Inventory (`discover_local_hardware`)**: Enumerates attached
//!    COM/serial ports and USB SDR/logic-analyzer/debug hardware IDs without active probing,
//!    writing, flashing, or glitching.
//! 3. **IEEE 1364 `.vcd` Logic Analyzer Parser & Bus Decoders (from scratch)**:
//!    - UART 8N1 decoder with automatic pulse-width baud estimation
//!    - SPI synchronous decoder (Modes 0–3, Flash JEDEC command tagging)
//!    - I2C START/STOP/Address/ACK/Data decoder

use anyhow::{Context, Result, bail};
use num_complex::Complex64;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

// ─── Library Hardware Abstraction Trait ──────────────────────────────────────

/// Capabilities metadata advertised by a hardware capture source implementation.
#[derive(Clone, Debug)]
pub struct HardwareCapabilities {
    pub device_name: String,
    pub sample_rate_hz: f64,
    pub supports_iq: bool,
    pub supports_analog_trace: bool,
    pub read_only_passive: bool,
}

/// Trait implemented by external hardware drivers or buffered lab testbenches when using
/// `iq_research_workbench` as a library.
pub trait HardwareCaptureSource {
    fn capabilities(&self) -> HardwareCapabilities;
    fn read_iq_block(&mut self, max_samples: usize) -> Result<Vec<Complex64>>;
    fn read_trace_block(&mut self, max_samples: usize) -> Result<Vec<f64>>;
}

/// Deterministic in-memory implementation of [`HardwareCaptureSource`] useful for automated
/// laboratory integration and unit testing.
pub struct MemoryHardwareSource {
    caps: HardwareCapabilities,
    iq_buf: Vec<Complex64>,
    trace_buf: Vec<f64>,
    iq_cursor: usize,
    trace_cursor: usize,
}

impl MemoryHardwareSource {
    pub fn new(name: impl Into<String>, sample_rate_hz: f64) -> Self {
        Self {
            caps: HardwareCapabilities {
                device_name: name.into(),
                sample_rate_hz,
                supports_iq: true,
                supports_analog_trace: true,
                read_only_passive: true,
            },
            iq_buf: Vec::new(),
            trace_buf: Vec::new(),
            iq_cursor: 0,
            trace_cursor: 0,
        }
    }

    pub fn with_iq(mut self, samples: Vec<Complex64>) -> Self {
        self.iq_buf = samples;
        self
    }

    pub fn with_trace(mut self, trace: Vec<f64>) -> Self {
        self.trace_buf = trace;
        self
    }
}

impl HardwareCaptureSource for MemoryHardwareSource {
    fn capabilities(&self) -> HardwareCapabilities {
        self.caps.clone()
    }

    fn read_iq_block(&mut self, max_samples: usize) -> Result<Vec<Complex64>> {
        if self.iq_cursor >= self.iq_buf.len() {
            return Ok(Vec::new());
        }
        let end = (self.iq_cursor + max_samples).min(self.iq_buf.len());
        let slice = self.iq_buf[self.iq_cursor..end].to_vec();
        self.iq_cursor = end;
        Ok(slice)
    }

    fn read_trace_block(&mut self, max_samples: usize) -> Result<Vec<f64>> {
        if self.trace_cursor >= self.trace_buf.len() {
            return Ok(Vec::new());
        }
        let end = (self.trace_cursor + max_samples).min(self.trace_buf.len());
        let slice = self.trace_buf[self.trace_cursor..end].to_vec();
        self.trace_cursor = end;
        Ok(slice)
    }
}

// ─── Known Lab Hardware USB ID Catalog ───────────────────────────────────────

fn classify_usb_vid_pid(vid_pid_upper: &str) -> Option<(&'static str, &'static str)> {
    match vid_pid_upper {
        "0BDA:2838" | "0BDA:2832" => Some(("sdr_receiver", "RTL-SDR Dongle (RTL2832U)")),
        "1D50:6089" => Some(("sdr_transceiver", "Great Scott Gadgets HackRF One")),
        "2CF0:5250" => Some(("hardware_multitool", "GreatFET One")),
        "1D50:6066" | "2B53:0001" => Some(("sdr_transceiver", "Nuand BladeRF")),
        "2500:0020" | "2500:0022" => Some(("sdr_transceiver", "Ettus USRP B200/B210")),
        "0456:B673" => Some(("sdr_transceiver", "Analog Devices ADALM-Pluto SDR")),
        "0925:3881" | "21A9:1001" => Some(("logic_analyzer", "Saleae / fx2lafw Logic Analyzer")),
        "0483:3748" | "0483:374B" | "0483:374E" => Some(("debug_probe", "STMicroelectronics ST-Link")),
        "1366:0101" | "1366:1015" => Some(("debug_probe", "SEGGER J-Link")),
        "1D50:6018" => Some(("debug_probe", "Black Magic Debug Probe")),
        "2E8A:000C" => Some(("debug_probe", "Raspberry Pi Debug Probe (CMSIS-DAP)")),
        "0403:6001" | "0403:6010" | "0403:6014" => Some(("serial_jtag_bridge", "FTDI USB-Serial / MPSSE")),
        "10C4:EA60" => Some(("serial_bridge", "Silicon Labs CP210x UART Bridge")),
        "1A86:7523" => Some(("serial_bridge", "WCH CH340 USB-Serial")),
        _ => None,
    }
}

fn extract_vid_pid(instance_id: &str) -> Option<String> {
    let upper = instance_id.to_ascii_uppercase();
    let vid_pos = upper.find("VID_")?;
    let pid_pos = upper.find("PID_")?;
    let vid = upper.get(vid_pos + 4..vid_pos + 8)?;
    let pid = upper.get(pid_pos + 4..pid_pos + 8)?;
    Some(format!("{vid}:{pid}"))
}

/// Passive read-only OS discovery of attached serial ports & known lab SDR/logic/debug USB hardware.
pub fn discover_local_hardware() -> Result<Value> {
    let mut serial_ports: Vec<Value> = Vec::new();
    let mut usb_devices: Vec<Value> = Vec::new();
    let mut recognized_lab_hardware: Vec<Value> = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "[System.IO.Ports.SerialPort]::GetPortNames() | ForEach-Object { $_ }",
            ])
            .output()
            && out.status.success()
        {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let port = line.trim();
                if !port.is_empty() {
                    serial_ports.push(json!({"port": port, "transport": "serial_com"}));
                }
            }
        }

        if let Ok(out) = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match 'VID_[0-9A-Fa-f]{4}' } | Select-Object -First 60 -Property FriendlyName,Class,InstanceId | ConvertTo-Json -Compress",
            ])
            .output()
            && out.status.success()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Ok(parsed) = serde_json::from_str::<Value>(text.trim()) {
                let items: Vec<Value> = match parsed {
                    Value::Array(arr) => arr,
                    obj @ Value::Object(_) => vec![obj],
                    _ => Vec::new(),
                };
                for item in items {
                    let name = item["FriendlyName"].as_str().unwrap_or("USB Device").to_owned();
                    let class = item["Class"].as_str().unwrap_or("USB").to_owned();
                    let inst = item["InstanceId"].as_str().unwrap_or("").to_owned();
                    let vid_pid = extract_vid_pid(&inst);
                    if let Some(ref vp) = vid_pid
                        && let Some((role, model)) = classify_usb_vid_pid(vp)
                    {
                        recognized_lab_hardware.push(json!({
                            "vid_pid": vp,
                            "role": role,
                            "model": model,
                            "os_name": name,
                            "instance_id": inst
                        }));
                    }
                    usb_devices.push(json!({
                        "name": name,
                        "class": class,
                        "vid_pid": vid_pid,
                        "instance_id": inst
                    }));
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.starts_with("ttyUSB")
                    || fname.starts_with("ttyACM")
                    || fname.starts_with("cu.")
                {
                    serial_ports.push(json!({"port": format!("/dev/{fname}"), "transport": "tty"}));
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir("/sys/bus/usb/devices") {
            for entry in entries.flatten() {
                let p = entry.path();
                if let (Ok(vid), Ok(pid)) = (
                    std::fs::read_to_string(p.join("idVendor")),
                    std::fs::read_to_string(p.join("idProduct")),
                ) {
                    let vp = format!("{}:{}", vid.trim(), pid.trim()).to_ascii_uppercase();
                    let prod = std::fs::read_to_string(p.join("product"))
                        .unwrap_or_else(|_| "USB Device".to_owned());
                    if let Some((role, model)) = classify_usb_vid_pid(&vp) {
                        recognized_lab_hardware.push(json!({
                            "vid_pid": vp,
                            "role": role,
                            "model": model,
                            "os_name": prod.trim()
                        }));
                    }
                    usb_devices.push(json!({
                        "name": prod.trim(),
                        "vid_pid": vp
                    }));
                }
            }
        }
    }

    Ok(json!({
        "schema_version": 1,
        "analysis": "passive_local_hardware_inventory",
        "mode": "read_only_os_enumeration",
        "serial_port_count": serial_ports.len(),
        "usb_device_count": usb_devices.len(),
        "recognized_lab_hardware_count": recognized_lab_hardware.len(),
        "serial_ports": serial_ports,
        "recognized_lab_hardware": recognized_lab_hardware,
        "usb_devices": usb_devices,
        "safety_note": "Passive OS descriptor listing only; no probes, resets, flashes, or RF transmissions were issued."
    }))
}

// ─── IEEE 1364 VCD Logic Analyzer Parser (From Scratch) ──────────────────────

#[derive(Clone, Debug)]
pub struct VcdSignalTimeline {
    pub name: String,
    pub timescale_sec: f64,
    /// Ordered `(timestamp_ticks, logic_level)` transitions.
    pub events: Vec<(u64, u8)>,
}

fn parse_timescale_seconds(tok: &str) -> f64 {
    let lower = tok.trim().to_ascii_lowercase();
    let num_end = lower
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(lower.len());
    let mult: f64 = lower[..num_end].parse().unwrap_or(1.0);
    let unit = lower[num_end..].trim();
    let scale = match unit {
        "ps" => 1e-12,
        "ns" => 1e-9,
        "us" => 1e-6,
        "ms" => 1e-3,
        "s" => 1.0,
        _ => 1e-9,
    };
    mult * scale
}

/// Parse an IEEE 1364 `.vcd` logic analyzer dump into named channel transition timelines.
pub fn parse_vcd_file(path: &Path) -> Result<HashMap<String, VcdSignalTimeline>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Reading VCD file {}", path.display()))?;
    let mut timescale_sec = 1e-9_f64;
    let mut id_to_name: HashMap<String, String> = HashMap::new();
    let mut timelines: HashMap<String, VcdSignalTimeline> = HashMap::new();
    let mut current_time: u64 = 0;
    let mut in_defs = true;

    let tokens: Vec<&str> = text.split_whitespace().collect();
    let mut i = 0usize;
    while i < tokens.len() {
        let tok = tokens[i];
        if in_defs {
            match tok {
                "$timescale" => {
                    i += 1;
                    let mut combined = String::new();
                    while i < tokens.len() && tokens[i] != "$end" {
                        combined.push_str(tokens[i]);
                        i += 1;
                    }
                    timescale_sec = parse_timescale_seconds(&combined);
                }
                "$var" => {
                    // $var wire 1 ! UART_TX $end
                    if i + 5 < tokens.len() {
                        let id = tokens[i + 3].to_owned();
                        let name = tokens[i + 4].to_owned();
                        id_to_name.insert(id.clone(), name.clone());
                        timelines.entry(name.clone()).or_insert_with(|| VcdSignalTimeline {
                            name,
                            timescale_sec,
                            events: Vec::new(),
                        });
                    }
                    while i < tokens.len() && tokens[i] != "$end" {
                        i += 1;
                    }
                }
                "$enddefinitions" => {
                    in_defs = false;
                }
                _ => {}
            }
        } else {
            if tok == "$dumpvars" || tok == "$end" || tok == "$comment" {
                if tok == "$comment" {
                    while i < tokens.len() && tokens[i] != "$end" {
                        i += 1;
                    }
                }
                i += 1;
                continue;
            }
            if let Some(ts_str) = tok.strip_prefix('#') {
                if let Ok(t) = ts_str.parse::<u64>() {
                    current_time = t;
                }
            } else if tok.starts_with('0') || tok.starts_with('1') {
                let level = if tok.starts_with('1') { 1u8 } else { 0u8 };
                let id = &tok[1..];
                if let Some(name) = id_to_name.get(id)
                    && let Some(tl) = timelines.get_mut(name)
                {
                    tl.timescale_sec = timescale_sec;
                    tl.events.push((current_time, level));
                }
            } else if (tok.starts_with('b') || tok.starts_with('B')) && i + 1 < tokens.len() {
                let level = if tok.ends_with('1') { 1u8 } else { 0u8 };
                let id = tokens[i + 1];
                if let Some(name) = id_to_name.get(id)
                    && let Some(tl) = timelines.get_mut(name)
                {
                    tl.timescale_sec = timescale_sec;
                    tl.events.push((current_time, level));
                }
                i += 1;
            }
        }
        i += 1;
    }

    if timelines.is_empty() {
        bail!("No signal channels parsed from VCD file {}", path.display());
    }
    Ok(timelines)
}

fn level_at_tick(events: &[(u64, u8)], tick: u64) -> u8 {
    let idx = events.partition_point(|&(t, _)| t <= tick);
    if idx == 0 {
        events.first().map_or(1, |&(_, lvl)| lvl)
    } else {
        events[idx - 1].1
    }
}

fn resolve_channel<'a>(
    timelines: &'a HashMap<String, VcdSignalTimeline>,
    preferred: Option<&str>,
    hints: &[&str],
) -> Result<&'a VcdSignalTimeline> {
    if let Some(name) = preferred {
        return timelines
            .get(name)
            .with_context(|| format!("VCD channel {name:?} not found."));
    }
    for (k, v) in timelines {
        let low = k.to_ascii_lowercase();
        if hints.iter().any(|h| low.contains(h)) {
            return Ok(v);
        }
    }
    timelines
        .values()
        .next()
        .context("No channels available in VCD.")
}

// ─── UART 8N1 Decoder (Auto-Baud Estimation + Security Telemetry Screen) ─────

/// Decode UART 8N1 bytes from a `.vcd` logic channel. Estimates baud automatically if `baud_hz` is None.
pub fn decode_uart_vcd(
    vcd_path: &Path,
    channel: Option<&str>,
    baud_hz: Option<f64>,
) -> Result<Value> {
    let timelines = parse_vcd_file(vcd_path)?;
    let tl = resolve_channel(&timelines, channel, &["uart", "tx", "rx", "serial"])?;
    if tl.events.len() < 3 {
        bail!("Channel '{}' contains fewer than 3 logic transitions.", tl.name);
    }

    // Estimate bit period in ticks from minimum valid pulse width
    let bit_ticks: f64 = if let Some(b) = baud_hz {
        if b <= 0.0 || !b.is_finite() {
            bail!("Baud rate must be finite positive.");
        }
        (1.0 / b) / tl.timescale_sec
    } else {
        let mut widths: Vec<u64> = tl
            .events
            .windows(2)
            .filter_map(|w| {
                let dt = w[1].0.saturating_sub(w[0].0);
                (dt > 0).then_some(dt)
            })
            .collect();
        widths.sort_unstable();
        widths.first().copied().context("Cannot infer UART bit period.")? as f64
    };
    let effective_baud = 1.0 / (bit_ticks * tl.timescale_sec);

    let mut bytes = Vec::new();
    let mut framing_errors = 0usize;
    let mut i = 1usize;
    let mut next_allowed_tick = 0u64;

    while i < tl.events.len() {
        let (t, lvl) = tl.events[i];
        let prev_lvl = tl.events[i - 1].1;
        // Start bit is falling edge 1 -> 0
        if prev_lvl == 1 && lvl == 0 && t >= next_allowed_tick {
            let mut byte = 0u8;
            for bit_idx in 0..8 {
                let sample_tick = t + ((1.5 + bit_idx as f64) * bit_ticks).round() as u64;
                let bit = level_at_tick(&tl.events, sample_tick);
                byte |= (bit & 1) << bit_idx;
            }
            let stop_tick = t + (9.5 * bit_ticks).round() as u64;
            if level_at_tick(&tl.events, stop_tick) == 0 {
                framing_errors += 1;
            }
            bytes.push(byte);
            next_allowed_tick = t + (9.6 * bit_ticks).round() as u64;
        }
        i += 1;
    }

    let decoded_text = String::from_utf8_lossy(&bytes).to_string();
    let lower = decoded_text.to_ascii_lowercase();
    let mut indicators = Vec::new();
    for kw in ["password", "root", "u-boot", "login", "api_key", "token", "shell"] {
        if lower.contains(kw) {
            indicators.push(format!("cleartext_uart_keyword:{kw}"));
        }
    }

    Ok(json!({
        "schema_version": 1,
        "analysis": "uart_logic_bus_decode",
        "channel": tl.name,
        "estimated_baud_hz": effective_baud,
        "byte_count": bytes.len(),
        "framing_errors": framing_errors,
        "bytes_hex": hex::encode(&bytes),
        "decoded_ascii": decoded_text,
        "security_indicators": indicators
    }))
}

// ─── SPI Bus Decoder ─────────────────────────────────────────────────────────

/// Decode synchronous SPI bytes (Modes 0–3) from a `.vcd` logic trace.
pub fn decode_spi_vcd(
    vcd_path: &Path,
    sclk_name: Option<&str>,
    mosi_name: Option<&str>,
    miso_name: Option<&str>,
    cs_name: Option<&str>,
    cpol: u8,
    cpha: u8,
) -> Result<Value> {
    let timelines = parse_vcd_file(vcd_path)?;
    let sclk = resolve_channel(&timelines, sclk_name, &["sclk", "clk", "sck"])?;
    let mosi = resolve_channel(&timelines, mosi_name, &["mosi", "sdi", "do"])?;
    let miso = miso_name
        .and_then(|n| timelines.get(n))
        .or_else(|| timelines.iter().find(|(k, _)| k.to_ascii_lowercase().contains("miso")).map(|(_, v)| v));
    let cs = cs_name
        .and_then(|n| timelines.get(n))
        .or_else(|| timelines.iter().find(|(k, _)| k.to_ascii_lowercase().contains("cs")).map(|(_, v)| v));

    // Mode 0/3 capture on rising edge, Mode 1/2 capture on falling edge
    let capture_rising = (cpol == 0 && cpha == 0) || (cpol == 1 && cpha == 1);
    let mut mosi_bytes = Vec::new();
    let mut miso_bytes = Vec::new();
    let mut cur_mosi = 0u8;
    let mut cur_miso = 0u8;
    let mut bit_count = 0u8;

    for w in sclk.events.windows(2) {
        let prev = w[0].1;
        let (tick, lvl) = w[1];
        let is_edge = if capture_rising {
            prev == 0 && lvl == 1
        } else {
            prev == 1 && lvl == 0
        };
        if !is_edge {
            continue;
        }
        if let Some(cs_tl) = cs
            && level_at_tick(&cs_tl.events, tick) != 0
        {
            bit_count = 0;
            cur_mosi = 0;
            cur_miso = 0;
            continue;
        }
        let b_mosi = level_at_tick(&mosi.events, tick) & 1;
        cur_mosi = (cur_mosi << 1) | b_mosi;
        if let Some(miso_tl) = miso {
            let b_miso = level_at_tick(&miso_tl.events, tick) & 1;
            cur_miso = (cur_miso << 1) | b_miso;
        }
        bit_count += 1;
        if bit_count == 8 {
            mosi_bytes.push(cur_mosi);
            if miso.is_some() {
                miso_bytes.push(cur_miso);
            }
            cur_mosi = 0;
            cur_miso = 0;
            bit_count = 0;
        }
    }

    let mut flash_opcodes = Vec::new();
    if let Some(&first) = mosi_bytes.first() {
        let desc = match first {
            0x9F => Some("JEDEC_RDID (0x9F)"),
            0x03 => Some("FLASH_READ (0x03)"),
            0x0B => Some("FLASH_FAST_READ (0x0B)"),
            0x05 => Some("READ_STATUS_REG (0x05)"),
            0x06 => Some("WRITE_ENABLE (0x06)"),
            _ => None,
        };
        if let Some(d) = desc {
            flash_opcodes.push(d);
        }
    }

    Ok(json!({
        "schema_version": 1,
        "analysis": "spi_logic_bus_decode",
        "cpol": cpol,
        "cpha": cpha,
        "byte_count": mosi_bytes.len(),
        "mosi_hex": hex::encode(&mosi_bytes),
        "miso_hex": hex::encode(&miso_bytes),
        "mosi_ascii_lossy": String::from_utf8_lossy(&mosi_bytes),
        "miso_ascii_lossy": String::from_utf8_lossy(&miso_bytes),
        "detected_flash_opcodes": flash_opcodes
    }))
}

// ─── I2C Bus Decoder ─────────────────────────────────────────────────────────

/// Decode I2C START, STOP, 7-bit address + R/W, byte stream, and ACK/NACK from `.vcd`.
pub fn decode_i2c_vcd(
    vcd_path: &Path,
    scl_name: Option<&str>,
    sda_name: Option<&str>,
) -> Result<Value> {
    let timelines = parse_vcd_file(vcd_path)?;
    let scl = resolve_channel(&timelines, scl_name, &["scl", "clk"])?;
    let sda = resolve_channel(&timelines, sda_name, &["sda", "data"])?;

    let mut merged: Vec<(u64, &str, u8)> = Vec::new();
    for &(t, v) in &scl.events {
        merged.push((t, "scl", v));
    }
    for &(t, v) in &sda.events {
        merged.push((t, "sda", v));
    }
    merged.sort_by_key(|e| e.0);

    let mut cur_scl = scl.events.first().map_or(1, |e| e.1);
    let mut cur_sda = sda.events.first().map_or(1, |e| e.1);
    let mut active = false;
    let mut bit_idx = 0u8;
    let mut cur_byte = 0u8;
    let mut txns: Vec<Value> = Vec::new();
    let mut cur_bytes: Vec<u8> = Vec::new();
    let mut cur_acks: Vec<bool> = Vec::new();

    for (_, line, val) in merged {
        if line == "sda" {
            if cur_scl == 1 && cur_sda == 1 && val == 0 {
                // START condition
                if active && !cur_bytes.is_empty() {
                    txns.push(format_i2c_txn(&cur_bytes, &cur_acks));
                    cur_bytes.clear();
                    cur_acks.clear();
                }
                active = true;
                bit_idx = 0;
                cur_byte = 0;
            } else if cur_scl == 1 && cur_sda == 0 && val == 1 {
                // STOP condition
                if active && !cur_bytes.is_empty() {
                    txns.push(format_i2c_txn(&cur_bytes, &cur_acks));
                    cur_bytes.clear();
                    cur_acks.clear();
                }
                active = false;
            }
            cur_sda = val;
        } else {
            let rising = cur_scl == 0 && val == 1;
            cur_scl = val;
            if active && rising {
                if bit_idx < 8 {
                    cur_byte = (cur_byte << 1) | (cur_sda & 1);
                    bit_idx += 1;
                } else {
                    cur_bytes.push(cur_byte);
                    cur_acks.push(cur_sda == 0);
                    cur_byte = 0;
                    bit_idx = 0;
                }
            }
        }
    }
    if active && !cur_bytes.is_empty() {
        txns.push(format_i2c_txn(&cur_bytes, &cur_acks));
    }

    Ok(json!({
        "schema_version": 1,
        "analysis": "i2c_logic_bus_decode",
        "transaction_count": txns.len(),
        "transactions": txns
    }))
}

fn format_i2c_txn(bytes: &[u8], acks: &[bool]) -> Value {
    let addr_byte = bytes[0];
    let addr_7bit = addr_byte >> 1;
    let is_read = (addr_byte & 1) == 1;
    let payload = &bytes[1..];
    json!({
        "address_7bit_hex": format!("0x{addr_7bit:02x}"),
        "direction": if is_read { "READ" } else { "WRITE" },
        "address_acked": acks.first().copied().unwrap_or(false),
        "payload_hex": hex::encode(payload),
        "payload_ascii": String::from_utf8_lossy(payload)
    })
}
fn format_spi_txn(bytes: &[u8]) -> Value {
    let mut binary_str = String::new();
    for &b in bytes {
        for i in 0..8 {
            binary_str.push(if (b >> (7 - i)) & 1 == 1 { '1' } else { '0' });
        }
        binary_str.push(' ');
    }
    binary_str.pop(); // Remove trailing space
    json!({
        "payload_hex": hex::encode(bytes),
        "payload_ascii": String::from_utf8_lossy(bytes),
        "payload_binary": binary_str,
        "transaction_type": "SPI",
        "payload_nuclear": bytes.iter().all(|&b| b == 0xFF),
        "payload_empty": bytes.is_empty(),
        "payload_length": bytes.len()
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    #[test]
    fn decodes_synthetic_uart_byte_from_vcd() {
        // Encode 'A' (0x41 = 0b0100_0001 LSB-first: 1,0,0,0,0,0,1,0) at 1000 baud (1000us/bit)
        let dir = std::env::temp_dir().join(format!("iq-hw-uart-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let vcd = dir.join("uart.vcd");
        let mut s = String::from("$timescale 1us $end\n$var wire 1 ! UART_TX $end\n$enddefinitions $end\n$dumpvars\n1!\n$end\n");
        let mut t = 1000u64;
        // Start bit 0
        writeln!(s, "#{t}\n0!").unwrap();
        t += 1000;
        let bits_lsb = [1, 0, 0, 0, 0, 0, 1, 0];
        let mut prev = 0u8;
        for b in bits_lsb {
            if b != prev {
                writeln!(s, "#{t}\n{b}!").unwrap();
                prev = b;
            }
            t += 1000;
        }
        // Stop bit 1
        writeln!(s, "#{t}\n1!").unwrap();
        std::fs::write(&vcd, s).unwrap();

        let rep = decode_uart_vcd(&vcd, None, Some(1000.0)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(rep["decoded_ascii"], "A");
        assert_eq!(rep["framing_errors"], 0);
    }

    #[test]
    fn memory_hardware_source_streams_data() {
        let mut src = MemoryHardwareSource::new("SimSDR", 1_000_000.0)
            .with_iq(vec![Complex64::new(1.0, 0.0), Complex64::new(0.0, 1.0)]);
        assert!(src.capabilities().read_only_passive);
        let blk = src.read_iq_block(10).unwrap();
        assert_eq!(blk.len(), 2);
    }
}
