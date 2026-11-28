use anyhow::{Result, Context};
use serde_json::json;
use std::process::Command;

/// Simple representation of a discovered device.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceInfo {
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub description: String,
    pub bus: String,
    pub extra: serde_json::Value,
}

/// Discover serial ports and USB devices on Windows (passive).
pub fn discover_windows() -> Result<Vec<DeviceInfo>> {
    // Serial ports via PowerShell
    let serial_output = Command::new("powershell")
        .args(["-NoProfile", "-Command", "[System.IO.Ports.SerialPort]::GetPortNames() | ForEach-Object { $_ }"])
        .output()
        .context("Failed to run PowerShell for serial ports")?;
    let mut devices = Vec::new();
    for line in String::from_utf8_lossy(&serial_output.stdout).lines() {
        let port = line.trim();
        if !port.is_empty() {
            devices.push(DeviceInfo {
                vendor_id: None,
                product_id: None,
                description: format!("Serial port {}", port),
                bus: "serial".into(),
                extra: json!({"port": port}),
            });
        }
    }

    // USB devices via Get-PnpDevice (limit to 200 for speed)
    let usb_output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match 'VID_[0-9A-Fa-f]{4}' } | Select-Object -First 200 -Property FriendlyName,Class,InstanceId | ConvertTo-Json -Compress",
        ])
        .output()
        .context("Failed to run PowerShell for USB devices")?;
    let json_str = String::from_utf8_lossy(&usb_output.stdout);
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json_str) {
        let items = match parsed {
            serde_json::Value::Array(arr) => arr,
            serde_json::Value::Object(_) => vec![parsed],
            _ => vec![],
        };
        for item in items {
            let name = item["FriendlyName"].as_str().unwrap_or("USB Device");
            let class = item["Class"].as_str().unwrap_or("USB");
            let instance = item["InstanceId"].as_str().unwrap_or("");
            let (vid, pid) = extract_vid_pid(instance);
            devices.push(DeviceInfo {
                vendor_id: vid,
                product_id: pid,
                description: name.into(),
                bus: "usb".into(),
                extra: json!({"class": class, "instance_id": instance}),
            });
        }
    }
    Ok(devices)
}

fn extract_vid_pid(instance: &str) -> (Option<String>, Option<String>) {
    let upper = instance.to_ascii_uppercase();
    let vid = upper.find("VID_").and_then(|p| upper.get(p + 4..p + 8)).map(|s| s.to_string());
    let pid = upper.find("PID_").and_then(|p| upper.get(p + 4..p + 8)).map(|s| s.to_string());
    (vid, pid)
}
