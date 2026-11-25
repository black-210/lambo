use iq_research_workbench::gui::handle_connection;
use iq_research_workbench::prelude::*;
use std::f64::consts::PI;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "iq-int-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn workbench_supports_raw_sdr_cf32_and_cu8_formats() {
    let dir = temp_dir("sdr");
    let cf32_path = dir.join("tone.cf32");
    let mut cf32_bytes = Vec::new();
    for i in 0..128 {
        let ang = 2.0 * PI * 12.0 * i as f64 / 128.0;
        cf32_bytes.extend_from_slice(&(ang.cos() as f32).to_le_bytes());
        cf32_bytes.extend_from_slice(&(ang.sin() as f32).to_le_bytes());
    }
    fs::write(&cf32_path, cf32_bytes).unwrap();

    let report = Workbench::new()
        .sample_rate(128.0)
        .analyze_iq_file(&cf32_path)
        .unwrap();
    assert_eq!(report["spectral_peaks"][0]["frequency"], 12.0);
    assert!(report["preview"]["spectrogram"].as_array().unwrap().len() >= 8);

    let cu8_path = dir.join("rtlsdr.cu8");
    let mut cu8_bytes = Vec::new();
    for i in 0..128 {
        let ang = 2.0 * PI * 6.0 * i as f64 / 128.0;
        let i_u8 = ((ang.cos() * 80.0) + 127.5).round() as u8;
        let q_u8 = ((ang.sin() * 80.0) + 127.5).round() as u8;
        cu8_bytes.push(i_u8);
        cu8_bytes.push(q_u8);
    }
    fs::write(&cu8_path, cu8_bytes).unwrap();
    let cu8_rep = Workbench::new().sample_rate(128.0).analyze_iq_file(&cu8_path).unwrap();
    assert_eq!(cu8_rep["spectral_peaks"][0]["frequency"], 6.0);

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn gui_http_loopback_serves_ui_and_api() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in listener.incoming().take(2).flatten() {
            handle_connection(s);
        }
    });

    let mut s1 = TcpStream::connect(addr).unwrap();
    s1.write_all(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut resp1 = String::new();
    s1.read_to_string(&mut resp1).unwrap();
    assert!(resp1.contains("200 OK"));
    assert!(resp1.contains("\"status\":\"ok\""));

    let mut s2 = TcpStream::connect(addr).unwrap();
    s2.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut resp2 = String::new();
    s2.read_to_string(&mut resp2).unwrap();
    assert!(resp2.contains("200 OK"));
    assert!(resp2.contains("IQ Hardware Red-Team"));
}
