#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod capture;
mod osint;
mod simulator;
mod state;
mod types;
mod ui;

use crate::capture::HybridCapture;
use crate::osint::{OsintConfig, OsintEngine};
use crate::simulator::TrafficSimulator;
use crate::state::TelemetryState;
use crate::types::CaptureMode;
use crate::ui::GlassTraceApp;
use clap::{Parser, ValueEnum};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliMode {
    Live,
    Sim,
}

#[derive(Parser, Debug)]
#[command(
    name = "glasstrace",
    version,
    about = "GlassTrace Desktop — Native network traffic monitor & live OSINT geo-telemetry"
)]
struct Args {
    /// Initial capture mode (live or sim)
    #[arg(long, value_enum, default_value_t = CliMode::Live)]
    mode: CliMode,

    /// Disable live ip-api.com / AbuseIPDB / VirusTotal HTTP lookups and use offline GeoIP fallback
    #[arg(long, default_value_t = false)]
    offline: bool,

    /// Optional AbuseIPDB v2 API key for threat reputation scoring
    #[arg(long, env = "ABUSEIPDB_API_KEY")]
    abuseipdb_key: Option<String>,

    /// Optional VirusTotal v3 API key for IP reputation scoring
    #[arg(long, env = "VT_API_KEY")]
    vt_key: Option<String>,

    /// Run a brief headless telemetry verification tick and exit (for CLI/CI checks)
    #[arg(long, default_value_t = false)]
    smoke_test: bool,
}

fn main() -> eframe::Result<()> {
    let args = Args::parse();

    let initial_mode = match args.mode {
        CliMode::Live => CaptureMode::Live,
        CliMode::Sim => CaptureMode::Sim,
    };

    let osint = Arc::new(OsintEngine::new(OsintConfig {
        offline: args.offline,
        abuseipdb_key: args.abuseipdb_key,
        vt_key: args.vt_key,
    }));

    let state = Arc::new(RwLock::new(TelemetryState::new(initial_mode)));

    if args.smoke_test {
        let mut live = HybridCapture::new();
        let mut sim = TrafficSimulator::new();
        let (flows, rx, tx, backend) = match initial_mode {
            CaptureMode::Live => live.poll_tick(&osint),
            CaptureMode::Sim => sim.next_tick(&osint),
        };
        if let Ok(mut guard) = state.write() {
            guard.ingest_tick(flows, rx, tx, backend);
            let snap = guard.snapshot();
            println!(
                "GlassTrace smoke-test OK | mode={:?} | backend={} | flows={} (in={}, out={}, listen={}) | rx={} B/s | tx={} B/s | alerts={} | osint_cache={}",
                snap.mode,
                snap.backend.backend_name,
                snap.flows.len(),
                snap.inbound_count,
                snap.outbound_count,
                snap.listening_count,
                snap.current_rx_bps,
                snap.current_tx_bps,
                snap.alerts.len(),
                osint.cache_len()
            );
        }
        return Ok(());
    }

    // Spawn 1-second background telemetry collector thread
    let state_bg = Arc::clone(&state);
    let osint_bg = Arc::clone(&osint);
    thread::Builder::new()
        .name("glasstrace-collector".into())
        .spawn(move || {
            let mut live_capture = HybridCapture::new();
            let mut sim = TrafficSimulator::new();
            loop {
                let mode = state_bg
                    .read()
                    .map(|g| g.mode)
                    .unwrap_or(CaptureMode::Live);

                let (flows, rx_bps, tx_bps, backend) = match mode {
                    CaptureMode::Live => live_capture.poll_tick(&osint_bg),
                    CaptureMode::Sim => sim.next_tick(&osint_bg),
                };

                if let Ok(mut guard) = state_bg.write() {
                    guard.ingest_tick(flows, rx_bps, tx_bps, backend);
                }

                thread::sleep(Duration::from_secs(1));
            }
        })
        .expect("failed to spawn collector thread");

    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("GlassTrace Desktop — Network Traffic & OSINT Geo-Telemetry")
            .with_inner_size([1440.0, 880.0])
            .with_min_inner_size([1024.0, 660.0]),
        ..Default::default()
    };

    eframe::run_native(
        "GlassTrace Desktop",
        native_options,
        Box::new(move |cc| Ok(Box::new(GlassTraceApp::new(cc, state, osint)))),
    )
}
