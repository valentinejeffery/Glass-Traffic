use crate::stats::StatsStore;
use crate::types::{
    AlertEvent, AlertKind, AppSummary, BandwidthPoint, CaptureBackendStatus, Direction, Flow,
};
use chrono::Local;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::PathBuf;

const HISTORY_LEN: usize = 120;
const MAX_ALERTS: usize = 250;

#[derive(Debug, Clone, Serialize)]
pub struct TelemetrySnapshot {
    pub backend: CaptureBackendStatus,
    pub home_lat: f32,
    pub home_lon: f32,
    pub home_label: String,
    pub current_rx_bps: u64,
    pub current_tx_bps: u64,
    pub peak_rx_bps: u64,
    pub peak_tx_bps: u64,
    pub session_rx_bytes: u64,
    pub session_tx_bytes: u64,
    pub inbound_count: usize,
    pub outbound_count: usize,
    pub listening_count: usize,
    pub unique_countries: usize,
    pub history: Vec<BandwidthPoint>,
    pub flows: Vec<Flow>,
    pub apps: Vec<AppSummary>,
    pub alerts: Vec<AlertEvent>,
}

pub struct TelemetryState {
    pub paused: bool,
    pub backend: CaptureBackendStatus,
    pub home_lat: f32,
    pub home_lon: f32,
    pub home_label: String,
    pub current_rx_bps: u64,
    pub current_tx_bps: u64,
    pub peak_rx_bps: u64,
    pub peak_tx_bps: u64,
    pub session_rx_bytes: u64,
    pub session_tx_bytes: u64,
    pub history: VecDeque<BandwidthPoint>,
    pub flows: Vec<Flow>,
    pub apps: Vec<AppSummary>,
    pub alerts: VecDeque<AlertEvent>,
    pub stats: StatsStore,
    seen_hosts: HashSet<String>,
    seen_countries: HashSet<String>,
    seen_inbound_ips: HashSet<String>,
    alerted_high_risk: HashSet<String>,
    alerted_proxy: HashSet<String>,
}

impl TelemetryState {
    pub fn new() -> Self {
        let mut history = VecDeque::with_capacity(HISTORY_LEN);
        let now = chrono::Utc::now().timestamp();
        for i in (0..HISTORY_LEN).rev() {
            history.push_back(BandwidthPoint {
                timestamp_unix: now - i as i64,
                rx_bps: 0,
                tx_bps: 0,
                active_flows: 0,
                inbound_flows: 0,
                outbound_flows: 0,
                alerts_in_tick: 0,
            });
        }

        Self {
            paused: false,
            backend: CaptureBackendStatus::default(),
            // Default home anchor (auto-detected on startup if online, or customizable by user)
            home_lat: 39.8,
            home_lon: -98.5,
            home_label: "Default Origin (US)".to_string(),
            current_rx_bps: 0,
            current_tx_bps: 0,
            peak_rx_bps: 0,
            peak_tx_bps: 0,
            session_rx_bytes: 0,
            session_tx_bytes: 0,
            history,
            flows: Vec::new(),
            apps: Vec::new(),
            alerts: VecDeque::with_capacity(MAX_ALERTS),
            stats: StatsStore::load_or_default(),
            seen_hosts: HashSet::new(),
            seen_countries: HashSet::new(),
            seen_inbound_ips: HashSet::new(),
            alerted_high_risk: HashSet::new(),
            alerted_proxy: HashSet::new(),
        }
    }

    pub fn set_home_origin(&mut self, lat: f32, lon: f32, label: String) {
        self.home_lat = lat.clamp(-85.0, 85.0);
        self.home_lon = lon.clamp(-180.0, 180.0);
        self.home_label = label;
    }

    pub fn clear_alerts(&mut self) {
        self.alerts.clear();
    }

    pub fn ingest_tick(
        &mut self,
        mut flows: Vec<Flow>,
        total_rx_bps: u64,
        total_tx_bps: u64,
        backend: CaptureBackendStatus,
    ) {
        if self.paused {
            return;
        }

        self.backend = backend;
        self.current_rx_bps = total_rx_bps;
        self.current_tx_bps = total_tx_bps;
        self.peak_rx_bps = self.peak_rx_bps.max(total_rx_bps);
        self.peak_tx_bps = self.peak_tx_bps.max(total_tx_bps);
        self.session_rx_bytes = self.session_rx_bytes.saturating_add(total_rx_bps);
        self.session_tx_bytes = self.session_tx_bytes.saturating_add(total_tx_bps);

        let ts_label = Local::now().format("%H:%M:%S").to_string();
        let mut alerts_in_tick = 0usize;

        // Sort flows by combined throughput descending, then risk descending
        flows.sort_by(|a, b| {
            let a_rate = a.rx_bps + a.tx_bps;
            let b_rate = b.rx_bps + b.tx_bps;
            b_rate
                .cmp(&a_rate)
                .then_with(|| b.osint.risk_score.cmp(&a.osint.risk_score))
                .then_with(|| a.process_name.cmp(&b.process_name))
        });

        let mut inbound_flows = 0usize;
        let mut outbound_flows = 0usize;
        let mut app_map: HashMap<String, AppSummary> = HashMap::new();

        for f in &flows {
            match f.direction {
                Direction::Inbound => inbound_flows += 1,
                Direction::Outbound => outbound_flows += 1,
                _ => {}
            }

            // Aggregate per-app summary
            let app = app_map
                .entry(f.process_name.clone())
                .or_insert_with(|| AppSummary {
                    process_name: f.process_name.clone(),
                    pid: f.pid,
                    rx_bps: 0,
                    tx_bps: 0,
                    total_rx: 0,
                    total_tx: 0,
                    flow_count: 0,
                    inbound_count: 0,
                    outbound_count: 0,
                    max_risk: 0,
                });
            app.rx_bps = app.rx_bps.saturating_add(f.rx_bps);
            app.tx_bps = app.tx_bps.saturating_add(f.tx_bps);
            app.total_rx = app.total_rx.saturating_add(f.total_rx);
            app.total_tx = app.total_tx.saturating_add(f.total_tx);
            app.flow_count += 1;
            if f.direction == Direction::Inbound {
                app.inbound_count += 1;
            } else if f.direction == Direction::Outbound {
                app.outbound_count += 1;
            }
            app.max_risk = app.max_risk.max(f.osint.risk_score);

            // Generate OSINT alerts for public endpoints
            if !f.osint.is_private && f.osint.source != "pending" {
                if f.direction == Direction::Inbound
                    && self.seen_inbound_ips.insert(f.remote_ip.clone())
                {
                    self.push_alert(AlertEvent {
                        timestamp: ts_label.clone(),
                        kind: AlertKind::InboundConnection,
                        severity: f.osint.risk_score.max(45),
                        ip: f.remote_ip.clone(),
                        process_name: f.process_name.clone(),
                        message: format!(
                            "Inbound {}:{} from {} ({}) -> {}",
                            f.protocol.as_str(),
                            f.local_port,
                            f.remote_ip,
                            f.osint.country_code,
                            f.process_name
                        ),
                    });
                    alerts_in_tick += 1;
                }

                if f.osint.risk_score >= 60 && self.alerted_high_risk.insert(f.remote_ip.clone()) {
                    self.push_alert(AlertEvent {
                        timestamp: ts_label.clone(),
                        kind: AlertKind::HighRisk,
                        severity: f.osint.risk_score,
                        ip: f.remote_ip.clone(),
                        process_name: f.process_name.clone(),
                        message: format!(
                            "High-risk endpoint {} (score {}) — {} [{}]",
                            f.remote_ip, f.osint.risk_score, f.osint.org, f.osint.country_code
                        ),
                    });
                    alerts_in_tick += 1;
                }

                if f.osint.is_proxy && self.alerted_proxy.insert(f.remote_ip.clone()) {
                    self.push_alert(AlertEvent {
                        timestamp: ts_label.clone(),
                        kind: AlertKind::ProxyRelay,
                        severity: 70,
                        ip: f.remote_ip.clone(),
                        process_name: f.process_name.clone(),
                        message: format!(
                            "Proxy / Tor / VPN relay {} ({}) via {}",
                            f.remote_ip, f.osint.org, f.process_name
                        ),
                    });
                    alerts_in_tick += 1;
                }

                if !f.osint.country_code.is_empty()
                    && f.osint.country_code != "--"
                    && f.osint.country_code != "LAN"
                    && self.seen_countries.insert(f.osint.country_code.clone())
                {
                    self.push_alert(AlertEvent {
                        timestamp: ts_label.clone(),
                        kind: AlertKind::NewCountry,
                        severity: 25,
                        ip: f.remote_ip.clone(),
                        process_name: f.process_name.clone(),
                        message: format!(
                            "New country observed: {} ({}) via {}",
                            f.osint.country, f.osint.country_code, f.process_name
                        ),
                    });
                    alerts_in_tick += 1;
                }

                if self.seen_hosts.insert(f.remote_ip.clone()) && self.seen_hosts.len() <= 50 {
                    self.push_alert(AlertEvent {
                        timestamp: ts_label.clone(),
                        kind: AlertKind::NewHost,
                        severity: 15,
                        ip: f.remote_ip.clone(),
                        process_name: f.process_name.clone(),
                        message: format!(
                            "New remote host {} ({}) — {}",
                            f.remote_ip, f.osint.org, f.process_name
                        ),
                    });
                    alerts_in_tick += 1;
                }
            }
        }

        let mut apps: Vec<AppSummary> = app_map.into_values().collect();
        apps.sort_by(|a, b| {
            (b.rx_bps + b.tx_bps)
                .cmp(&(a.rx_bps + a.tx_bps))
                .then_with(|| (b.total_rx + b.total_tx).cmp(&(a.total_rx + a.total_tx)))
                .then_with(|| b.flow_count.cmp(&a.flow_count))
        });

        self.stats
            .record_tick(&flows, total_rx_bps, total_tx_bps, alerts_in_tick);

        self.flows = flows;
        self.apps = apps;

        if self.history.len() >= HISTORY_LEN {
            self.history.pop_front();
        }
        self.history.push_back(BandwidthPoint {
            timestamp_unix: chrono::Utc::now().timestamp(),
            rx_bps: total_rx_bps,
            tx_bps: total_tx_bps,
            active_flows: self.flows.len(),
            inbound_flows,
            outbound_flows,
            alerts_in_tick,
        });
    }

    fn push_alert(&mut self, event: AlertEvent) {
        if self.alerts.len() >= MAX_ALERTS {
            self.alerts.pop_back();
        }
        self.alerts.push_front(event);
    }

    pub fn snapshot(&self) -> TelemetrySnapshot {
        let inbound_count = self
            .flows
            .iter()
            .filter(|f| f.direction == Direction::Inbound || f.rx_bps > 0 || f.total_rx > 0)
            .count();
        let outbound_count = self
            .flows
            .iter()
            .filter(|f| f.direction == Direction::Outbound || f.tx_bps > 0 || f.total_tx > 0)
            .count();
        let listening_count = self
            .flows
            .iter()
            .filter(|f| f.direction == Direction::Listening)
            .count();

        TelemetrySnapshot {
            backend: self.backend.clone(),
            home_lat: self.home_lat,
            home_lon: self.home_lon,
            home_label: self.home_label.clone(),
            current_rx_bps: self.current_rx_bps,
            current_tx_bps: self.current_tx_bps,
            peak_rx_bps: self.peak_rx_bps,
            peak_tx_bps: self.peak_tx_bps,
            session_rx_bytes: self.session_rx_bytes,
            session_tx_bytes: self.session_tx_bytes,
            inbound_count,
            outbound_count,
            listening_count,
            unique_countries: self.seen_countries.len(),
            history: self.history.iter().cloned().collect(),
            flows: self.flows.clone(),
            apps: self.apps.clone(),
            alerts: self.alerts.iter().cloned().collect(),
        }
    }

    pub fn export_json(&self) -> Result<PathBuf, String> {
        let snap = self.snapshot();
        let fname = format!(
            "packetatlas_session_{}.json",
            Local::now().format("%Y%m%d_%H%M%S")
        );
        let path = PathBuf::from(&fname);
        let body = serde_json::to_string_pretty(&snap).map_err(|e| e.to_string())?;
        fs::write(&path, body).map_err(|e| e.to_string())?;
        Ok(path)
    }

    pub fn export_csv(&self) -> Result<PathBuf, String> {
        let fname = format!(
            "packetatlas_flows_{}.csv",
            Local::now().format("%Y%m%d_%H%M%S")
        );
        let path = PathBuf::from(&fname);
        let mut out = String::from(
            "direction,protocol,process,pid,local_ip,local_port,remote_ip,remote_port,state,rx_bps,tx_bps,total_rx,total_tx,country,city,asn,org,risk_score\n",
        );
        for f in &self.flows {
            out.push_str(&format!(
                "{},{},\"{}\",{},{},{},{},{},{},{},{},{},{},\"{}\",\"{}\",\"{}\",\"{}\",{}\n",
                f.direction.as_str(),
                f.protocol.as_str(),
                f.process_name.replace('"', "\"\""),
                f.pid,
                f.local_ip,
                f.local_port,
                f.remote_ip,
                f.remote_port,
                f.state,
                f.rx_bps,
                f.tx_bps,
                f.total_rx,
                f.total_tx,
                f.osint.country.replace('"', "\"\""),
                f.osint.city.replace('"', "\"\""),
                f.osint.asn.replace('"', "\"\""),
                f.osint.org.replace('"', "\"\""),
                f.osint.risk_score
            ));
        }
        fs::write(&path, out).map_err(|e| e.to_string())?;
        Ok(path)
    }
}
