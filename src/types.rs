use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Icmp => "ICMP",
            Protocol::Other(_) => "OTHER",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
    Listening,
    Local,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::Inbound => "IN",
            Direction::Outbound => "OUT",
            Direction::Listening => "LISTEN",
            Direction::Local => "LOCAL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureMode {
    Live,
    Sim,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureBackendStatus {
    pub raw_capture_active: bool,
    pub backend_name: String,
    pub elevation_note: String,
    pub raw_packets_captured: u64,
    pub active_interfaces: Vec<String>,
}

impl Default for CaptureBackendStatus {
    fn default() -> Self {
        Self {
            raw_capture_active: false,
            backend_name: "Initializing...".to_string(),
            elevation_note: String::new(),
            raw_packets_captured: 0,
            active_interfaces: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintInfo {
    pub ip: String,
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub lat: f32,
    pub lon: f32,
    pub asn: String,
    pub isp: String,
    pub org: String,
    pub rdns: String,
    pub is_proxy: bool,
    pub is_hosting: bool,
    pub is_private: bool,
    pub risk_score: u8,
    pub risk_reasons: Vec<String>,
    pub abuseipdb_score: Option<u8>,
    pub virustotal_malicious: Option<u32>,
    pub source: String,
}

impl OsintInfo {
    pub fn pending(ip: &str) -> Self {
        Self {
            ip: ip.to_string(),
            country: "Resolving...".to_string(),
            country_code: "--".to_string(),
            city: String::new(),
            lat: 0.0,
            lon: 0.0,
            asn: String::new(),
            isp: String::new(),
            org: String::new(),
            rdns: String::new(),
            is_proxy: false,
            is_hosting: false,
            is_private: false,
            risk_score: 0,
            risk_reasons: Vec::new(),
            abuseipdb_score: None,
            virustotal_malicious: None,
            source: "pending".to_string(),
        }
    }

    pub fn private_network(ip: &str, label: &str) -> Self {
        Self {
            ip: ip.to_string(),
            country: label.to_string(),
            country_code: "LAN".to_string(),
            city: "Local Network".to_string(),
            lat: 0.0,
            lon: 0.0,
            asn: "RFC1918 / Local".to_string(),
            isp: "Local Interface".to_string(),
            org: label.to_string(),
            rdns: String::new(),
            is_proxy: false,
            is_hosting: false,
            is_private: true,
            risk_score: 0,
            risk_reasons: Vec::new(),
            abuseipdb_score: None,
            virustotal_malicious: None,
            source: "private".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub key: String,
    pub protocol: Protocol,
    pub direction: Direction,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub total_rx: u64,
    pub total_tx: u64,
    pub packets_rx: u64,
    pub packets_tx: u64,
    pub exact_accounting: bool,
    pub last_seen_unix: i64,
    pub osint: OsintInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertKind {
    HighRisk,
    ProxyRelay,
    NewCountry,
    NewHost,
    InboundConnection,
}

impl AlertKind {
    pub fn label(&self) -> &'static str {
        match self {
            AlertKind::HighRisk => "HIGH_RISK",
            AlertKind::ProxyRelay => "PROXY_RELAY",
            AlertKind::NewCountry => "NEW_COUNTRY",
            AlertKind::NewHost => "NEW_HOST",
            AlertKind::InboundConnection => "INBOUND_CONN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    pub timestamp: String,
    pub kind: AlertKind,
    pub severity: u8,
    pub ip: String,
    pub process_name: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthPoint {
    pub timestamp_unix: i64,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub active_flows: usize,
    pub inbound_flows: usize,
    pub outbound_flows: usize,
    pub alerts_in_tick: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSummary {
    pub process_name: String,
    pub pid: u32,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub total_rx: u64,
    pub total_tx: u64,
    pub flow_count: usize,
    pub inbound_count: usize,
    pub outbound_count: usize,
    pub max_risk: u8,
}

/// Raw socket record produced by platform socket-table collectors (Windows iphlpapi / Linux /proc/net)
#[derive(Debug, Clone)]
pub struct RawSocketEntry {
    pub protocol: Protocol,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
}

/// Interface-level byte counters for fallback delta accounting
#[derive(Debug, Clone, Default)]
pub struct InterfaceCounters {
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub active_interfaces: Vec<String>,
}

/// Format bytes/sec into a crisp human-readable rate string
pub fn format_rate(bps: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let v = bps as f64;
    if v >= GB {
        format!("{:.2} GB/s", v / GB)
    } else if v >= MB {
        format!("{:.2} MB/s", v / MB)
    } else if v >= KB {
        format!("{:.1} KB/s", v / KB)
    } else {
        format!("{} B/s", bps)
    }
}

/// Format cumulative byte count into human-readable size
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let v = bytes as f64;
    if v >= GB {
        format!("{:.2} GB", v / GB)
    } else if v >= MB {
        format!("{:.2} MB", v / MB)
    } else if v >= KB {
        format!("{:.1} KB", v / KB)
    } else {
        format!("{} B", bytes)
    }
}

/// Classify whether an IP address is private, loopback, link-local, multicast, or unspecified.
pub fn classify_special_ip(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                Some("Unspecified (0.0.0.0)")
            } else if v4.is_loopback() {
                Some("Loopback")
            } else if v4.is_private() {
                Some("Private LAN (RFC1918)")
            } else if v4.is_link_local() {
                Some("Link-Local (APIPA)")
            } else if v4.is_multicast() {
                Some("Multicast")
            } else if v4.is_broadcast() {
                Some("Broadcast")
            } else if v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64 {
                Some("CGNAT (RFC6598)")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                Some("Unspecified (::)")
            } else if v6.is_loopback() {
                Some("Loopback (::1)")
            } else if v6.is_multicast() {
                Some("IPv6 Multicast")
            } else if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                Some("IPv6 Unique Local (ULA)")
            } else if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                Some("IPv6 Link-Local")
            } else {
                None
            }
        }
    }
}
