use crate::osint::{compute_risk_score, OsintEngine};
use crate::types::{CaptureBackendStatus, Direction, Flow, OsintInfo, Protocol};
use chrono::Utc;

struct SimTemplate {
    protocol: Protocol,
    direction: Direction,
    local_port: u16,
    remote_ip: &'static str,
    remote_port: u16,
    process_name: &'static str,
    process_path: &'static str,
    pid: u32,
    base_rx: u64,
    base_tx: u64,
    country: &'static str,
    cc: &'static str,
    city: &'static str,
    lat: f32,
    lon: f32,
    asn: &'static str,
    isp: &'static str,
    org: &'static str,
    rdns: &'static str,
    is_proxy: bool,
    is_hosting: bool,
    abuse_score: Option<u8>,
}

const TEMPLATES: &[SimTemplate] = &[
    SimTemplate {
        protocol: Protocol::Tcp,
        direction: Direction::Outbound,
        local_port: 54102,
        remote_ip: "142.250.190.46",
        remote_port: 443,
        process_name: "chrome.exe",
        process_path: r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        pid: 4812,
        base_rx: 420_000,
        base_tx: 48_000,
        country: "United States",
        cc: "US",
        city: "Mountain View",
        lat: 37.4056,
        lon: -122.0775,
        asn: "AS15169 Google LLC",
        isp: "Google LLC",
        org: "Google Cloud",
        rdns: "ord38s28-in-f14.1e100.net",
        is_proxy: false,
        is_hosting: true,
        abuse_score: Some(0),
    },
    SimTemplate {
        protocol: Protocol::Udp,
        direction: Direction::Outbound,
        local_port: 58921,
        remote_ip: "162.159.135.234",
        remote_port: 443,
        process_name: "Discord.exe",
        process_path: r"C:\Users\User\AppData\Local\Discord\Discord.exe",
        pid: 9320,
        base_rx: 185_000,
        base_tx: 162_000,
        country: "United States",
        cc: "US",
        city: "Ashburn",
        lat: 39.0438,
        lon: -77.4874,
        asn: "AS13335 Cloudflare, Inc.",
        isp: "Cloudflare",
        org: "Discord Voice / Cloudflare",
        rdns: "discord.cloudflare.net",
        is_proxy: false,
        is_hosting: true,
        abuse_score: Some(0),
    },
    SimTemplate {
        protocol: Protocol::Tcp,
        direction: Direction::Outbound,
        local_port: 51944,
        remote_ip: "140.82.121.4",
        remote_port: 443,
        process_name: "Code.exe",
        process_path: r"C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe",
        pid: 7410,
        base_rx: 92_000,
        base_tx: 64_000,
        country: "Netherlands",
        cc: "NL",
        city: "Amsterdam",
        lat: 52.3676,
        lon: 4.9041,
        asn: "AS36459 GitHub, Inc.",
        isp: "GitHub",
        org: "GitHub EU Edge",
        rdns: "lb-140-82-121-4-ams.github.com",
        is_proxy: false,
        is_hosting: true,
        abuse_score: Some(0),
    },
    SimTemplate {
        protocol: Protocol::Tcp,
        direction: Direction::Outbound,
        local_port: 60412,
        remote_ip: "185.220.101.42",
        remote_port: 9001,
        process_name: "powershell.exe",
        process_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        pid: 11204,
        base_rx: 14_000,
        base_tx: 82_000,
        country: "Germany",
        cc: "DE",
        city: "Frankfurt",
        lat: 50.1109,
        lon: 8.6821,
        asn: "AS205100 F3 Netze e.V.",
        isp: "F3 Netze e.V.",
        org: "Tor Exit Relay",
        rdns: "tor-exit-42.f3netze.de",
        is_proxy: true,
        is_hosting: true,
        abuse_score: Some(88),
    },
    SimTemplate {
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        local_port: 3389,
        remote_ip: "45.155.205.93",
        remote_port: 49218,
        process_name: "svchost.exe",
        process_path: r"C:\Windows\System32\svchost.exe",
        pid: 1244,
        base_rx: 28_000,
        base_tx: 6_200,
        country: "Russia",
        cc: "RU",
        city: "Moscow",
        lat: 55.7558,
        lon: 37.6173,
        asn: "AS49505 OOO Network of data-centers Selectel",
        isp: "Selectel",
        org: "Unknown Scanner / RDP Probe",
        rdns: "",
        is_proxy: true,
        is_hosting: true,
        abuse_score: Some(96),
    },
    SimTemplate {
        protocol: Protocol::Tcp,
        direction: Direction::Outbound,
        local_port: 57120,
        remote_ip: "13.107.246.40",
        remote_port: 443,
        process_name: "msedge.exe",
        process_path: r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        pid: 6220,
        base_rx: 210_000,
        base_tx: 24_000,
        country: "United Kingdom",
        cc: "GB",
        city: "London",
        lat: 51.5074,
        lon: -0.1278,
        asn: "AS8075 Microsoft Corporation",
        isp: "Microsoft Azure",
        org: "Microsoft Front Door",
        rdns: "edge.microsoft.com",
        is_proxy: false,
        is_hosting: true,
        abuse_score: Some(0),
    },
    SimTemplate {
        protocol: Protocol::Udp,
        direction: Direction::Outbound,
        local_port: 61205,
        remote_ip: "103.28.54.16",
        remote_port: 27015,
        process_name: "steam.exe",
        process_path: r"C:\Program Files (x86)\Steam\steam.exe",
        pid: 8810,
        base_rx: 340_000,
        base_tx: 95_000,
        country: "Singapore",
        cc: "SG",
        city: "Singapore",
        lat: 1.3521,
        lon: 103.8198,
        asn: "AS32590 Valve Corporation",
        isp: "Valve Corporation",
        org: "Steam Relay Singapore",
        rdns: "sgp-relay.valve.net",
        is_proxy: false,
        is_hosting: true,
        abuse_score: Some(0),
    },
    SimTemplate {
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        local_port: 22,
        remote_ip: "133.242.18.91",
        remote_port: 55102,
        process_name: "sshd.exe",
        process_path: r"C:\Windows\System32\OpenSSH\sshd.exe",
        pid: 2180,
        base_rx: 44_000,
        base_tx: 112_000,
        country: "Japan",
        cc: "JP",
        city: "Tokyo",
        lat: 35.6762,
        lon: 139.6503,
        asn: "AS9370 SAKURA Internet Inc.",
        isp: "SAKURA Internet",
        org: "Tokyo Remote Admin",
        rdns: "tk2-201-10191.vs.sakura.ne.jp",
        is_proxy: false,
        is_hosting: true,
        abuse_score: Some(4),
    },
    SimTemplate {
        protocol: Protocol::Tcp,
        direction: Direction::Outbound,
        local_port: 50321,
        remote_ip: "177.71.207.14",
        remote_port: 443,
        process_name: "Spotify.exe",
        process_path: r"C:\Users\User\AppData\Roaming\Spotify\Spotify.exe",
        pid: 5512,
        base_rx: 155_000,
        base_tx: 11_000,
        country: "Brazil",
        cc: "BR",
        city: "Sao Paulo",
        lat: -23.5505,
        lon: -46.6333,
        asn: "AS16509 Amazon.com, Inc.",
        isp: "Amazon AWS",
        org: "Spotify Audio CDN",
        rdns: "audio-sa.spotify.com",
        is_proxy: false,
        is_hosting: true,
        abuse_score: Some(0),
    },
    SimTemplate {
        protocol: Protocol::Tcp,
        direction: Direction::Listening,
        local_port: 445,
        remote_ip: "0.0.0.0",
        remote_port: 0,
        process_name: "System (Kernel)",
        process_path: "ntoskrnl.exe",
        pid: 4,
        base_rx: 0,
        base_tx: 0,
        country: "Listening Socket",
        cc: "LAN",
        city: "Local Host",
        lat: 0.0,
        lon: 0.0,
        asn: "Local",
        isp: "Windows SMB",
        org: "Local Listener",
        rdns: "",
        is_proxy: false,
        is_hosting: false,
        abuse_score: None,
    },
];

pub struct TrafficSimulator {
    tick: u64,
    totals: Vec<(u64, u64)>,
}

impl TrafficSimulator {
    pub fn new() -> Self {
        Self {
            tick: 0,
            totals: vec![(0, 0); TEMPLATES.len()],
        }
    }

    pub fn next_tick(&mut self, osint: &OsintEngine) -> (Vec<Flow>, u64, u64, CaptureBackendStatus) {
        self.tick = self.tick.wrapping_add(1);
        let now = Utc::now().timestamp();

        let mut flows = Vec::with_capacity(TEMPLATES.len());
        let mut total_rx = 0u64;
        let mut total_tx = 0u64;

        for (i, t) in TEMPLATES.iter().enumerate() {
            // Smooth wave + deterministic jitter so graphs look organic and alive
            let phase = (self.tick as f64) * 0.45 + (i as f64) * 1.1;
            let wave = 0.65 + 0.55 * phase.sin().abs();
            let spike = if (self.tick + i as u64 * 3) % 13 == 0 {
                2.1
            } else {
                1.0
            };

            let rx = ((t.base_rx as f64) * wave * spike) as u64;
            let tx = ((t.base_tx as f64) * (0.7 + 0.4 * phase.cos().abs())) as u64;
            self.totals[i].0 = self.totals[i].0.saturating_add(rx);
            self.totals[i].1 = self.totals[i].1.saturating_add(tx);
            total_rx = total_rx.saturating_add(rx);
            total_tx = total_tx.saturating_add(tx);

            let mut info = if t.direction == Direction::Listening {
                OsintInfo::private_network(t.remote_ip, "Listening Socket")
            } else {
                let mut o = OsintInfo {
                    ip: t.remote_ip.to_string(),
                    country: t.country.to_string(),
                    country_code: t.cc.to_string(),
                    city: t.city.to_string(),
                    lat: t.lat,
                    lon: t.lon,
                    asn: t.asn.to_string(),
                    isp: t.isp.to_string(),
                    org: t.org.to_string(),
                    rdns: t.rdns.to_string(),
                    is_proxy: t.is_proxy,
                    is_hosting: t.is_hosting,
                    is_private: false,
                    risk_score: 0,
                    risk_reasons: Vec::new(),
                    abuseipdb_score: t.abuse_score,
                    virustotal_malicious: if t.abuse_score.unwrap_or(0) > 85 {
                        Some(4)
                    } else {
                        Some(0)
                    },
                    source: "sim".to_string(),
                };
                compute_risk_score(&mut o);
                o
            };

            // Also seed OSINT engine so Deep Inspector works seamlessly
            if !info.is_private {
                osint.seed(info.clone());
            } else {
                info.risk_score = 0;
            }

            let key = format!(
                "{}:192.168.1.42:{}->{}:{}",
                t.protocol.as_str(),
                t.local_port,
                t.remote_ip,
                t.remote_port
            );

            flows.push(Flow {
                key,
                protocol: t.protocol,
                direction: t.direction,
                local_ip: "192.168.1.42".to_string(),
                local_port: t.local_port,
                remote_ip: t.remote_ip.to_string(),
                remote_port: t.remote_port,
                state: if t.direction == Direction::Listening {
                    "LISTEN".to_string()
                } else if t.protocol == Protocol::Udp {
                    "UDP".to_string()
                } else {
                    "ESTABLISHED".to_string()
                },
                pid: t.pid,
                process_name: t.process_name.to_string(),
                process_path: t.process_path.to_string(),
                rx_bps: rx,
                tx_bps: tx,
                total_rx: self.totals[i].0,
                total_tx: self.totals[i].1,
                packets_rx: (self.totals[i].0 / 900).max(1),
                packets_tx: (self.totals[i].1 / 700).max(1),
                exact_accounting: true,
                last_seen_unix: now,
                osint: info,
            });
        }

        let status = CaptureBackendStatus {
            raw_capture_active: true,
            backend_name: "Global Threat & Traffic Simulator".to_string(),
            elevation_note: "Simulated global dataset — switch to LIVE for real host traffic"
                .to_string(),
            raw_packets_captured: self.tick * 184,
            active_interfaces: vec!["Ethernet0 (Sim)".to_string(), "Wi-Fi (Sim)".to_string()],
        };

        (flows, total_rx, total_tx, status)
    }
}
