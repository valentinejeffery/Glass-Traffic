pub mod packet;

#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
mod linux;

use crate::capture::packet::{FlowByteDelta, FlowTuple, PacketTracker};
use crate::osint::OsintEngine;
use crate::types::{
    CaptureBackendStatus, Direction, Flow, InterfaceCounters, Protocol, RawSocketEntry,
};
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct HybridCapture {
    tracker: Arc<PacketTracker>,
    stop_flag: Arc<AtomicBool>,
    raw_active: bool,
    elevation_note: String,
    prev_iface_rx: Option<u64>,
    prev_iface_tx: Option<u64>,
    /// Cumulative totals per flow key across ticks
    cumulative: HashMap<String, (u64, u64, u64, u64)>,
}

impl HybridCapture {
    pub fn new() -> Self {
        let local_ips = platform_discover_local_ips();
        let tracker = PacketTracker::new(local_ips);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let (raw_active, elevation_note) =
            platform_start_raw_capture(Arc::clone(&tracker), Arc::clone(&stop_flag));

        Self {
            tracker,
            stop_flag,
            raw_active,
            elevation_note,
            prev_iface_rx: None,
            prev_iface_tx: None,
            cumulative: HashMap::new(),
        }
    }

    pub fn backend_status(&self, active_interfaces: Vec<String>) -> CaptureBackendStatus {
        let backend_name = if cfg!(windows) {
            if self.raw_active {
                "Windows SIO_RCVALL + iphlpapi (Hybrid)".to_string()
            } else {
                "Windows iphlpapi Socket Table".to_string()
            }
        } else if cfg!(target_os = "linux") {
            if self.raw_active {
                "Linux AF_PACKET + /proc/net (Hybrid)".to_string()
            } else {
                "Linux /proc/net Socket Table".to_string()
            }
        } else {
            "Cross-Platform Fallback".to_string()
        };

        CaptureBackendStatus {
            raw_capture_active: self.raw_active,
            backend_name,
            elevation_note: self.elevation_note.clone(),
            raw_packets_captured: self.tracker.total_packets(),
            active_interfaces,
        }
    }

    /// Perform one 1-second capture tick:
    /// returns `(flows, total_rx_bps, total_tx_bps, backend_status)`.
    pub fn poll_tick(&mut self, osint: &OsintEngine) -> (Vec<Flow>, u64, u64, CaptureBackendStatus) {
        let now = Utc::now().timestamp();
        let (sockets, counters) = platform_collect_sockets_and_counters();
        let mut raw_deltas = self.tracker.drain_deltas();

        // Keep local IP list fresh (e.g. if Wi-Fi/VPN changes)
        if !sockets.is_empty() {
            let mut locals = platform_discover_local_ips();
            for s in &sockets {
                if !s.local_ip.is_unspecified() {
                    locals.insert(s.local_ip);
                }
            }
            self.tracker.update_local_ips(locals);
        }

        // Compute hardware interface RX/TX delta for accurate total bandwidth & non-admin fallback
        let iface_rx_delta = self
            .prev_iface_rx
            .map(|prev| counters.total_rx_bytes.saturating_sub(prev))
            .unwrap_or(0);
        let iface_tx_delta = self
            .prev_iface_tx
            .map(|prev| counters.total_tx_bytes.saturating_sub(prev))
            .unwrap_or(0);
        self.prev_iface_rx = Some(counters.total_rx_bytes);
        self.prev_iface_tx = Some(counters.total_tx_bytes);

        // Identify listening local ports so we can accurately classify INBOUND vs OUTBOUND connections
        let mut listening_ports: HashSet<(Protocol, u16)> = HashSet::new();
        for s in &sockets {
            if s.state == "LISTEN" || s.remote_ip.is_unspecified() {
                listening_ports.insert((s.protocol, s.local_port));
            }
        }

        // Count active non-listening flows for fallback interface-delta distribution
        let active_external_count = sockets
            .iter()
            .filter(|s| {
                s.state == "ESTABLISHED"
                    && !s.remote_ip.is_unspecified()
                    && !s.remote_ip.is_loopback()
            })
            .count()
            .max(1) as u64;

        let mut flows = Vec::with_capacity(sockets.len() + raw_deltas.len());
        let mut raw_total_rx = 0u64;
        let mut raw_total_tx = 0u64;

        // 1. Process all OS socket-table entries (with process attribution)
        for s in sockets {
            let tuple = FlowTuple {
                protocol: s.protocol,
                local_ip: s.local_ip,
                local_port: s.local_port,
                remote_ip: s.remote_ip,
                remote_port: s.remote_port,
            };

            let matched_delta: Option<FlowByteDelta> = raw_deltas.remove(&tuple);
            let direction = classify_direction(&s, &listening_ports, matched_delta.as_ref());

            let (rx_bps, tx_bps, pkt_rx, pkt_tx, exact) = if let Some(d) = matched_delta {
                raw_total_rx = raw_total_rx.saturating_add(d.rx_bytes);
                raw_total_tx = raw_total_tx.saturating_add(d.tx_bytes);
                (d.rx_bytes, d.tx_bytes, d.rx_packets, d.tx_packets, true)
            } else if !self.raw_active
                && s.state == "ESTABLISHED"
                && !s.remote_ip.is_unspecified()
                && !s.remote_ip.is_loopback()
            {
                // Non-admin fallback: attribute interface delta evenly across active external flows
                (
                    iface_rx_delta / active_external_count,
                    iface_tx_delta / active_external_count,
                    0,
                    0,
                    false,
                )
            } else {
                (0, 0, 0, 0, self.raw_active)
            };

            let key = format!(
                "{}:{}:{}->{}:{}",
                s.protocol.as_str(),
                s.local_ip,
                s.local_port,
                s.remote_ip,
                s.remote_port
            );

            let (tot_rx, tot_tx, tot_prx, tot_ptx) = self.update_cumulative(&key, rx_bps, tx_bps, pkt_rx, pkt_tx);

            let remote_ip_str = s.remote_ip.to_string();
            let osint_info = if s.remote_ip.is_unspecified() {
                crate::types::OsintInfo::private_network(&remote_ip_str, "Listening Socket")
            } else {
                osint.lookup(&remote_ip_str)
            };

            flows.push(Flow {
                key,
                protocol: s.protocol,
                direction,
                local_ip: s.local_ip.to_string(),
                local_port: s.local_port,
                remote_ip: remote_ip_str,
                remote_port: s.remote_port,
                state: s.state,
                pid: s.pid,
                process_name: s.process_name,
                process_path: s.process_path,
                rx_bps,
                tx_bps,
                total_rx: tot_rx,
                total_tx: tot_tx,
                packets_rx: tot_prx,
                packets_tx: tot_ptx,
                exact_accounting: exact,
                last_seen_unix: now,
                osint: osint_info,
            });
        }

        // 2. Surface any raw-captured packets (e.g. UDP/ICMP/ephemeral flows) not in the socket snapshot
        for (tuple, d) in raw_deltas {
            if d.rx_bytes == 0 && d.tx_bytes == 0 {
                continue;
            }
            raw_total_rx = raw_total_rx.saturating_add(d.rx_bytes);
            raw_total_tx = raw_total_tx.saturating_add(d.tx_bytes);

            let direction = d.first_direction.unwrap_or_else(|| {
                if tuple.remote_ip.is_loopback() {
                    Direction::Local
                } else if d.rx_bytes > d.tx_bytes && listening_ports.contains(&(tuple.protocol, tuple.local_port)) {
                    Direction::Inbound
                } else {
                    Direction::Outbound
                }
            });

            let key = format!(
                "{}:{}:{}->{}:{}",
                tuple.protocol.as_str(),
                tuple.local_ip,
                tuple.local_port,
                tuple.remote_ip,
                tuple.remote_port
            );
            let (tot_rx, tot_tx, tot_prx, tot_ptx) =
                self.update_cumulative(&key, d.rx_bytes, d.tx_bytes, d.rx_packets, d.tx_packets);

            let remote_ip_str = tuple.remote_ip.to_string();
            let osint_info = osint.lookup(&remote_ip_str);

            flows.push(Flow {
                key,
                protocol: tuple.protocol,
                direction,
                local_ip: tuple.local_ip.to_string(),
                local_port: tuple.local_port,
                remote_ip: remote_ip_str,
                remote_port: tuple.remote_port,
                state: "RAW_PACKET".to_string(),
                pid: 0,
                process_name: format!("Raw {} Packet", tuple.protocol.as_str()),
                process_path: String::new(),
                rx_bps: d.rx_bytes,
                tx_bps: d.tx_bytes,
                total_rx: tot_rx,
                total_tx: tot_tx,
                packets_rx: tot_prx,
                packets_tx: tot_ptx,
                exact_accounting: true,
                last_seen_unix: now,
                osint: osint_info,
            });
        }

        // Prefer interface hardware counters when higher (captures all traffic including kernel/VPN),
        // or raw packet totals when interface counters are unavailable.
        let total_rx_bps = iface_rx_delta.max(raw_total_rx);
        let total_tx_bps = iface_tx_delta.max(raw_total_tx);

        let status = self.backend_status(counters.active_interfaces);
        (flows, total_rx_bps, total_tx_bps, status)
    }

    fn update_cumulative(
        &mut self,
        key: &str,
        rx: u64,
        tx: u64,
        prx: u64,
        ptx: u64,
    ) -> (u64, u64, u64, u64) {
        let entry = self
            .cumulative
            .entry(key.to_string())
            .or_insert((0, 0, 0, 0));
        entry.0 = entry.0.saturating_add(rx);
        entry.1 = entry.1.saturating_add(tx);
        entry.2 = entry.2.saturating_add(prx);
        entry.3 = entry.3.saturating_add(ptx);
        *entry
    }
}

impl Drop for HybridCapture {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }
}

fn classify_direction(
    s: &RawSocketEntry,
    listening_ports: &HashSet<(Protocol, u16)>,
    raw_delta: Option<&FlowByteDelta>,
) -> Direction {
    if s.state == "LISTEN" || s.state == "UDP_LISTEN" || s.remote_ip.is_unspecified() {
        return Direction::Listening;
    }
    if s.remote_ip.is_loopback() || s.local_ip == s.remote_ip {
        return Direction::Local;
    }
    // If our local port is an open listening server port and remote port is ephemeral, it's INBOUND
    if listening_ports.contains(&(s.protocol, s.local_port)) && s.remote_port >= 1024 {
        return Direction::Inbound;
    }
    // Well-known server port locally (< 1024) with high remote port is also inbound
    if s.local_port > 0 && s.local_port < 1024 && s.remote_port >= 1024 {
        return Direction::Inbound;
    }
    if let Some(d) = raw_delta {
        if let Some(dir) = d.first_direction {
            return dir;
        }
    }
    Direction::Outbound
}

fn platform_discover_local_ips() -> HashSet<IpAddr> {
    #[cfg(windows)]
    {
        windows::discover_local_ips()
    }
    #[cfg(target_os = "linux")]
    {
        linux::discover_local_ips()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        HashSet::new()
    }
}

fn platform_start_raw_capture(
    tracker: Arc<PacketTracker>,
    stop_flag: Arc<AtomicBool>,
) -> (bool, String) {
    #[cfg(windows)]
    {
        windows::start_raw_capture(tracker, stop_flag)
    }
    #[cfg(target_os = "linux")]
    {
        linux::start_raw_capture(tracker, stop_flag)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (tracker, stop_flag);
        (false, "OS socket fallback only on this platform".into())
    }
}

fn platform_collect_sockets_and_counters() -> (Vec<RawSocketEntry>, InterfaceCounters) {
    #[cfg(windows)]
    {
        windows::collect_sockets_and_counters()
    }
    #[cfg(target_os = "linux")]
    {
        linux::collect_sockets_and_counters()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        (Vec::new(), InterfaceCounters::default())
    }
}
