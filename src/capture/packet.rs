use crate::types::{Direction, Protocol};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    pub protocol: Protocol,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
}

#[derive(Debug, Clone, Default)]
pub struct FlowByteDelta {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub first_direction: Option<Direction>,
}

/// Thread-safe accumulator updated by the raw packet capture thread(s) and drained every 1s tick.
pub struct PacketTracker {
    local_ips: Mutex<HashSet<IpAddr>>,
    deltas: Mutex<HashMap<FlowTuple, FlowByteDelta>>,
    total_packets: AtomicU64,
}

impl PacketTracker {
    pub fn new(initial_local_ips: HashSet<IpAddr>) -> Arc<Self> {
        Arc::new(Self {
            local_ips: Mutex::new(initial_local_ips),
            deltas: Mutex::new(HashMap::new()),
            total_packets: AtomicU64::new(0),
        })
    }

    pub fn update_local_ips(&self, ips: HashSet<IpAddr>) {
        if let Ok(mut guard) = self.local_ips.lock() {
            *guard = ips;
        }
    }

    pub fn total_packets(&self) -> u64 {
        self.total_packets.load(Ordering::Relaxed)
    }

    /// Drain all accumulated per-flow byte deltas since the previous tick.
    pub fn drain_deltas(&self) -> HashMap<FlowTuple, FlowByteDelta> {
        if let Ok(mut guard) = self.deltas.lock() {
            std::mem::take(&mut *guard)
        } else {
            HashMap::new()
        }
    }

    /// Parse a raw IP packet (starting at IPv4 or IPv6 header, no Ethernet header)
    /// and record its incoming or outgoing byte count.
    pub fn ingest_ip_packet(&self, buf: &[u8]) {
        let Some(parsed) = parse_ip_packet(buf) else {
            return;
        };
        self.record_parsed(parsed);
    }

    /// Parse a raw Ethernet frame (used by Linux AF_PACKET) and record its byte count.
    #[allow(dead_code)]
    pub fn ingest_ethernet_frame(&self, buf: &[u8]) {
        if buf.len() < 14 {
            return;
        }
        let mut ethertype = u16::from_be_bytes([buf[12], buf[13]]);
        let mut offset = 14usize;
        // Handle 802.1Q VLAN tag if present
        if ethertype == 0x8100 && buf.len() >= 18 {
            ethertype = u16::from_be_bytes([buf[16], buf[17]]);
            offset = 18;
        }
        if ethertype == 0x0800 || ethertype == 0x86DD {
            self.ingest_ip_packet(&buf[offset..]);
        }
    }

    fn record_parsed(&self, pkt: ParsedPacket) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);

        let (src_is_local, dst_is_local) = if let Ok(locals) = self.local_ips.lock() {
            (
                locals.contains(&pkt.src_ip) || pkt.src_ip.is_loopback(),
                locals.contains(&pkt.dst_ip) || pkt.dst_ip.is_loopback(),
            )
        } else {
            (false, false)
        };

        let (tuple, is_tx, dir) = if src_is_local && !dst_is_local {
            (
                FlowTuple {
                    protocol: pkt.protocol,
                    local_ip: pkt.src_ip,
                    local_port: pkt.src_port,
                    remote_ip: pkt.dst_ip,
                    remote_port: pkt.dst_port,
                },
                true,
                Direction::Outbound,
            )
        } else if dst_is_local && !src_is_local {
            (
                FlowTuple {
                    protocol: pkt.protocol,
                    local_ip: pkt.dst_ip,
                    local_port: pkt.dst_port,
                    remote_ip: pkt.src_ip,
                    remote_port: pkt.src_port,
                },
                false,
                Direction::Inbound,
            )
        } else if src_is_local && dst_is_local {
            (
                FlowTuple {
                    protocol: pkt.protocol,
                    local_ip: pkt.src_ip,
                    local_port: pkt.src_port,
                    remote_ip: pkt.dst_ip,
                    remote_port: pkt.dst_port,
                },
                true,
                Direction::Local,
            )
        } else {
            // Promiscuous packet not matching a known local IP — treat as inbound observation
            (
                FlowTuple {
                    protocol: pkt.protocol,
                    local_ip: pkt.dst_ip,
                    local_port: pkt.dst_port,
                    remote_ip: pkt.src_ip,
                    remote_port: pkt.src_port,
                },
                false,
                Direction::Inbound,
            )
        };

        if let Ok(mut guard) = self.deltas.lock() {
            let entry = guard.entry(tuple).or_default();
            if entry.first_direction.is_none() {
                entry.first_direction = Some(dir);
            }
            if is_tx {
                entry.tx_bytes = entry.tx_bytes.saturating_add(pkt.total_len as u64);
                entry.tx_packets = entry.tx_packets.saturating_add(1);
            } else {
                entry.rx_bytes = entry.rx_bytes.saturating_add(pkt.total_len as u64);
                entry.rx_packets = entry.rx_packets.saturating_add(1);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ParsedPacket {
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub total_len: usize,
}

pub fn parse_ip_packet(buf: &[u8]) -> Option<ParsedPacket> {
    if buf.is_empty() {
        return None;
    }
    let version = buf[0] >> 4;
    match version {
        4 => parse_ipv4(buf),
        6 => parse_ipv6(buf),
        _ => None,
    }
}

fn parse_ipv4(buf: &[u8]) -> Option<ParsedPacket> {
    if buf.len() < 20 {
        return None;
    }
    let ihl = ((buf[0] & 0x0F) as usize) * 4;
    if ihl < 20 || buf.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let total_len = total_len.max(buf.len());
    let proto_num = buf[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));

    let payload = &buf[ihl..];
    let (protocol, src_port, dst_port) = parse_transport(proto_num, payload);
    Some(ParsedPacket {
        protocol,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        total_len,
    })
}

fn parse_ipv6(buf: &[u8]) -> Option<ParsedPacket> {
    if buf.len() < 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let total_len = (40 + payload_len).max(buf.len());
    let next_header = buf[6];
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&buf[8..24]);
    dst.copy_from_slice(&buf[24..40]);
    let src_ip = IpAddr::V6(Ipv6Addr::from(src));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst));

    let payload = &buf[40..];
    let (protocol, src_port, dst_port) = parse_transport(next_header, payload);
    Some(ParsedPacket {
        protocol,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        total_len,
    })
}

fn parse_transport(proto_num: u8, payload: &[u8]) -> (Protocol, u16, u16) {
    match proto_num {
        6 => {
            if payload.len() >= 4 {
                (
                    Protocol::Tcp,
                    u16::from_be_bytes([payload[0], payload[1]]),
                    u16::from_be_bytes([payload[2], payload[3]]),
                )
            } else {
                (Protocol::Tcp, 0, 0)
            }
        }
        17 => {
            if payload.len() >= 4 {
                (
                    Protocol::Udp,
                    u16::from_be_bytes([payload[0], payload[1]]),
                    u16::from_be_bytes([payload[2], payload[3]]),
                )
            } else {
                (Protocol::Udp, 0, 0)
            }
        }
        1 | 58 => (Protocol::Icmp, 0, 0),
        other => (Protocol::Other(other), 0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_tcp_packet_and_tracks_outbound() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // IPv4, IHL=5 (20 bytes)
        pkt[2] = 0x00;
        pkt[3] = 40;
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[192, 168, 1, 10]); // src
        pkt[16..20].copy_from_slice(&[1, 1, 1, 1]); // dst
        pkt[20..22].copy_from_slice(&54321u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());

        let mut locals = HashSet::new();
        locals.insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        let tracker = PacketTracker::new(locals);
        tracker.ingest_ip_packet(&pkt);

        let deltas = tracker.drain_deltas();
        assert_eq!(deltas.len(), 1);
        let (tuple, delta) = deltas.into_iter().next().unwrap();
        assert_eq!(tuple.protocol, Protocol::Tcp);
        assert_eq!(tuple.local_port, 54321);
        assert_eq!(tuple.remote_port, 443);
        assert_eq!(delta.tx_bytes, 40);
        assert_eq!(delta.rx_bytes, 0);
        assert_eq!(delta.first_direction, Some(Direction::Outbound));
    }

    #[test]
    fn parses_ipv4_udp_inbound_packet() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2] = 0x00;
        pkt[3] = 28;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[8, 8, 8, 8]); // remote src
        pkt[16..20].copy_from_slice(&[192, 168, 1, 10]); // local dst
        pkt[20..22].copy_from_slice(&53u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&55123u16.to_be_bytes());

        let mut locals = HashSet::new();
        locals.insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        let tracker = PacketTracker::new(locals);
        tracker.ingest_ip_packet(&pkt);

        let deltas = tracker.drain_deltas();
        let (tuple, delta) = deltas.into_iter().next().unwrap();
        assert_eq!(tuple.protocol, Protocol::Udp);
        assert_eq!(tuple.local_port, 55123);
        assert_eq!(tuple.remote_port, 53);
        assert_eq!(delta.rx_bytes, 28);
        assert_eq!(delta.tx_bytes, 0);
        assert_eq!(delta.first_direction, Some(Direction::Inbound));
    }
}
