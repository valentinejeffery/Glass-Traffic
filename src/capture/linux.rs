#![cfg(target_os = "linux")]

use crate::capture::packet::PacketTracker;
use crate::types::{InterfaceCounters, Protocol, RawSocketEntry};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

pub fn discover_local_ips() -> HashSet<IpAddr> {
    let mut set = HashSet::new();
    set.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    set.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));

    // Read local IPs from /proc/net/fib_trie or active /proc/net/tcp local endpoints
    if let Ok(content) = fs::read_to_string("/proc/net/fib_trie") {
        let mut prev_ip: Option<Ipv4Addr> = None;
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("|-- ") {
                if let Ok(ip) = rest.parse::<Ipv4Addr>() {
                    prev_ip = Some(ip);
                    continue;
                }
            }
            if trimmed.contains("/32 host LOCAL") {
                if let Some(ip) = prev_ip {
                    if !ip.is_unspecified() {
                        set.insert(IpAddr::V4(ip));
                    }
                }
            }
        }
    }

    set
}

pub fn start_raw_capture(
    tracker: Arc<PacketTracker>,
    stop_flag: Arc<AtomicBool>,
) -> (bool, String) {
    unsafe {
        let eth_p_all = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth_p_all);
        if fd < 0 {
            return (
                false,
                "Standard mode (non-root) — run with sudo or CAP_NET_RAW for exact per-flow raw packet capture".into(),
            );
        }

        let _ = thread::Builder::new()
            .name("glasstrace-af-packet".into())
            .spawn(move || {
                let mut buf = vec![0u8; 65536];
                while !stop_flag.load(Ordering::Relaxed) {
                    let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
                    if n > 0 {
                        tracker.ingest_ethernet_frame(&buf[..n as usize]);
                    } else if n < 0 {
                        break;
                    }
                }
                libc::close(fd);
            });

        (
            true,
            "Linux AF_PACKET Raw Capture active (exact per-flow RX/TX)".into(),
        )
    }
}

pub fn collect_sockets_and_counters() -> (Vec<RawSocketEntry>, InterfaceCounters) {
    let inode_map = build_inode_pid_map();
    let mut entries = Vec::with_capacity(256);

    parse_proc_net("/proc/net/tcp", Protocol::Tcp, false, &inode_map, &mut entries);
    parse_proc_net("/proc/net/tcp6", Protocol::Tcp, true, &inode_map, &mut entries);
    parse_proc_net("/proc/net/udp", Protocol::Udp, false, &inode_map, &mut entries);
    parse_proc_net("/proc/net/udp6", Protocol::Udp, true, &inode_map, &mut entries);

    let counters = read_proc_net_dev();
    (entries, counters)
}

fn build_inode_pid_map() -> HashMap<u64, (u32, String, String)> {
    let mut map = HashMap::new();
    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return map;
    };

    for entry in proc_dir.flatten() {
        let fname = entry.file_name();
        let Some(pid_str) = fname.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        let fd_dir = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };

        let mut comm_loaded = None;
        let mut exe_loaded = None;

        for fd in fds.flatten() {
            if let Ok(link) = fs::read_link(fd.path()) {
                if let Some(s) = link.to_str() {
                    if let Some(inode_str) = s
                        .strip_prefix("socket:[")
                        .and_then(|v| v.strip_suffix(']'))
                    {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            let comm = comm_loaded.get_or_insert_with(|| {
                                fs::read_to_string(entry.path().join("comm"))
                                    .unwrap_or_else(|_| format!("pid-{}", pid))
                                    .trim()
                                    .to_string()
                            });
                            let exe = exe_loaded.get_or_insert_with(|| {
                                fs::read_link(entry.path().join("exe"))
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_default()
                            });
                            map.insert(inode, (pid, comm.clone(), exe.clone()));
                        }
                    }
                }
            }
        }
    }
    map
}

fn parse_proc_net(
    path: &str,
    protocol: Protocol,
    is_v6: bool,
    inode_map: &HashMap<u64, (u32, String, String)>,
    out: &mut Vec<RawSocketEntry>,
) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let Some((local_ip, local_port)) = parse_hex_addr(cols[1], is_v6) else {
            continue;
        };
        let Some((remote_ip, remote_port)) = parse_hex_addr(cols[2], is_v6) else {
            continue;
        };
        let state = linux_state_name(cols[3], protocol);
        let inode = cols[9].parse::<u64>().unwrap_or(0);
        let (pid, process_name, process_path) = inode_map
            .get(&inode)
            .cloned()
            .unwrap_or((0, "kernel/other".to_string(), String::new()));

        out.push(RawSocketEntry {
            protocol,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            state: state.to_string(),
            pid,
            process_name,
            process_path,
        });
    }
}

fn parse_hex_addr(s: &str, is_v6: bool) -> Option<(IpAddr, u16)> {
    let (ip_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if !is_v6 {
        let raw = u32::from_str_radix(ip_hex, 16).ok()?;
        // /proc/net/tcp stores IPv4 in host byte order (little-endian on x86_64)
        let ip = Ipv4Addr::from(u32::from_be(raw));
        Some((IpAddr::V4(ip), port))
    } else {
        if ip_hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let chunk = u32::from_str_radix(&ip_hex[i * 8..(i + 1) * 8], 16).ok()?;
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&chunk.to_ne_bytes());
        }
        Some((IpAddr::V6(Ipv6Addr::from(bytes)), port))
    }
}

fn linux_state_name(hex: &str, proto: Protocol) -> &'static str {
    if proto == Protocol::Udp {
        return match hex {
            "01" => "UDP_ESTAB",
            "07" => "UDP_LISTEN",
            _ => "UDP",
        };
    }
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RCVD",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn read_proc_net_dev() -> InterfaceCounters {
    let mut counters = InterfaceCounters::default();
    let Ok(content) = fs::read_to_string("/proc/net/dev") else {
        return counters;
    };
    for line in content.lines().skip(2) {
        let Some((iface, rest)) = line.split_once(':') else {
            continue;
        };
        let iface = iface.trim();
        if iface == "lo" {
            continue;
        }
        let nums: Vec<&str> = rest.split_whitespace().collect();
        if nums.len() >= 9 {
            let rx = nums[0].parse::<u64>().unwrap_or(0);
            let tx = nums[8].parse::<u64>().unwrap_or(0);
            if rx > 0 || tx > 0 {
                counters.total_rx_bytes = counters.total_rx_bytes.saturating_add(rx);
                counters.total_tx_bytes = counters.total_tx_bytes.saturating_add(tx);
                counters.active_interfaces.push(iface.to_string());
            }
        }
    }
    counters
}
