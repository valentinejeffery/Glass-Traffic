#![cfg(windows)]

use crate::capture::packet::PacketTracker;
use crate::types::{InterfaceCounters, Protocol, RawSocketEntry};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetExtendedTcpTable, GetExtendedUdpTable, GetIfTable2, GetIpAddrTable,
    MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IPADDRTABLE, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    bind, closesocket, recv, socket, WSAIoctl, WSAStartup, AF_INET, AF_INET6, INVALID_SOCKET,
    IPPROTO_IP, RCVALL_ON, SIO_RCVALL, SOCKADDR, SOCKADDR_IN, SOCK_RAW, SOCKET_ERROR, WSADATA,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

pub fn discover_local_ips() -> HashSet<IpAddr> {
    let mut set = HashSet::new();
    set.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    set.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));

    unsafe {
        let mut size: u32 = 0;
        let _ = GetIpAddrTable(std::ptr::null_mut(), &mut size, 0);
        if size == 0 {
            return set;
        }
        let mut buf = vec![0u8; size as usize];
        let table = buf.as_mut_ptr() as *mut MIB_IPADDRTABLE;
        if GetIpAddrTable(table, &mut size, 0) == NO_ERROR {
            let count = (*table).dwNumEntries as usize;
            let first = (*table).table.as_ptr();
            for i in 0..count {
                let row = &*first.add(i);
                let ip = Ipv4Addr::from(u32::from_be(row.dwAddr));
                if !ip.is_unspecified() {
                    set.insert(IpAddr::V4(ip));
                }
            }
        }
    }
    set
}

/// Start Windows raw IP packet capture using SIO_RCVALL on every active local IPv4 interface.
/// Succeeds when running as Administrator (no Npcap/WinPcap driver required).
/// Returns (active, status_message).
pub fn start_raw_capture(
    tracker: Arc<PacketTracker>,
    stop_flag: Arc<AtomicBool>,
) -> (bool, String) {
    unsafe {
        let mut wsa: WSADATA = std::mem::zeroed();
        if WSAStartup(0x0202, &mut wsa) != 0 {
            return (false, "WSAStartup failed — using OS socket tables".into());
        }
    }

    let local_v4s: Vec<Ipv4Addr> = discover_local_ips()
        .into_iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4),
            _ => None,
        })
        .collect();

    if local_v4s.is_empty() {
        return (
            false,
            "No active IPv4 interfaces found — using OS socket tables".into(),
        );
    }

    let mut started = 0usize;
    for ip in local_v4s {
        unsafe {
            let sock = socket(AF_INET as i32, SOCK_RAW as i32, IPPROTO_IP as i32);
            if sock == INVALID_SOCKET {
                continue;
            }

            let mut addr: SOCKADDR_IN = std::mem::zeroed();
            addr.sin_family = AF_INET;
            addr.sin_port = 0;
            addr.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());

            if bind(
                sock,
                &addr as *const SOCKADDR_IN as *const SOCKADDR,
                std::mem::size_of::<SOCKADDR_IN>() as i32,
            ) == SOCKET_ERROR
            {
                closesocket(sock);
                continue;
            }

            let mut opt_val: u32 = RCVALL_ON as u32;
            let mut bytes_returned: u32 = 0;
            let res = WSAIoctl(
                sock,
                SIO_RCVALL,
                &mut opt_val as *mut u32 as *mut _,
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
                None,
            );

            if res == SOCKET_ERROR {
                closesocket(sock);
                continue;
            }

            started += 1;
            let tracker_clone = Arc::clone(&tracker);
            let stop_clone = Arc::clone(&stop_flag);
            let _ = thread::Builder::new()
                .name(format!("glasstrace-raw-{}", ip))
                .spawn(move || {
                    let mut buf = vec![0u8; 65536];
                    while !stop_clone.load(Ordering::Relaxed) {
                        let n = recv(sock, buf.as_mut_ptr(), buf.len() as i32, 0);
                        if n > 0 {
                            tracker_clone.ingest_ip_packet(&buf[..n as usize]);
                        } else if n < 0 {
                            break;
                        }
                    }
                    closesocket(sock);
                });
        }
    }

    if started > 0 {
        (
            true,
            format!(
                "Administrator Raw Capture active ({} interface(s), exact per-flow RX/TX)",
                started
            ),
        )
    } else {
        (
            false,
            "Standard mode (non-Admin) — run as Administrator for exact per-flow raw packet capture"
                .into(),
        )
    }
}

pub fn collect_sockets_and_counters() -> (Vec<RawSocketEntry>, InterfaceCounters) {
    let mut pid_cache: HashMap<u32, (String, String)> = HashMap::new();
    let mut entries = Vec::with_capacity(256);

    collect_tcp4(&mut entries, &mut pid_cache);
    collect_tcp6(&mut entries, &mut pid_cache);
    collect_udp4(&mut entries, &mut pid_cache);
    collect_udp6(&mut entries, &mut pid_cache);

    let counters = read_interface_counters();
    (entries, counters)
}

fn resolve_pid(pid: u32, cache: &mut HashMap<u32, (String, String)>) -> (String, String) {
    if let Some(hit) = cache.get(&pid) {
        return hit.clone();
    }
    let resolved = match pid {
        0 => ("System Idle".to_string(), String::new()),
        4 => ("System (Kernel)".to_string(), "ntoskrnl.exe".to_string()),
        _ => unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                (format!("PID {}", pid), String::new())
            } else {
                let mut buf = [0u16; 1024];
                let mut len = buf.len() as u32;
                let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len);
                CloseHandle(handle);
                if ok != 0 && len > 0 {
                    let full = String::from_utf16_lossy(&buf[..len as usize]);
                    let name = full
                        .rsplit(['\\', '/'])
                        .next()
                        .unwrap_or(&full)
                        .to_string();
                    (name, full)
                } else {
                    (format!("PID {}", pid), String::new())
                }
            }
        },
    };
    cache.insert(pid, resolved.clone());
    resolved
}

fn tcp_state_name(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

fn collect_tcp4(out: &mut Vec<RawSocketEntry>, pid_cache: &mut HashMap<u32, (String, String)>) {
    unsafe {
        let mut size: u32 = 0;
        let ret = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if ret != ERROR_INSUFFICIENT_BUFFER && ret != NO_ERROR {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        if GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ) != NO_ERROR
        {
            return;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        let rows = table.table.as_ptr();
        for i in 0..count {
            let row: &MIB_TCPROW_OWNER_PID = &*rows.add(i);
            let local_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr)));
            let remote_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwRemoteAddr)));
            let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
            let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
            let (process_name, process_path) = resolve_pid(row.dwOwningPid, pid_cache);
            out.push(RawSocketEntry {
                protocol: Protocol::Tcp,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                state: tcp_state_name(row.dwState).to_string(),
                pid: row.dwOwningPid,
                process_name,
                process_path,
            });
        }
    }
}

fn collect_tcp6(out: &mut Vec<RawSocketEntry>, pid_cache: &mut HashMap<u32, (String, String)>) {
    unsafe {
        let mut size: u32 = 0;
        let ret = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if ret != ERROR_INSUFFICIENT_BUFFER && ret != NO_ERROR {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        if GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ) != NO_ERROR
        {
            return;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        let rows = table.table.as_ptr();
        for i in 0..count {
            let row: &MIB_TCP6ROW_OWNER_PID = &*rows.add(i);
            let local_ip = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr));
            let remote_ip = IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr));
            let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
            let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
            let (process_name, process_path) = resolve_pid(row.dwOwningPid, pid_cache);
            out.push(RawSocketEntry {
                protocol: Protocol::Tcp,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                state: tcp_state_name(row.dwState).to_string(),
                pid: row.dwOwningPid,
                process_name,
                process_path,
            });
        }
    }
}

fn collect_udp4(out: &mut Vec<RawSocketEntry>, pid_cache: &mut HashMap<u32, (String, String)>) {
    unsafe {
        let mut size: u32 = 0;
        let ret = GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if ret != ERROR_INSUFFICIENT_BUFFER && ret != NO_ERROR {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        if GetExtendedUdpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        ) != NO_ERROR
        {
            return;
        }
        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        let rows = table.table.as_ptr();
        for i in 0..count {
            let row: &MIB_UDPROW_OWNER_PID = &*rows.add(i);
            let local_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr)));
            let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
            let (process_name, process_path) = resolve_pid(row.dwOwningPid, pid_cache);
            out.push(RawSocketEntry {
                protocol: Protocol::Udp,
                local_ip,
                local_port,
                remote_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                remote_port: 0,
                state: "UDP_LISTEN".to_string(),
                pid: row.dwOwningPid,
                process_name,
                process_path,
            });
        }
    }
}

fn collect_udp6(out: &mut Vec<RawSocketEntry>, pid_cache: &mut HashMap<u32, (String, String)>) {
    unsafe {
        let mut size: u32 = 0;
        let ret = GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if ret != ERROR_INSUFFICIENT_BUFFER && ret != NO_ERROR {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        if GetExtendedUdpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        ) != NO_ERROR
        {
            return;
        }
        let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        let rows = table.table.as_ptr();
        for i in 0..count {
            let row: &MIB_UDP6ROW_OWNER_PID = &*rows.add(i);
            let local_ip = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr));
            let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
            let (process_name, process_path) = resolve_pid(row.dwOwningPid, pid_cache);
            out.push(RawSocketEntry {
                protocol: Protocol::Udp,
                local_ip,
                local_port,
                remote_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                remote_port: 0,
                state: "UDP_LISTEN".to_string(),
                pid: row.dwOwningPid,
                process_name,
                process_path,
            });
        }
    }
}

fn read_interface_counters() -> InterfaceCounters {
    let mut counters = InterfaceCounters::default();
    unsafe {
        let mut table_ptr: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        if GetIfTable2(&mut table_ptr) != NO_ERROR || table_ptr.is_null() {
            return counters;
        }
        let count = (*table_ptr).NumEntries as usize;
        let rows = (*table_ptr).Table.as_ptr();
        for i in 0..count {
            let row: &MIB_IF_ROW2 = &*rows.add(i);
            // Skip loopback (type 24) and inactive adapters
            if row.Type == 24 || row.OperStatus != IfOperStatusUp {
                continue;
            }
            // Skip NDIS filter driver layers (bit 1 = FilterInterface)
            if (row.InterfaceAndOperStatusFlags._bitfield & 0x02) != 0 {
                continue;
            }
            if row.InOctets == 0 && row.OutOctets == 0 {
                continue;
            }

            let alias_end = row
                .Alias
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(row.Alias.len());
            let alias = String::from_utf16_lossy(&row.Alias[..alias_end]);
            let alias_lower = alias.to_lowercase();
            if alias_lower.contains("filter")
                || alias_lower.contains("scheduler")
                || alias_lower.contains("wfp")
                || alias_lower.contains("npcap")
                || alias_lower.contains("miniport")
            {
                continue;
            }

            counters.total_rx_bytes = counters.total_rx_bytes.saturating_add(row.InOctets);
            counters.total_tx_bytes = counters.total_tx_bytes.saturating_add(row.OutOctets);

            if !alias.is_empty() && !counters.active_interfaces.contains(&alias) {
                counters.active_interfaces.push(alias);
            }
        }
        FreeMibTable(table_ptr as *const _);
    }
    counters
}
