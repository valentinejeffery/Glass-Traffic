# GlassTrace Desktop

A fast, **100% native GPU-rendered desktop application** (Rust + `egui`) for monitoring **all incoming and outgoing network traffic** with live OSINT geo-telemetry, process attribution, and threat scoring.

No browser, no WebView, no Electron, and no external packet-capture drivers (Npcap/WinPcap) required.

## Key Features

- **Native Desktop UI (`egui` / `eframe`)**
  - Interactive vector **World Map** with animated geodesic arcs (Cyan = Inbound, Violet = Outbound, Crimson = High Risk) and click-to-inspect endpoints.
  - **GlassWire-style 120s RX/TX Wave Graph** with hover crosshair, auto-scaling, and OSINT alert timeline markers.
  - **Per-Application Breakdown** sidebar (clickable process filter with live RX/TX throughput, inbound count, and max risk).
  - **Incoming & Outgoing Traffic Flows Table** with filters (`All`, `Inbound`, `Outbound`, `Listening`, `High Risk`, `TCP/UDP/ICMP`) and live search.
  - **Live OSINT Alert Feed** (`INBOUND_CONN`, `HIGH_RISK`, `PROXY_RELAY`, `NEW_COUNTRY`, `NEW_HOST`) and **Deep Endpoint Inspector** (GeoIP, ASN, ISP, Org, rDNS, risk reasons, active sockets, and on-demand refresh).
  - One-click **Export CSV** and **Export JSON** session snapshots.

- **Hybrid Incoming & Outgoing Capture Engine**
  - **Windows 10/11 (Primary Target)**:
    - **Elevated (Administrator)**: Automatically enables WinSock2 `SIO_RCVALL` raw IP packet capture on all active interfaces for **exact per-flow incoming & outgoing byte accounting** (including UDP/ICMP/ephemeral flows) — zero external drivers required.
    - **Standard (Non-Admin Fallback)**: Uses Win32 `iphlpapi` (`GetExtendedTcpTable` & `GetExtendedUdpTable` for IPv4 & IPv6, `GetIfTable2` for hardware NIC RX/TX counters, and `QueryFullProcessImageNameW` for exact process names & executable paths).
  - **Linux**:
    - **Elevated (`sudo` / `CAP_NET_RAW`)**: `AF_PACKET` raw Ethernet/IPv4/IPv6 capture for exact per-flow RX/TX accounting.
    - **Non-Root Fallback**: `/proc/net/{tcp,tcp6,udp,udp6,dev}` + `/proc/<pid>/{fd,comm,exe}`.

- **Live OSINT Enrichment**
  - Async background enrichment via `ip-api.com` (GeoIP, ASN, ISP, Org, rDNS, proxy/VPN/hosting detection).
  - Instant RFC1918/loopback/link-local/multicast classification and offline GeoIP fallback (`--offline`).
  - Optional **AbuseIPDB v2** (`--abuseipdb-key`) and **VirusTotal v3** (`--vt-key`) threat intelligence hooks.

## Building & Running on Windows 10/11

1. Install Rust from [rustup.rs](https://rustup.rs/).
2. Build the single native executable:
   ```powershell
   cargo build --release
   ```
3. Run `target\release\glasstrace.exe`:
   - **Standard user**: Monitors all active IPv4/IPv6 TCP/UDP connections, listening ports, process names, and NIC bandwidth.
   - **Run as Administrator**: Unlocks full raw packet capture (`SIO_RCVALL`) for exact per-flow incoming & outgoing byte accounting across TCP, UDP, and ICMP.
4. *(Optional)* Build the Windows NSIS installer (`GlassTrace-Setup-0.2.0.exe`):
   ```powershell
   makensis installer\glasstrace.nsi
   ```

## CLI Options

```text
glasstrace [OPTIONS]

Options:
  --offline                     Use offline GeoIP fallback instead of live HTTP lookups
  --abuseipdb-key <KEY>         AbuseIPDB v2 API key (or env ABUSEIPDB_API_KEY)
  --vt-key <KEY>                VirusTotal v3 API key (or env VT_API_KEY)
  --smoke-test                  Run a single headless capture/OSINT check and exit
```

## Project Structure

- `src/main.rs` — CLI arguments, 1s background collector thread, and native `eframe` window launcher.
- `src/capture/mod.rs` — Unified hybrid capture orchestrator and Inbound/Outbound/Listening direction classifier.
- `src/capture/packet.rs` — Zero-dependency IPv4/IPv6 + TCP/UDP/ICMP packet parser and per-flow byte tracker.
- `src/capture/windows.rs` — Native Windows `SIO_RCVALL` raw capture + `iphlpapi` IPv4/IPv6 socket & process attribution.
- `src/capture/linux.rs` — Native Linux `AF_PACKET` raw capture + `/proc/net` IPv4/IPv6 socket & process attribution.
- `src/osint.rs` — Thread-safe OSINT cache, `ip-api.com`, AbuseIPDB v2, VirusTotal v3, risk scoring, and offline fallback.
- `src/state.rs` — Thread-safe 120s ring buffer, per-app aggregation, OSINT alert generator, and JSON/CSV export.
- `src/ui/` — Native GPU-rendered `egui` desktop UI (`world_map.rs`, `bandwidth_graph.rs`, `panels.rs`, `mod.rs`).
