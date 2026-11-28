# PacketAtlas

A fast, **100% native GPU-rendered Windows desktop application** (Rust + `egui`) for monitoring **all incoming and outgoing network traffic** with live OSINT geo-telemetry, process attribution, system-tray background recording, and categorized bandwidth analytics.

No browser, no WebView, no Electron, and no external packet-capture drivers (Npcap/WinPcap) required.

## Key Features

- **Native Desktop UI (`egui` / `eframe`)**
  - **Charcoal Black & Obsidian Navy Themes** with one-click theme switcher.
  - **Interactive World Map & Satellite View** with animated bidirectional geodesic pulses (Cyan moving toward your PC = Incoming RX; Violet moving away = Outgoing TX; Crimson = High Risk), Scroll-to-Zoom, Drag-to-Pan, and customizable **PC Origin** (auto-detected via GeoIP, city presets, custom lat/lon, or Right-Click on map).
  - **GlassWire-style 120s RX/TX Wave Graph** with hover crosshair and OSINT alert markers.
  - **Per-Application Breakdown** sidebar with crisp vector directional arrows (down = incoming, up = outgoing), live RX/TX throughput, and click-to-filter.
  - **Incoming & Outgoing Traffic Flows Table** with filters (`All`, `Inbound`, `Outbound`, `Listening`, `High Risk`, `TCP/UDP/ICMP`) and live search.
  - **Live OSINT Alert Feed & Deep Endpoint Inspector** (GeoIP, ASN, ISP, Org, rDNS, risk score & reasons, active sockets, and on-demand live refresh).
  - **Minimize to System Tray**: Keeps recording all traffic in the background when minimized or closed, with native tray icon & menu (`Show PacketAtlas`, `Pause / Resume Recording`, `Quit PacketAtlas`).
  - **Statistics & Reports**: Persistent **Daily (24h)**, **Weekly (7d)**, and **Monthly (30d)** charts plus breakdowns & CSV/JSON exports by Inbound, Outbound, Company/Org, Location/Country, Application, and Bandwidth Size.

- **Hybrid Incoming & Outgoing Capture Engine**
  - **Windows 10/11**:
    - **Administrator**: WinSock2 `SIO_RCVALL` raw IP packet capture for **exact per-flow incoming & outgoing byte accounting** (zero external drivers required).
    - **Standard User Fallback**: Win32 `iphlpapi` (`GetExtendedTcpTable` & `GetExtendedUdpTable` IPv4/IPv6, `GetIfTable2`, and `QueryFullProcessImageNameW`).

## Building on Windows 10/11

```powershell
cargo build --release
makensis installer\packetatlas.nsi
```

## CLI Options

```text
packetatlas [OPTIONS]

Options:
  --offline                     Use offline GeoIP fallback instead of live HTTP lookups
  --abuseipdb-key <KEY>         AbuseIPDB v2 API key (or env ABUSEIPDB_API_KEY)
  --vt-key <KEY>                VirusTotal v3 API key (or env VT_API_KEY)
  --smoke-test                  Run a single headless capture/OSINT check and exit
```
