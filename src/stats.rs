use crate::types::{Direction, Flow};
use chrono::{Duration, Local, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timeframe {
    Daily,
    Weekly,
    Monthly,
}

impl Timeframe {
    pub fn label(&self) -> &'static str {
        match self {
            Timeframe::Daily => "Daily (24h)",
            Timeframe::Weekly => "Weekly (7d)",
            Timeframe::Monthly => "Monthly (30d)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportCategory {
    Inbound,
    Outbound,
    ByCompany,
    ByLocation,
    ByApplication,
    ByBandwidthSize,
    DailyReport,
    WeeklyReport,
    MonthlyReport,
    FullReport,
}

impl ExportCategory {
    pub const ALL: &'static [ExportCategory] = &[
        ExportCategory::Inbound,
        ExportCategory::Outbound,
        ExportCategory::ByCompany,
        ExportCategory::ByLocation,
        ExportCategory::ByApplication,
        ExportCategory::ByBandwidthSize,
        ExportCategory::DailyReport,
        ExportCategory::WeeklyReport,
        ExportCategory::MonthlyReport,
        ExportCategory::FullReport,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            ExportCategory::Inbound => "Inbound Traffic",
            ExportCategory::Outbound => "Outbound Traffic",
            ExportCategory::ByCompany => "By Company / Org",
            ExportCategory::ByLocation => "By Location / Country",
            ExportCategory::ByApplication => "By Application",
            ExportCategory::ByBandwidthSize => "By Bandwidth Size",
            ExportCategory::DailyReport => "Daily Report (24h)",
            ExportCategory::WeeklyReport => "Weekly Report (7d)",
            ExportCategory::MonthlyReport => "Monthly Report (30d)",
            ExportCategory::FullReport => "Full Complete Report",
        }
    }

    pub fn slug(&self) -> &'static str {
        match self {
            ExportCategory::Inbound => "inbound",
            ExportCategory::Outbound => "outbound",
            ExportCategory::ByCompany => "by_company",
            ExportCategory::ByLocation => "by_location",
            ExportCategory::ByApplication => "by_application",
            ExportCategory::ByBandwidthSize => "by_bandwidth_size",
            ExportCategory::DailyReport => "daily_report",
            ExportCategory::WeeklyReport => "weekly_report",
            ExportCategory::MonthlyReport => "monthly_report",
            ExportCategory::FullReport => "full_report",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Csv,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyBucket {
    pub date: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub hourly_rx: [u64; 24],
    pub hourly_tx: [u64; 24],
    pub alerts: u64,
}

impl DailyBucket {
    fn new(date: String) -> Self {
        Self {
            date,
            rx_bytes: 0,
            tx_bytes: 0,
            hourly_rx: [0; 24],
            hourly_tx: [0; 24],
            alerts: 0,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CategoryStat {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub samples: u64,
    pub max_risk: u8,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocationStat {
    pub country: String,
    pub country_code: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub samples: u64,
    pub max_risk: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartBar {
    pub label: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthTierRow {
    pub tier: String,
    pub flow_count: usize,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsStore {
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub inbound_flow_bytes: u64,
    pub outbound_flow_bytes: u64,
    pub daily: BTreeMap<String, DailyBucket>,
    pub by_company: HashMap<String, CategoryStat>,
    pub by_location: HashMap<String, LocationStat>,
    pub by_app: HashMap<String, CategoryStat>,
    #[serde(skip)]
    ticks_since_save: u64,
}

impl Default for StatsStore {
    fn default() -> Self {
        Self {
            total_rx_bytes: 0,
            total_tx_bytes: 0,
            inbound_flow_bytes: 0,
            outbound_flow_bytes: 0,
            daily: BTreeMap::new(),
            by_company: HashMap::new(),
            by_location: HashMap::new(),
            by_app: HashMap::new(),
            ticks_since_save: 0,
        }
    }
}

impl StatsStore {
    pub fn storage_path() -> PathBuf {
        #[cfg(windows)]
        {
            if let Ok(appdata) = std::env::var("APPDATA") {
                return PathBuf::from(appdata)
                    .join("PacketAtlas")
                    .join("stats_history.json");
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("packetatlas")
                .join("stats_history.json");
        }
        PathBuf::from("packetatlas_stats_history.json")
    }

    pub fn load_or_default() -> Self {
        let path = Self::storage_path();
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(mut parsed) = serde_json::from_str::<StatsStore>(&content) {
                parsed.ticks_since_save = 0;
                // Purge any legacy non-country entries (Private LAN, Listening Socket, etc.)
                parsed
                    .by_location
                    .retain(|_, v| is_real_country(&v.country, &v.country_code));
                return parsed;
            }
        }
        Self::default()
    }

    pub fn save_to_disk(&mut self) {
        self.ticks_since_save = 0;
        let path = Self::storage_path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(body) = serde_json::to_string_pretty(self) {
            let _ = fs::write(&path, body);
        }
    }

    pub fn record_tick(&mut self, flows: &[Flow], total_rx_bps: u64, total_tx_bps: u64, alerts: usize) {
        let now = Local::now();
        let date_key = now.format("%Y-%m-%d").to_string();
        let hour = (now.hour() as usize).min(23);

        self.total_rx_bytes = self.total_rx_bytes.saturating_add(total_rx_bps);
        self.total_tx_bytes = self.total_tx_bytes.saturating_add(total_tx_bps);

        let bucket = self
            .daily
            .entry(date_key.clone())
            .or_insert_with(|| DailyBucket::new(date_key));
        bucket.rx_bytes = bucket.rx_bytes.saturating_add(total_rx_bps);
        bucket.tx_bytes = bucket.tx_bytes.saturating_add(total_tx_bps);
        bucket.hourly_rx[hour] = bucket.hourly_rx[hour].saturating_add(total_rx_bps);
        bucket.hourly_tx[hour] = bucket.hourly_tx[hour].saturating_add(total_tx_bps);
        bucket.alerts = bucket.alerts.saturating_add(alerts as u64);

        // Trim daily history to last 90 days
        while self.daily.len() > 90 {
            if let Some(oldest) = self.daily.keys().next().cloned() {
                self.daily.remove(&oldest);
            } else {
                break;
            }
        }

        for f in flows {
            let rate_sum = f.rx_bps.saturating_add(f.tx_bps);
            if f.direction == Direction::Inbound {
                self.inbound_flow_bytes = self.inbound_flow_bytes.saturating_add(rate_sum);
            } else if f.direction == Direction::Outbound {
                self.outbound_flow_bytes = self.outbound_flow_bytes.saturating_add(rate_sum);
            }

            // Company / Org
            let company = if !f.osint.org.is_empty() {
                f.osint.org.clone()
            } else if !f.osint.isp.is_empty() {
                f.osint.isp.clone()
            } else if f.osint.is_private {
                "Local Network".to_string()
            } else {
                "Unresolved".to_string()
            };
            let comp_entry = self
                .by_company
                .entry(company.clone())
                .or_insert_with(|| CategoryStat {
                    name: company,
                    ..Default::default()
                });
            comp_entry.rx_bytes = comp_entry.rx_bytes.saturating_add(f.rx_bps);
            comp_entry.tx_bytes = comp_entry.tx_bytes.saturating_add(f.tx_bps);
            comp_entry.samples = comp_entry.samples.saturating_add(1);
            comp_entry.max_risk = comp_entry.max_risk.max(f.osint.risk_score);

            // Location / Country (exclude private LAN, loopback, listening sockets, and unresolved entries)
            if !f.osint.is_private
                && f.osint.source != "pending"
                && is_real_country(&f.osint.country, &f.osint.country_code)
            {
                let country = f.osint.country.clone();
                let cc = f.osint.country_code.clone();
                let loc_entry = self
                    .by_location
                    .entry(country.clone())
                    .or_insert_with(|| LocationStat {
                        country,
                        country_code: cc,
                        ..Default::default()
                    });
                loc_entry.rx_bytes = loc_entry.rx_bytes.saturating_add(f.rx_bps);
                loc_entry.tx_bytes = loc_entry.tx_bytes.saturating_add(f.tx_bps);
                loc_entry.samples = loc_entry.samples.saturating_add(1);
                loc_entry.max_risk = loc_entry.max_risk.max(f.osint.risk_score);
            }

            // Application / Process
            let app_entry = self
                .by_app
                .entry(f.process_name.clone())
                .or_insert_with(|| CategoryStat {
                    name: f.process_name.clone(),
                    ..Default::default()
                });
            app_entry.rx_bytes = app_entry.rx_bytes.saturating_add(f.rx_bps);
            app_entry.tx_bytes = app_entry.tx_bytes.saturating_add(f.tx_bps);
            app_entry.samples = app_entry.samples.saturating_add(1);
            app_entry.max_risk = app_entry.max_risk.max(f.osint.risk_score);
        }

        // Auto-save to disk every 30 seconds
        self.ticks_since_save += 1;
        if self.ticks_since_save >= 30 {
            self.save_to_disk();
        }
    }

    pub fn chart_bars(&self, tf: Timeframe) -> Vec<ChartBar> {
        let today = Local::now().date_naive();
        match tf {
            Timeframe::Daily => {
                let key = today.format("%Y-%m-%d").to_string();
                let bucket = self.daily.get(&key);
                (0..24)
                    .map(|h| ChartBar {
                        label: format!("{:02}h", h),
                        rx_bytes: bucket.map(|b| b.hourly_rx[h]).unwrap_or(0),
                        tx_bytes: bucket.map(|b| b.hourly_tx[h]).unwrap_or(0),
                    })
                    .collect()
            }
            Timeframe::Weekly => (0..7)
                .rev()
                .map(|days_ago| {
                    let d = today - Duration::days(days_ago);
                    let key = d.format("%Y-%m-%d").to_string();
                    let label = d.format("%a %m/%d").to_string();
                    let b = self.daily.get(&key);
                    ChartBar {
                        label,
                        rx_bytes: b.map(|v| v.rx_bytes).unwrap_or(0),
                        tx_bytes: b.map(|v| v.tx_bytes).unwrap_or(0),
                    }
                })
                .collect(),
            Timeframe::Monthly => (0..30)
                .rev()
                .map(|days_ago| {
                    let d = today - Duration::days(days_ago);
                    let key = d.format("%Y-%m-%d").to_string();
                    let label = d.format("%m/%d").to_string();
                    let b = self.daily.get(&key);
                    ChartBar {
                        label,
                        rx_bytes: b.map(|v| v.rx_bytes).unwrap_or(0),
                        tx_bytes: b.map(|v| v.tx_bytes).unwrap_or(0),
                    }
                })
                .collect(),
        }
    }

    pub fn sorted_companies(&self) -> Vec<CategoryStat> {
        let mut v: Vec<CategoryStat> = self.by_company.values().cloned().collect();
        v.sort_by(|a, b| (b.rx_bytes + b.tx_bytes).cmp(&(a.rx_bytes + a.tx_bytes)));
        v
    }

    pub fn sorted_locations(&self) -> Vec<LocationStat> {
        let mut v: Vec<LocationStat> = self
            .by_location
            .values()
            .filter(|l| is_real_country(&l.country, &l.country_code))
            .cloned()
            .collect();
        v.sort_by(|a, b| (b.rx_bytes + b.tx_bytes).cmp(&(a.rx_bytes + a.tx_bytes)));
        v
    }

    pub fn sorted_apps(&self) -> Vec<CategoryStat> {
        let mut v: Vec<CategoryStat> = self.by_app.values().cloned().collect();
        v.sort_by(|a, b| (b.rx_bytes + b.tx_bytes).cmp(&(a.rx_bytes + a.tx_bytes)));
        v
    }

    pub fn bandwidth_tiers(flows: &[Flow]) -> Vec<BandwidthTierRow> {
        let mut small = BandwidthTierRow {
            tier: "< 10 KB (Lightweight)".into(),
            flow_count: 0,
            rx_bytes: 0,
            tx_bytes: 0,
        };
        let mut med = BandwidthTierRow {
            tier: "10 KB - 1 MB (Medium)".into(),
            flow_count: 0,
            rx_bytes: 0,
            tx_bytes: 0,
        };
        let mut large = BandwidthTierRow {
            tier: "1 MB - 50 MB (Heavy)".into(),
            flow_count: 0,
            rx_bytes: 0,
            tx_bytes: 0,
        };
        let mut huge = BandwidthTierRow {
            tier: "> 50 MB (Bulk Transfer)".into(),
            flow_count: 0,
            rx_bytes: 0,
            tx_bytes: 0,
        };

        for f in flows {
            let total = f.total_rx.saturating_add(f.total_tx);
            let target = if total < 10 * 1024 {
                &mut small
            } else if total < 1024 * 1024 {
                &mut med
            } else if total < 50 * 1024 * 1024 {
                &mut large
            } else {
                &mut huge
            };
            target.flow_count += 1;
            target.rx_bytes = target.rx_bytes.saturating_add(f.total_rx);
            target.tx_bytes = target.tx_bytes.saturating_add(f.total_tx);
        }

        vec![huge, large, med, small]
    }

    pub fn export_category(
        &self,
        category: ExportCategory,
        format: ExportFormat,
        flows: &[Flow],
    ) -> Result<PathBuf, String> {
        let ext = match format {
            ExportFormat::Csv => "csv",
            ExportFormat::Json => "json",
        };
        let fname = format!(
            "packetatlas_{}_{}.{}",
            category.slug(),
            Local::now().format("%Y%m%d_%H%M%S"),
            ext
        );
        let path = PathBuf::from(&fname);

        let content = match (category, format) {
            (ExportCategory::Inbound, ExportFormat::Csv) => {
                let subset: Vec<&Flow> = flows
                    .iter()
                    .filter(|f| {
                        f.direction == Direction::Inbound || f.rx_bps > 0 || f.total_rx > 0
                    })
                    .collect();
                flows_to_csv(&subset)
            }
            (ExportCategory::Inbound, ExportFormat::Json) => {
                let subset: Vec<&Flow> = flows
                    .iter()
                    .filter(|f| {
                        f.direction == Direction::Inbound || f.rx_bps > 0 || f.total_rx > 0
                    })
                    .collect();
                serde_json::to_string_pretty(&subset).map_err(|e| e.to_string())?
            }
            (ExportCategory::Outbound, ExportFormat::Csv) => {
                let subset: Vec<&Flow> = flows
                    .iter()
                    .filter(|f| {
                        f.direction == Direction::Outbound || f.tx_bps > 0 || f.total_tx > 0
                    })
                    .collect();
                flows_to_csv(&subset)
            }
            (ExportCategory::Outbound, ExportFormat::Json) => {
                let subset: Vec<&Flow> = flows
                    .iter()
                    .filter(|f| {
                        f.direction == Direction::Outbound || f.tx_bps > 0 || f.total_tx > 0
                    })
                    .collect();
                serde_json::to_string_pretty(&subset).map_err(|e| e.to_string())?
            }
            (ExportCategory::ByCompany, ExportFormat::Csv) => {
                let mut out = String::from("company,rx_bytes,tx_bytes,total_bytes,samples,max_risk\n");
                for c in self.sorted_companies() {
                    out.push_str(&format!(
                        "\"{}\",{},{},{},{},{}\n",
                        c.name.replace('"', "\"\""),
                        c.rx_bytes,
                        c.tx_bytes,
                        c.rx_bytes + c.tx_bytes,
                        c.samples,
                        c.max_risk
                    ));
                }
                out
            }
            (ExportCategory::ByCompany, ExportFormat::Json) => {
                serde_json::to_string_pretty(&self.sorted_companies()).map_err(|e| e.to_string())?
            }
            (ExportCategory::ByLocation, ExportFormat::Csv) => {
                let mut out = String::from("country,country_code,rx_bytes,tx_bytes,total_bytes,samples,max_risk\n");
                for l in self.sorted_locations() {
                    out.push_str(&format!(
                        "\"{}\",{},{},{},{},{},{}\n",
                        l.country.replace('"', "\"\""),
                        l.country_code,
                        l.rx_bytes,
                        l.tx_bytes,
                        l.rx_bytes + l.tx_bytes,
                        l.samples,
                        l.max_risk
                    ));
                }
                out
            }
            (ExportCategory::ByLocation, ExportFormat::Json) => {
                serde_json::to_string_pretty(&self.sorted_locations()).map_err(|e| e.to_string())?
            }
            (ExportCategory::ByApplication, ExportFormat::Csv) => {
                let mut out = String::from("application,rx_bytes,tx_bytes,total_bytes,samples,max_risk\n");
                for a in self.sorted_apps() {
                    out.push_str(&format!(
                        "\"{}\",{},{},{},{},{}\n",
                        a.name.replace('"', "\"\""),
                        a.rx_bytes,
                        a.tx_bytes,
                        a.rx_bytes + a.tx_bytes,
                        a.samples,
                        a.max_risk
                    ));
                }
                out
            }
            (ExportCategory::ByApplication, ExportFormat::Json) => {
                serde_json::to_string_pretty(&self.sorted_apps()).map_err(|e| e.to_string())?
            }
            (ExportCategory::ByBandwidthSize, ExportFormat::Csv) => {
                let mut out = String::from("tier,flow_count,rx_bytes,tx_bytes,total_bytes\n");
                for t in Self::bandwidth_tiers(flows) {
                    out.push_str(&format!(
                        "\"{}\",{},{},{},{}\n",
                        t.tier,
                        t.flow_count,
                        t.rx_bytes,
                        t.tx_bytes,
                        t.rx_bytes + t.tx_bytes
                    ));
                }
                out
            }
            (ExportCategory::ByBandwidthSize, ExportFormat::Json) => {
                serde_json::to_string_pretty(&Self::bandwidth_tiers(flows))
                    .map_err(|e| e.to_string())?
            }
            (ExportCategory::DailyReport, ExportFormat::Csv) => {
                bars_to_csv("hour", &self.chart_bars(Timeframe::Daily))
            }
            (ExportCategory::DailyReport, ExportFormat::Json) => {
                serde_json::to_string_pretty(&self.chart_bars(Timeframe::Daily))
                    .map_err(|e| e.to_string())?
            }
            (ExportCategory::WeeklyReport, ExportFormat::Csv) => {
                bars_to_csv("day", &self.chart_bars(Timeframe::Weekly))
            }
            (ExportCategory::WeeklyReport, ExportFormat::Json) => {
                serde_json::to_string_pretty(&self.chart_bars(Timeframe::Weekly))
                    .map_err(|e| e.to_string())?
            }
            (ExportCategory::MonthlyReport, ExportFormat::Csv) => {
                bars_to_csv("date", &self.chart_bars(Timeframe::Monthly))
            }
            (ExportCategory::MonthlyReport, ExportFormat::Json) => {
                serde_json::to_string_pretty(&self.chart_bars(Timeframe::Monthly))
                    .map_err(|e| e.to_string())?
            }
            (ExportCategory::FullReport, ExportFormat::Csv) => {
                let all: Vec<&Flow> = flows.iter().collect();
                flows_to_csv(&all)
            }
            (ExportCategory::FullReport, ExportFormat::Json) => {
                let bundle = serde_json::json!({
                    "exported_at": Local::now().to_rfc3339(),
                    "totals": {
                        "rx_bytes": self.total_rx_bytes,
                        "tx_bytes": self.total_tx_bytes,
                        "inbound_flow_bytes": self.inbound_flow_bytes,
                        "outbound_flow_bytes": self.outbound_flow_bytes,
                    },
                    "daily_24h": self.chart_bars(Timeframe::Daily),
                    "weekly_7d": self.chart_bars(Timeframe::Weekly),
                    "monthly_30d": self.chart_bars(Timeframe::Monthly),
                    "by_company": self.sorted_companies(),
                    "by_location": self.sorted_locations(),
                    "by_application": self.sorted_apps(),
                    "by_bandwidth_size": Self::bandwidth_tiers(flows),
                    "active_flows": flows,
                });
                serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())?
            }
        };

        fs::write(&path, content).map_err(|e| e.to_string())?;
        Ok(path)
    }
}

fn flows_to_csv(flows: &[&Flow]) -> String {
    let mut out = String::from(
        "direction,protocol,process,pid,local_ip,local_port,remote_ip,remote_port,state,rx_bps,tx_bps,total_rx,total_tx,country,city,company,asn,risk_score\n",
    );
    for f in flows {
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
            f.osint.org.replace('"', "\"\""),
            f.osint.asn.replace('"', "\"\""),
            f.osint.risk_score
        ));
    }
    out
}

fn bars_to_csv(col_name: &str, bars: &[ChartBar]) -> String {
    let mut out = format!("{},rx_bytes,tx_bytes,total_bytes\n", col_name);
    for b in bars {
        out.push_str(&format!(
            "\"{}\",{},{},{}\n",
            b.label,
            b.rx_bytes,
            b.tx_bytes,
            b.rx_bytes + b.tx_bytes
        ));
    }
    out
}

/// Returns true only for real geolocated countries (valid 2-letter ISO code, excluding LAN/local/listening sockets).
pub fn is_real_country(country: &str, cc: &str) -> bool {
    let cc = cc.trim();
    if cc.len() != 2 || !cc.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    let lower = country.trim().to_lowercase();
    if lower.is_empty() {
        return false;
    }
    const EXCLUDED: &[&str] = &[
        "private",
        "listening",
        "loopback",
        "unspecified",
        "link-local",
        "multicast",
        "broadcast",
        "cgnat",
        "resolving",
        "unknown",
        "local",
    ];
    !EXCLUDED.iter().any(|k| lower.contains(k))
}
