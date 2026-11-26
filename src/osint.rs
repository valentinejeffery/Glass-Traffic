use crate::types::{classify_special_ip, OsintInfo};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{mpsc, Arc, RwLock};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct OsintConfig {
    pub offline: bool,
    pub abuseipdb_key: Option<String>,
    pub vt_key: Option<String>,
}

struct LookupRequest {
    ip: String,
    force_refresh: bool,
}

pub struct OsintEngine {
    cache: Arc<RwLock<HashMap<String, OsintInfo>>>,
    inflight: Arc<RwLock<HashSet<String>>>,
    tx: mpsc::Sender<LookupRequest>,
    offline: bool,
}

impl OsintEngine {
    pub fn new(config: OsintConfig) -> Self {
        let cache = Arc::new(RwLock::new(HashMap::new()));
        let inflight = Arc::new(RwLock::new(HashSet::new()));
        let (tx, rx) = mpsc::channel::<LookupRequest>();

        let cache_bg = Arc::clone(&cache);
        let inflight_bg = Arc::clone(&inflight);
        let offline = config.offline;

        thread::Builder::new()
            .name("glasstrace-osint".into())
            .spawn(move || {
                Self::worker_loop(rx, cache_bg, inflight_bg, config);
            })
            .expect("failed to spawn OSINT worker thread");

        Self {
            cache,
            inflight,
            tx,
            offline,
        }
    }

    /// Look up cached OSINT info for an IP. If not cached yet, returns an immediate
    /// classification (private / offline hint / pending) and queues an async live lookup.
    pub fn lookup(&self, ip: &str) -> OsintInfo {
        if let Ok(guard) = self.cache.read() {
            if let Some(info) = guard.get(ip) {
                return info.clone();
            }
        }

        // Instant classification for special/private IPs
        if let Ok(parsed) = ip.parse::<IpAddr>() {
            if let Some(label) = classify_special_ip(parsed) {
                let info = OsintInfo::private_network(ip, label);
                if let Ok(mut guard) = self.cache.write() {
                    guard.insert(ip.to_string(), info.clone());
                }
                return info;
            }
        }

        // Offline mode uses deterministic fallback table immediately
        if self.offline {
            let info = offline_fallback(ip);
            if let Ok(mut guard) = self.cache.write() {
                guard.insert(ip.to_string(), info.clone());
            }
            return info;
        }

        // Enqueue live async lookup if not already in flight
        let should_queue = if let Ok(mut guard) = self.inflight.write() {
            guard.insert(ip.to_string())
        } else {
            false
        };

        if should_queue {
            let _ = self.tx.send(LookupRequest {
                ip: ip.to_string(),
                force_refresh: false,
            });
        }

        // Return offline hint if available while live lookup completes, otherwise pending
        offline_hint(ip).unwrap_or_else(|| OsintInfo::pending(ip))
    }

    /// Force an immediate live refresh for a specific IP (triggered from Deep Inspector).
    pub fn refresh(&self, ip: &str) {
        if let Ok(parsed) = ip.parse::<IpAddr>() {
            if classify_special_ip(parsed).is_some() {
                return;
            }
        }
        let _ = self.tx.send(LookupRequest {
            ip: ip.to_string(),
            force_refresh: true,
        });
    }

    pub fn cache_len(&self) -> usize {
        self.cache.read().map(|g| g.len()).unwrap_or(0)
    }

    fn worker_loop(
        rx: mpsc::Receiver<LookupRequest>,
        cache: Arc<RwLock<HashMap<String, OsintInfo>>>,
        inflight: Arc<RwLock<HashSet<String>>>,
        config: OsintConfig,
    ) {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(4))
            .timeout_read(Duration::from_secs(5))
            .build();

        while let Ok(req) = rx.recv() {
            if !req.force_refresh {
                if let Ok(guard) = cache.read() {
                    if let Some(existing) = guard.get(&req.ip) {
                        if existing.source == "live" {
                            if let Ok(mut inf) = inflight.write() {
                                inf.remove(&req.ip);
                            }
                            continue;
                        }
                    }
                }
            }

            let mut info = if config.offline {
                offline_fallback(&req.ip)
            } else {
                fetch_ip_api(&agent, &req.ip).unwrap_or_else(|| offline_fallback(&req.ip))
            };

            if !config.offline {
                if let Some(ref key) = config.abuseipdb_key {
                    if let Some(score) = fetch_abuseipdb(&agent, &req.ip, key) {
                        info.abuseipdb_score = Some(score);
                    }
                }
                if let Some(ref key) = config.vt_key {
                    if let Some(malicious) = fetch_virustotal(&agent, &req.ip, key) {
                        info.virustotal_malicious = Some(malicious);
                    }
                }
            }

            compute_risk_score(&mut info);

            if let Ok(mut guard) = cache.write() {
                guard.insert(req.ip.clone(), info);
            }
            if let Ok(mut inf) = inflight.write() {
                inf.remove(&req.ip);
            }

            // Respect ip-api.com free-tier rate limit (~45 req/min -> ~1.4s spacing)
            if !config.offline {
                thread::sleep(Duration::from_millis(1400));
            }
        }
    }
}

fn fetch_ip_api(agent: &ureq::Agent, ip: &str) -> Option<OsintInfo> {
    let url = format!(
        "http://ip-api.com/json/{}?fields=status,country,countryCode,city,lat,lon,isp,org,as,reverse,proxy,hosting",
        ip
    );
    let resp = agent.get(&url).call().ok()?;
    let json: serde_json::Value = resp.into_json().ok()?;
    if json.get("status").and_then(|v| v.as_str()) != Some("success") {
        return None;
    }

    let str_field = |k: &str| {
        json.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    Some(OsintInfo {
        ip: ip.to_string(),
        country: str_field("country"),
        country_code: str_field("countryCode"),
        city: str_field("city"),
        lat: json.get("lat").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32,
        lon: json.get("lon").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32,
        asn: str_field("as"),
        isp: str_field("isp"),
        org: str_field("org"),
        rdns: str_field("reverse"),
        is_proxy: json.get("proxy").and_then(|v| v.as_bool()).unwrap_or(false),
        is_hosting: json
            .get("hosting")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        is_private: false,
        risk_score: 0,
        risk_reasons: Vec::new(),
        abuseipdb_score: None,
        virustotal_malicious: None,
        source: "live".to_string(),
    })
}

/// Detect the local machine's public GeoIP coordinates (lat, lon, "City, CC") via ip-api.com.
pub fn detect_local_geoip() -> Option<(f32, f32, String)> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(4))
        .timeout_read(Duration::from_secs(5))
        .build();
    let resp = agent
        .get("http://ip-api.com/json/?fields=status,countryCode,city,lat,lon")
        .call()
        .ok()?;
    let json: serde_json::Value = resp.into_json().ok()?;
    if json.get("status").and_then(|v| v.as_str()) != Some("success") {
        return None;
    }
    let lat = json.get("lat")?.as_f64()? as f32;
    let lon = json.get("lon")?.as_f64()? as f32;
    let city = json.get("city").and_then(|v| v.as_str()).unwrap_or("");
    let cc = json
        .get("countryCode")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let label = if !city.is_empty() && !cc.is_empty() {
        format!("{}, {}", city, cc)
    } else if !cc.is_empty() {
        cc.to_string()
    } else {
        format!("{:.2}, {:.2}", lat, lon)
    };
    Some((lat, lon, label))
}

fn fetch_abuseipdb(agent: &ureq::Agent, ip: &str, api_key: &str) -> Option<u8> {
    let url = format!(
        "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
        ip
    );
    let resp = agent
        .get(&url)
        .set("Key", api_key)
        .set("Accept", "application/json")
        .call()
        .ok()?;
    let json: serde_json::Value = resp.into_json().ok()?;
    json.get("data")?
        .get("abuseConfidenceScore")?
        .as_u64()
        .map(|v| v.min(100) as u8)
}

fn fetch_virustotal(agent: &ureq::Agent, ip: &str, api_key: &str) -> Option<u32> {
    let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip);
    let resp = agent
        .get(&url)
        .set("x-apikey", api_key)
        .set("Accept", "application/json")
        .call()
        .ok()?;
    let json: serde_json::Value = resp.into_json().ok()?;
    json.get("data")?
        .get("attributes")?
        .get("last_analysis_stats")?
        .get("malicious")?
        .as_u64()
        .map(|v| v as u32)
}

pub fn compute_risk_score(info: &mut OsintInfo) {
    if info.is_private {
        info.risk_score = 0;
        info.risk_reasons.clear();
        return;
    }

    let mut score: u32 = 5;
    let mut reasons = Vec::new();

    if info.is_proxy {
        score += 42;
        reasons.push("Proxy / VPN / Tor relay detected".to_string());
    }
    if info.is_hosting {
        score += 15;
        reasons.push("Cloud / Datacenter hosting endpoint".to_string());
    }
    if info.rdns.is_empty() && !info.is_private {
        score += 8;
        reasons.push("No reverse DNS (PTR) record".to_string());
    }
    if let Some(abuse) = info.abuseipdb_score {
        if abuse >= 50 {
            score += 45;
            reasons.push(format!("AbuseIPDB high confidence ({}%)", abuse));
        } else if abuse >= 15 {
            score += 20;
            reasons.push(format!("AbuseIPDB reports ({}%)", abuse));
        }
    }
    if let Some(vt) = info.virustotal_malicious {
        if vt >= 3 {
            score += 50;
            reasons.push(format!("VirusTotal flagged by {} engines", vt));
        } else if vt >= 1 {
            score += 25;
            reasons.push(format!("VirusTotal flagged by {} engine(s)", vt));
        }
    }

    let org_lower = format!("{} {} {}", info.org, info.isp, info.asn).to_lowercase();
    if org_lower.contains("tor") || org_lower.contains("exit") || org_lower.contains("bulletproof") {
        score += 35;
        reasons.push("Anonymizer / high-risk ASN keyword".to_string());
    }

    info.risk_score = score.min(100) as u8;
    info.risk_reasons = reasons;
}

fn offline_hint(ip: &str) -> Option<OsintInfo> {
    let entries: &[(&str, &str, &str, &str, f32, f32, &str, &str, bool, bool)] = &[
        (
            "1.1.1.",
            "United States",
            "US",
            "San Francisco",
            37.7749,
            -122.4194,
            "AS13335 Cloudflare, Inc.",
            "Cloudflare",
            false,
            true,
        ),
        (
            "1.0.0.",
            "Australia",
            "AU",
            "Sydney",
            -33.8688,
            151.2093,
            "AS13335 Cloudflare, Inc.",
            "Cloudflare",
            false,
            true,
        ),
        (
            "8.8.8.",
            "United States",
            "US",
            "Mountain View",
            37.4056,
            -122.0775,
            "AS15169 Google LLC",
            "Google Public DNS",
            false,
            true,
        ),
        (
            "8.8.4.",
            "United States",
            "US",
            "Mountain View",
            37.4056,
            -122.0775,
            "AS15169 Google LLC",
            "Google Public DNS",
            false,
            true,
        ),
        (
            "140.82.",
            "United States",
            "US",
            "Ashburn",
            39.0438,
            -77.4874,
            "AS36459 GitHub, Inc.",
            "GitHub",
            false,
            true,
        ),
        (
            "13.107.",
            "United States",
            "US",
            "Redmond",
            47.6740,
            -122.1215,
            "AS8075 Microsoft Corp",
            "Microsoft Azure",
            false,
            true,
        ),
        (
            "20.",
            "United States",
            "US",
            "Des Moines",
            41.5868,
            -93.6250,
            "AS8075 Microsoft Corp",
            "Microsoft Azure",
            false,
            true,
        ),
        (
            "52.",
            "United States",
            "US",
            "Ashburn",
            39.0438,
            -77.4874,
            "AS16509 Amazon.com, Inc.",
            "Amazon AWS",
            false,
            true,
        ),
        (
            "54.",
            "Ireland",
            "IE",
            "Dublin",
            53.3498,
            -6.2603,
            "AS16509 Amazon.com, Inc.",
            "Amazon AWS",
            false,
            true,
        ),
        (
            "142.250.",
            "United States",
            "US",
            "Mountain View",
            37.4056,
            -122.0775,
            "AS15169 Google LLC",
            "Google Cloud",
            false,
            true,
        ),
        (
            "104.16.",
            "United States",
            "US",
            "San Jose",
            37.3382,
            -121.8863,
            "AS13335 Cloudflare, Inc.",
            "Cloudflare CDN",
            false,
            true,
        ),
        (
            "151.101.",
            "United States",
            "US",
            "San Francisco",
            37.7749,
            -122.4194,
            "AS54113 Fastly, Inc.",
            "Fastly CDN",
            false,
            true,
        ),
        (
            "185.220.",
            "Germany",
            "DE",
            "Frankfurt",
            50.1109,
            8.6821,
            "AS205100 F3 Netze e.V.",
            "Tor Exit Relay",
            true,
            true,
        ),
    ];

    for &(prefix, country, cc, city, lat, lon, asn, org, is_proxy, is_hosting) in entries {
        if ip.starts_with(prefix) {
            let mut info = OsintInfo {
                ip: ip.to_string(),
                country: country.to_string(),
                country_code: cc.to_string(),
                city: city.to_string(),
                lat,
                lon,
                asn: asn.to_string(),
                isp: org.to_string(),
                org: org.to_string(),
                rdns: String::new(),
                is_proxy,
                is_hosting,
                is_private: false,
                risk_score: 0,
                risk_reasons: Vec::new(),
                abuseipdb_score: None,
                virustotal_malicious: None,
                source: "offline".to_string(),
            };
            compute_risk_score(&mut info);
            return Some(info);
        }
    }
    None
}

fn offline_fallback(ip: &str) -> OsintInfo {
    if let Some(hit) = offline_hint(ip) {
        return hit;
    }

    // Deterministic geographic placement for unknown public IPs in offline mode
    let mut hash: u32 = 2166136261;
    for b in ip.bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(16777619);
    }

    let hubs = [
        ("United States", "US", "Ashburn", 39.04f32, -77.48f32),
        ("Germany", "DE", "Frankfurt", 50.11, 8.68),
        ("United Kingdom", "GB", "London", 51.50, -0.12),
        ("Netherlands", "NL", "Amsterdam", 52.37, 4.89),
        ("Singapore", "SG", "Singapore", 1.35, 103.82),
        ("Japan", "JP", "Tokyo", 35.68, 139.69),
        ("France", "FR", "Paris", 48.85, 2.35),
        ("Canada", "CA", "Toronto", 43.65, -79.38),
    ];
    let (country, cc, city, lat, lon) = hubs[(hash as usize) % hubs.len()];
    let mut info = OsintInfo {
        ip: ip.to_string(),
        country: country.to_string(),
        country_code: cc.to_string(),
        city: city.to_string(),
        lat,
        lon,
        asn: "AS-UNKNOWN (Offline)".to_string(),
        isp: "Offline GeoIP Estimate".to_string(),
        org: "Unresolved (Offline)".to_string(),
        rdns: String::new(),
        is_proxy: false,
        is_hosting: false,
        is_private: false,
        risk_score: 0,
        risk_reasons: Vec::new(),
        abuseipdb_score: None,
        virustotal_malicious: None,
        source: "offline".to_string(),
    };
    compute_risk_score(&mut info);
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ip_gets_zero_risk() {
        let engine = OsintEngine::new(OsintConfig {
            offline: true,
            abuseipdb_key: None,
            vt_key: None,
        });
        let info = engine.lookup("192.168.1.50");
        assert!(info.is_private);
        assert_eq!(info.risk_score, 0);
        assert_eq!(info.country_code, "LAN");
    }

    #[test]
    fn tor_relay_scores_high_risk() {
        let engine = OsintEngine::new(OsintConfig {
            offline: true,
            abuseipdb_key: None,
            vt_key: None,
        });
        let info = engine.lookup("185.220.101.42");
        assert!(info.is_proxy);
        assert!(info.risk_score >= 60);
    }
}
