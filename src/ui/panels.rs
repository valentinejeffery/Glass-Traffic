use crate::osint::OsintEngine;
use crate::types::{
    format_bytes, format_rate, AlertEvent, AlertKind, AppSummary, Direction, Flow, Protocol,
};
use eframe::egui::{self, Color32, RichText, Stroke};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectionFilter {
    All,
    Inbound,
    Outbound,
    Listening,
    HighRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoFilter {
    All,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RightTab {
    Alerts,
    Inspector,
}

pub fn risk_color(score: u8) -> Color32 {
    if score >= 60 {
        Color32::from_rgb(239, 68, 68)
    } else if score >= 30 {
        Color32::from_rgb(245, 158, 11)
    } else {
        Color32::from_rgb(16, 185, 129)
    }
}

pub fn direction_color(dir: Direction) -> Color32 {
    match dir {
        Direction::Inbound => Color32::from_rgb(34, 211, 238),
        Direction::Outbound => Color32::from_rgb(168, 85, 247),
        Direction::Listening => Color32::from_rgb(16, 185, 129),
        Direction::Local => Color32::from_rgb(148, 163, 184),
    }
}

/// Draw a crisp vector arrow directly on the painter (no font glyph dependency).
/// `pointing_up = true` for Outgoing (TX), `pointing_up = false` for Incoming (RX).
pub fn draw_dir_arrow(ui: &mut egui::Ui, pointing_up: bool, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::Vec2::new(9.0, 12.0), egui::Sense::hover());
    let p = ui.painter();
    let cx = rect.center().x;
    let top = rect.top() + 1.5;
    let bot = rect.bottom() - 1.5;
    let stroke = Stroke::new(1.6_f32, color);

    // Shaft
    p.line_segment([egui::Pos2::new(cx, top), egui::Pos2::new(cx, bot)], stroke);

    // Arrowhead
    if pointing_up {
        p.line_segment(
            [egui::Pos2::new(cx, top), egui::Pos2::new(cx - 3.2, top + 3.5)],
            stroke,
        );
        p.line_segment(
            [egui::Pos2::new(cx, top), egui::Pos2::new(cx + 3.2, top + 3.5)],
            stroke,
        );
    } else {
        p.line_segment(
            [egui::Pos2::new(cx, bot), egui::Pos2::new(cx - 3.2, bot - 3.5)],
            stroke,
        );
        p.line_segment(
            [egui::Pos2::new(cx, bot), egui::Pos2::new(cx + 3.2, bot - 3.5)],
            stroke,
        );
    }
}

pub fn draw_apps_panel(
    ui: &mut egui::Ui,
    apps: &[AppSummary],
    selected_app: &mut Option<String>,
) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("APPLICATIONS")
                .strong()
                .size(12.0)
                .color(Color32::from_rgb(148, 163, 184)),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if selected_app.is_some() && ui.small_button("Clear").clicked() {
                *selected_app = None;
            }
            ui.label(
                RichText::new(format!("{}", apps.len()))
                    .size(11.0)
                    .color(Color32::from_rgb(100, 116, 139)),
            );
        });
    });
    ui.add_space(4.0);

    let max_rate = apps
        .iter()
        .map(|a| a.rx_bps + a.tx_bps)
        .max()
        .unwrap_or(1)
        .max(1) as f32;

    egui::ScrollArea::vertical()
        .id_salt("apps_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for app in apps {
                let is_selected = selected_app.as_deref() == Some(app.process_name.as_str());
                let fill = if is_selected {
                    ui.visuals().widgets.hovered.bg_fill
                } else {
                    ui.visuals().faint_bg_color
                };
                let border = if is_selected {
                    Color32::from_rgb(34, 211, 238)
                } else {
                    ui.visuals().widgets.noninteractive.bg_stroke.color
                };

                let frame_resp = egui::Frame::none()
                    .fill(fill)
                    .stroke(Stroke::new(1.0_f32, border))
                    .rounding(5.0)
                    .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(&app.process_name)
                                    .strong()
                                    .size(12.5)
                                    .color(Color32::from_rgb(226, 232, 240)),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if app.max_risk >= 60 {
                                        ui.label(
                                            RichText::new(format!("!{}", app.max_risk))
                                                .strong()
                                                .size(10.5)
                                                .color(Color32::from_rgb(239, 68, 68)),
                                        );
                                    }
                                    ui.label(
                                        RichText::new(format!("{}f", app.flow_count))
                                            .size(10.5)
                                            .color(Color32::from_rgb(100, 116, 139)),
                                    );
                                },
                            );
                        });

                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 3.0;
                            // Incoming (RX) — arrow pointing DOWN
                            draw_dir_arrow(ui, false, Color32::from_rgb(34, 211, 238));
                            ui.label(
                                RichText::new(format_rate(app.rx_bps))
                                    .size(10.5)
                                    .color(Color32::from_rgb(34, 211, 238)),
                            );
                            ui.add_space(6.0);
                            // Outgoing (TX) — arrow pointing UP
                            draw_dir_arrow(ui, true, Color32::from_rgb(168, 85, 247));
                            ui.label(
                                RichText::new(format_rate(app.tx_bps))
                                    .size(10.5)
                                    .color(Color32::from_rgb(168, 85, 247)),
                            );
                            if app.inbound_count > 0 {
                                ui.add_space(4.0);
                                ui.label(
                                    RichText::new(format!("IN:{}", app.inbound_count))
                                        .size(10.0)
                                        .color(Color32::from_rgb(56, 189, 248)),
                                );
                            }
                        });

                        // Mini activity bar
                        let frac = ((app.rx_bps + app.tx_bps) as f32 / max_rate).clamp(0.03, 1.0);
                        let (bar_rect, _) = ui.allocate_exact_size(
                            egui::Vec2::new(ui.available_width(), 3.5),
                            egui::Sense::hover(),
                        );
                        let p = ui.painter();
                        p.rect_filled(
                            bar_rect,
                            2.0,
                            ui.visuals().widgets.noninteractive.bg_stroke.color,
                        );
                        let mut active_rect = bar_rect;
                        active_rect.set_width(bar_rect.width() * frac);
                        p.rect_filled(
                            active_rect,
                            2.0,
                            if app.max_risk >= 60 {
                                Color32::from_rgb(239, 68, 68)
                            } else {
                                Color32::from_rgb(34, 211, 238)
                            },
                        );
                    });

                let click = frame_resp.response.interact(egui::Sense::click());
                if click.clicked() {
                    if is_selected {
                        *selected_app = None;
                    } else {
                        *selected_app = Some(app.process_name.clone());
                    }
                }
                ui.add_space(4.0);
            }
        });
}

#[allow(clippy::too_many_arguments)]
pub fn draw_flows_table(
    ui: &mut egui::Ui,
    flows: &[Flow],
    dir_filter: &mut DirectionFilter,
    proto_filter: &mut ProtoFilter,
    selected_app: &Option<String>,
    search: &mut String,
    selected_ip: &mut Option<String>,
    right_tab: &mut RightTab,
) {
    // Filter toolbar
    ui.horizontal_wrapped(|ui| {
        ui.label(
            RichText::new("TRAFFIC FLOWS")
                .strong()
                .size(12.0)
                .color(Color32::from_rgb(148, 163, 184)),
        );
        ui.separator();

        for (label, val) in [
            ("All", DirectionFilter::All),
            ("Inbound (IN)", DirectionFilter::Inbound),
            ("Outbound (OUT)", DirectionFilter::Outbound),
            ("Listening", DirectionFilter::Listening),
            ("High Risk", DirectionFilter::HighRisk),
        ] {
            if ui.selectable_label(*dir_filter == val, label).clicked() {
                *dir_filter = val;
            }
        }

        ui.separator();
        for (label, val) in [
            ("All", ProtoFilter::All),
            ("TCP", ProtoFilter::Tcp),
            ("UDP", ProtoFilter::Udp),
            ("ICMP", ProtoFilter::Icmp),
        ] {
            if ui.selectable_label(*proto_filter == val, label).clicked() {
                *proto_filter = val;
            }
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add(
                egui::TextEdit::singleline(search)
                    .hint_text("Search IP, app, country, port...")
                    .desired_width(190.0),
            );
        });
    });

    ui.add_space(4.0);

    let q = search.trim().to_lowercase();
    let mut filtered: Vec<&Flow> = flows
        .iter()
        .filter(|f| {
            if let Some(ref app) = selected_app {
                if &f.process_name != app {
                    return false;
                }
            }
            match dir_filter {
                DirectionFilter::All => true,
                DirectionFilter::Inbound => {
                    f.direction == Direction::Inbound || f.rx_bps > 0 || f.total_rx > 0
                }
                DirectionFilter::Outbound => {
                    f.direction == Direction::Outbound || f.tx_bps > 0 || f.total_tx > 0
                }
                DirectionFilter::Listening => f.direction == Direction::Listening,
                DirectionFilter::HighRisk => f.osint.risk_score >= 60,
            }
        })
        .filter(|f| match proto_filter {
            ProtoFilter::All => true,
            ProtoFilter::Tcp => f.protocol == Protocol::Tcp,
            ProtoFilter::Udp => f.protocol == Protocol::Udp,
            ProtoFilter::Icmp => f.protocol == Protocol::Icmp,
        })
        .filter(|f| {
            if q.is_empty() {
                return true;
            }
            f.remote_ip.to_lowercase().contains(&q)
                || f.process_name.to_lowercase().contains(&q)
                || f.osint.country.to_lowercase().contains(&q)
                || f.osint.country_code.to_lowercase().contains(&q)
                || f.osint.org.to_lowercase().contains(&q)
                || f.remote_port.to_string().contains(&q)
                || f.local_port.to_string().contains(&q)
        })
        .collect();

    // Sort by incoming volume when viewing Inbound, outgoing volume when viewing Outbound
    match dir_filter {
        DirectionFilter::Inbound => filtered.sort_by(|a, b| {
            b.rx_bps
                .cmp(&a.rx_bps)
                .then_with(|| b.total_rx.cmp(&a.total_rx))
        }),
        DirectionFilter::Outbound => filtered.sort_by(|a, b| {
            b.tx_bps
                .cmp(&a.tx_bps)
                .then_with(|| b.total_tx.cmp(&a.total_tx))
        }),
        _ => {}
    }

    egui::ScrollArea::vertical()
        .id_salt("flows_table_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("flows_grid")
                .num_columns(9)
                .striped(true)
                .spacing([10.0, 5.0])
                .min_col_width(40.0)
                .show(ui, |ui| {
                    // Header row
                    for h in [
                        "DIR",
                        "PROTO",
                        "PROCESS",
                        "LOCAL PORT",
                        "REMOTE ENDPOINT",
                        "LOCATION / ORG",
                        "IN (RX)",
                        "OUT (TX)",
                        "RISK",
                    ] {
                        ui.label(
                            RichText::new(h)
                                .strong()
                                .size(11.0)
                                .color(Color32::from_rgb(148, 163, 184)),
                        );
                    }
                    ui.end_row();

                    for flow in filtered.iter().take(250) {
                        let is_sel = selected_ip.as_deref() == Some(flow.remote_ip.as_str());

                        ui.label(
                            RichText::new(flow.direction.as_str())
                                .strong()
                                .size(11.0)
                                .color(direction_color(flow.direction)),
                        );

                        ui.label(
                            RichText::new(flow.protocol.as_str())
                                .size(11.0)
                                .color(Color32::from_rgb(148, 163, 184)),
                        );

                        let proc_text = if flow.pid > 0 {
                            format!("{} ({})", flow.process_name, flow.pid)
                        } else {
                            flow.process_name.clone()
                        };
                        ui.label(
                            RichText::new(proc_text)
                                .size(11.5)
                                .color(Color32::from_rgb(226, 232, 240)),
                        );

                        ui.label(
                            RichText::new(format!(":{}", flow.local_port))
                                .monospace()
                                .size(11.0)
                                .color(Color32::from_rgb(148, 163, 184)),
                        );

                        let ep = if flow.remote_port > 0 {
                            format!("{}:{}", flow.remote_ip, flow.remote_port)
                        } else {
                            flow.remote_ip.clone()
                        };
                        let ep_btn = ui.selectable_label(
                            is_sel,
                            RichText::new(ep).monospace().size(11.5).color(if is_sel {
                                Color32::from_rgb(34, 211, 238)
                            } else {
                                Color32::from_rgb(241, 245, 249)
                            }),
                        );
                        if ep_btn.clicked() {
                            *selected_ip = Some(flow.remote_ip.clone());
                            *right_tab = RightTab::Inspector;
                        }

                        let loc = if flow.osint.is_private {
                            flow.osint.country.clone()
                        } else if flow.osint.org.is_empty() {
                            format!("{} {}", flow.osint.country_code, flow.osint.country)
                        } else {
                            format!(
                                "[{}] {} — {}",
                                flow.osint.country_code, flow.osint.city, flow.osint.org
                            )
                        };
                        ui.label(
                            RichText::new(loc)
                                .size(11.0)
                                .color(Color32::from_rgb(203, 213, 225)),
                        );

                        ui.label(
                            RichText::new(format_rate(flow.rx_bps))
                                .monospace()
                                .size(11.0)
                                .color(Color32::from_rgb(34, 211, 238)),
                        );

                        ui.label(
                            RichText::new(format_rate(flow.tx_bps))
                                .monospace()
                                .size(11.0)
                                .color(Color32::from_rgb(168, 85, 247)),
                        );

                        ui.label(
                            RichText::new(format!("{}", flow.osint.risk_score))
                                .strong()
                                .size(11.0)
                                .color(risk_color(flow.osint.risk_score)),
                        );

                        ui.end_row();
                    }
                });

            if filtered.is_empty() {
                ui.add_space(16.0);
                ui.centered_and_justified(|ui| {
                    ui.label(
                        RichText::new("No matching traffic flows right now.")
                            .color(Color32::from_rgb(100, 116, 139)),
                    );
                });
            }
        });
}

pub fn draw_right_panel(
    ui: &mut egui::Ui,
    tab: &mut RightTab,
    alerts: &[AlertEvent],
    flows: &[Flow],
    selected_ip: &mut Option<String>,
    osint: &OsintEngine,
    clear_alerts_clicked: &mut bool,
) {
    ui.horizontal(|ui| {
        if ui
            .selectable_label(
                *tab == RightTab::Alerts,
                format!("OSINT Feed ({})", alerts.len()),
            )
            .clicked()
        {
            *tab = RightTab::Alerts;
        }
        if ui
            .selectable_label(*tab == RightTab::Inspector, "Deep Inspector")
            .clicked()
        {
            *tab = RightTab::Inspector;
        }
    });
    ui.separator();

    match tab {
        RightTab::Alerts => {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Live Intelligence Events")
                        .size(11.0)
                        .color(Color32::from_rgb(148, 163, 184)),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if !alerts.is_empty() && ui.small_button("Clear").clicked() {
                        *clear_alerts_clicked = true;
                    }
                });
            });
            ui.add_space(4.0);

            egui::ScrollArea::vertical()
                .id_salt("alerts_scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for ev in alerts {
                        let badge_col = match ev.kind {
                            AlertKind::HighRisk => Color32::from_rgb(239, 68, 68),
                            AlertKind::ProxyRelay => Color32::from_rgb(245, 158, 11),
                            AlertKind::InboundConnection => Color32::from_rgb(34, 211, 238),
                            AlertKind::NewCountry => Color32::from_rgb(168, 85, 247),
                            AlertKind::NewHost => Color32::from_rgb(100, 116, 139),
                        };

                        let resp = egui::Frame::none()
                            .fill(ui.visuals().faint_bg_color)
                            .stroke(Stroke::new(
                                1.0_f32,
                                ui.visuals().widgets.noninteractive.bg_stroke.color,
                            ))
                            .rounding(5.0)
                            .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(ev.kind.label())
                                            .strong()
                                            .size(10.0)
                                            .color(badge_col),
                                    );
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.label(
                                                RichText::new(&ev.timestamp)
                                                    .monospace()
                                                    .size(10.0)
                                                    .color(Color32::from_rgb(100, 116, 139)),
                                            );
                                        },
                                    );
                                });
                                ui.label(
                                    RichText::new(&ev.message)
                                        .size(11.5)
                                        .color(Color32::from_rgb(226, 232, 240)),
                                );
                            });

                        if resp.response.interact(egui::Sense::click()).clicked() {
                            *selected_ip = Some(ev.ip.clone());
                            *tab = RightTab::Inspector;
                        }
                        ui.add_space(4.0);
                    }
                });
        }
        RightTab::Inspector => {
            let Some(ip) = selected_ip.clone() else {
                ui.add_space(20.0);
                ui.label(
                    RichText::new(
                        "Click any endpoint on the World Map, Traffic Flows table, or OSINT Feed to inspect its full GeoIP, ASN, rDNS, and threat telemetry.",
                    )
                    .color(Color32::from_rgb(148, 163, 184)),
                );
                return;
            };

            let info = osint.lookup(&ip);
            let matching_flows: Vec<&Flow> =
                flows.iter().filter(|f| f.remote_ip == ip).collect();

            egui::ScrollArea::vertical()
                .id_salt("inspector_scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(&ip)
                                .monospace()
                                .strong()
                                .size(15.0)
                                .color(Color32::from_rgb(34, 211, 238)),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Live Refresh").clicked() {
                                osint.refresh(&ip);
                            }
                        });
                    });

                    ui.add_space(6.0);
                    // Risk Score Banner
                    let rc = risk_color(info.risk_score);
                    egui::Frame::none()
                        .fill(ui.visuals().faint_bg_color)
                        .stroke(Stroke::new(1.0_f32, rc))
                        .rounding(6.0)
                        .inner_margin(8.0)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("RISK SCORE").strong().size(11.0));
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            RichText::new(format!("{}/100", info.risk_score))
                                                .strong()
                                                .size(14.0)
                                                .color(rc),
                                        );
                                    },
                                );
                            });
                            if info.risk_reasons.is_empty() {
                                ui.label(
                                    RichText::new("No threat indicators flagged.")
                                        .size(11.0)
                                        .color(Color32::from_rgb(148, 163, 184)),
                                );
                            } else {
                                for r in &info.risk_reasons {
                                    ui.label(RichText::new(format!("• {}", r)).size(11.0).color(rc));
                                }
                            }
                        });

                    ui.add_space(8.0);
                    egui::Grid::new("osint_kv")
                        .num_columns(2)
                        .spacing([8.0, 4.0])
                        .show(ui, |ui| {
                            kv_row(
                                ui,
                                "Location",
                                &format!("{} ({}) — {}", info.country, info.country_code, info.city),
                            );
                            kv_row(
                                ui,
                                "Coordinates",
                                &format!("{:.4}, {:.4}", info.lat, info.lon),
                            );
                            kv_row(ui, "ASN", &info.asn);
                            kv_row(ui, "ISP", &info.isp);
                            kv_row(ui, "Org", &info.org);
                            kv_row(
                                ui,
                                "rDNS (PTR)",
                                if info.rdns.is_empty() {
                                    "—"
                                } else {
                                    &info.rdns
                                },
                            );
                            kv_row(
                                ui,
                                "Flags",
                                &format!(
                                    "Proxy/VPN: {}  |  Hosting: {}",
                                    if info.is_proxy { "YES" } else { "No" },
                                    if info.is_hosting { "YES" } else { "No" }
                                ),
                            );
                            if let Some(abuse) = info.abuseipdb_score {
                                kv_row(ui, "AbuseIPDB", &format!("{}% confidence", abuse));
                            }
                            if let Some(vt) = info.virustotal_malicious {
                                kv_row(ui, "VirusTotal", &format!("{} malicious detections", vt));
                            }
                            kv_row(ui, "Intel Source", &info.source);
                        });

                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(format!("ACTIVE SOCKETS ({})", matching_flows.len()))
                            .strong()
                            .size(11.0)
                            .color(Color32::from_rgb(148, 163, 184)),
                    );
                    ui.add_space(4.0);

                    for f in matching_flows {
                        egui::Frame::none()
                            .fill(ui.visuals().faint_bg_color)
                            .stroke(Stroke::new(
                                1.0_f32,
                                ui.visuals().widgets.noninteractive.bg_stroke.color,
                            ))
                            .rounding(5.0)
                            .inner_margin(6.0)
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(f.direction.as_str())
                                            .strong()
                                            .size(10.5)
                                            .color(direction_color(f.direction)),
                                    );
                                    ui.label(
                                        RichText::new(format!(
                                            "{} :{} -> :{}",
                                            f.protocol.as_str(),
                                            f.local_port,
                                            f.remote_port
                                        ))
                                        .monospace()
                                        .size(11.0),
                                    );
                                });
                                ui.label(
                                    RichText::new(format!(
                                        "{} (PID {}) | {}",
                                        f.process_name, f.pid, f.state
                                    ))
                                    .size(11.0)
                                    .color(Color32::from_rgb(203, 213, 225)),
                                );
                                if !f.process_path.is_empty() {
                                    ui.label(
                                        RichText::new(&f.process_path)
                                            .size(9.5)
                                            .color(Color32::from_rgb(100, 116, 139)),
                                    );
                                }
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 3.0;
                                    ui.label(
                                        RichText::new("Total")
                                            .size(10.5)
                                            .color(Color32::from_rgb(148, 163, 184)),
                                    );
                                    draw_dir_arrow(ui, false, Color32::from_rgb(34, 211, 238));
                                    ui.label(
                                        RichText::new(format_bytes(f.total_rx))
                                            .size(10.5)
                                            .color(Color32::from_rgb(34, 211, 238)),
                                    );
                                    ui.add_space(4.0);
                                    draw_dir_arrow(ui, true, Color32::from_rgb(168, 85, 247));
                                    ui.label(
                                        RichText::new(format!(
                                            "{} {}",
                                            format_bytes(f.total_tx),
                                            if f.exact_accounting { "(exact)" } else { "(est)" }
                                        ))
                                        .size(10.5)
                                        .color(Color32::from_rgb(168, 85, 247)),
                                    );
                                });
                            });
                        ui.add_space(4.0);
                    }
                });
        }
    }
}

fn kv_row(ui: &mut egui::Ui, k: &str, v: &str) {
    ui.label(
        RichText::new(k)
            .size(11.0)
            .color(Color32::from_rgb(148, 163, 184)),
    );
    ui.label(
        RichText::new(if v.is_empty() { "—" } else { v })
            .size(11.5)
            .color(Color32::from_rgb(241, 245, 249)),
    );
    ui.end_row();
}
