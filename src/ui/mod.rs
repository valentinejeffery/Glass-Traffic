pub mod bandwidth_graph;
pub mod panels;
pub mod world_map;

use crate::osint::OsintEngine;
use crate::state::TelemetryState;
use crate::types::{format_bytes, format_rate, CaptureMode};
use crate::ui::bandwidth_graph::draw_bandwidth_graph;
use crate::ui::panels::{
    draw_apps_panel, draw_flows_table, draw_right_panel, DirectionFilter, ProtoFilter, RightTab,
};
use crate::ui::world_map::draw_world_map;
use eframe::egui::{self, Color32, RichText, Stroke};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

pub struct GlassTraceApp {
    state: Arc<RwLock<TelemetryState>>,
    osint: Arc<OsintEngine>,
    start_time: Instant,
    selected_app: Option<String>,
    selected_ip: Option<String>,
    dir_filter: DirectionFilter,
    proto_filter: ProtoFilter,
    search: String,
    right_tab: RightTab,
    toast_msg: Option<(String, Instant)>,
}

impl GlassTraceApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        state: Arc<RwLock<TelemetryState>>,
        osint: Arc<OsintEngine>,
    ) -> Self {
        apply_glass_theme(&cc.egui_ctx);
        Self {
            state,
            osint,
            start_time: Instant::now(),
            selected_app: None,
            selected_ip: None,
            dir_filter: DirectionFilter::All,
            proto_filter: ProtoFilter::All,
            search: String::new(),
            right_tab: RightTab::Alerts,
            toast_msg: None,
        }
    }

    fn show_toast(&mut self, msg: String) {
        self.toast_msg = Some((msg, Instant::now()));
    }
}

impl eframe::App for GlassTraceApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Keep animated map arcs & live telemetry smooth (~30 FPS)
        ctx.request_repaint_after(Duration::from_millis(33));

        let (snap, is_paused) = {
            let guard = self.state.read().expect("state lock poisoned");
            (guard.snapshot(), guard.paused)
        };

        let mut switch_mode_to: Option<CaptureMode> = None;
        let mut toggle_pause = false;
        let mut export_csv = false;
        let mut export_json = false;
        let mut clear_alerts = false;

        // Top Command & KPI Bar
        egui::TopBottomPanel::top("top_bar")
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_rgb(11, 16, 26))
                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(30, 41, 59)))
                    .inner_margin(egui::Margin::symmetric(12.0, 8.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    // Brand
                    ui.label(
                        RichText::new("◈ GLASSTRACE")
                            .strong()
                            .size(16.0)
                            .color(Color32::from_rgb(34, 211, 238)),
                    );
                    ui.label(
                        RichText::new("DESKTOP")
                            .strong()
                            .size(10.0)
                            .color(Color32::from_rgb(168, 85, 247)),
                    );
                    ui.separator();

                    // Live vs Sim toggle
                    if ui
                        .selectable_label(snap.mode == CaptureMode::Live, "● LIVE CAPTURE")
                        .clicked()
                        && snap.mode != CaptureMode::Live
                    {
                        switch_mode_to = Some(CaptureMode::Live);
                    }
                    if ui
                        .selectable_label(snap.mode == CaptureMode::Sim, "◎ GLOBAL SIM")
                        .clicked()
                        && snap.mode != CaptureMode::Sim
                    {
                        switch_mode_to = Some(CaptureMode::Sim);
                    }

                    if ui
                        .button(if is_paused { "▶ Resume" } else { "⏸ Pause" })
                        .clicked()
                    {
                        toggle_pause = true;
                    }

                    ui.separator();

                    // KPI pills
                    kpi_pill(
                        ui,
                        "IN (RX)",
                        &format_rate(snap.current_rx_bps),
                        Color32::from_rgb(34, 211, 238),
                    );
                    kpi_pill(
                        ui,
                        "OUT (TX)",
                        &format_rate(snap.current_tx_bps),
                        Color32::from_rgb(168, 85, 247),
                    );
                    kpi_pill(
                        ui,
                        "SESSION",
                        &format!(
                            "↓{} ↑{}",
                            format_bytes(snap.session_rx_bytes),
                            format_bytes(snap.session_tx_bytes)
                        ),
                        Color32::from_rgb(203, 213, 225),
                    );
                    kpi_pill(
                        ui,
                        "FLOWS",
                        &format!(
                            "{} IN / {} OUT / {} LISTEN",
                            snap.inbound_count, snap.outbound_count, snap.listening_count
                        ),
                        Color32::from_rgb(56, 189, 248),
                    );
                    kpi_pill(
                        ui,
                        "COUNTRIES",
                        &format!("{}", snap.unique_countries),
                        Color32::from_rgb(16, 185, 129),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Export JSON").clicked() {
                            export_json = true;
                        }
                        if ui.button("Export CSV").clicked() {
                            export_csv = true;
                        }
                    });
                });

                // Second compact status line: capture backend privilege badge + interfaces + toast
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let badge_col = if snap.backend.raw_capture_active {
                        Color32::from_rgb(16, 185, 129)
                    } else {
                        Color32::from_rgb(245, 158, 11)
                    };
                    ui.label(
                        RichText::new(format!("● {}", snap.backend.backend_name))
                            .strong()
                            .size(11.0)
                            .color(badge_col),
                    )
                    .on_hover_text(&snap.backend.elevation_note);

                    ui.label(
                        RichText::new(format!("— {}", snap.backend.elevation_note))
                            .size(10.5)
                            .color(Color32::from_rgb(148, 163, 184)),
                    );

                    if snap.backend.raw_packets_captured > 0 {
                        ui.label(
                            RichText::new(format!(
                                " | Raw Packets: {}",
                                snap.backend.raw_packets_captured
                            ))
                            .monospace()
                            .size(10.5)
                            .color(Color32::from_rgb(148, 163, 184)),
                        );
                    }

                    if !snap.backend.active_interfaces.is_empty() {
                        ui.label(
                            RichText::new(format!(
                                " | NICs: {}",
                                snap.backend.active_interfaces.join(", ")
                            ))
                            .size(10.5)
                            .color(Color32::from_rgb(100, 116, 139)),
                        );
                    }

                    if let Some((ref msg, when)) = self.toast_msg {
                        if when.elapsed() < Duration::from_secs(5) {
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        RichText::new(msg)
                                            .strong()
                                            .size(11.0)
                                            .color(Color32::from_rgb(16, 185, 129)),
                                    );
                                },
                            );
                        }
                    }
                });
            });

        // Left Sidebar: Per-Application Breakdown
        egui::SidePanel::left("apps_panel")
            .resizable(true)
            .default_width(235.0)
            .min_width(180.0)
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_rgb(11, 16, 26))
                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(30, 41, 59)))
                    .inner_margin(8.0),
            )
            .show(ctx, |ui| {
                draw_apps_panel(ui, &snap.apps, &mut self.selected_app);
            });

        // Right Sidebar: Live OSINT Feed & Deep Endpoint Inspector
        egui::SidePanel::right("osint_panel")
            .resizable(true)
            .default_width(310.0)
            .min_width(240.0)
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_rgb(11, 16, 26))
                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(30, 41, 59)))
                    .inner_margin(8.0),
            )
            .show(ctx, |ui| {
                draw_right_panel(
                    ui,
                    &mut self.right_tab,
                    &snap.alerts,
                    &snap.flows,
                    &mut self.selected_ip,
                    &self.osint,
                    &mut clear_alerts,
                );
            });

        // Center Workspace: World Map + Bandwidth Wave Graph + Incoming/Outgoing Flows Table
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_rgb(8, 12, 21))
                    .inner_margin(10.0),
            )
            .show(ctx, |ui| {
                let total_h = ui.available_height();
                let map_h = (total_h * 0.38).clamp(210.0, 360.0);

                ui.allocate_ui(egui::Vec2::new(ui.available_width(), map_h), |ui| {
                    let prev_ip = self.selected_ip.clone();
                    draw_world_map(
                        ui,
                        &snap.flows,
                        snap.home_lat,
                        snap.home_lon,
                        &mut self.selected_ip,
                        self.start_time.elapsed().as_secs_f64(),
                    );
                    if self.selected_ip != prev_ip && self.selected_ip.is_some() {
                        self.right_tab = RightTab::Inspector;
                    }
                });

                ui.add_space(8.0);
                draw_bandwidth_graph(ui, &snap.history);
                ui.add_space(8.0);

                draw_flows_table(
                    ui,
                    &snap.flows,
                    &mut self.dir_filter,
                    &mut self.proto_filter,
                    &self.selected_app,
                    &mut self.search,
                    &mut self.selected_ip,
                    &mut self.right_tab,
                );
            });

        // Apply state mutations outside the read lock
        if let Some(new_mode) = switch_mode_to {
            if let Ok(mut guard) = self.state.write() {
                guard.reset_for_mode_switch(new_mode);
            }
            self.selected_app = None;
            self.selected_ip = None;
        }
        if toggle_pause {
            if let Ok(mut guard) = self.state.write() {
                guard.paused = !guard.paused;
            }
        }
        if clear_alerts {
            if let Ok(mut guard) = self.state.write() {
                guard.clear_alerts();
            }
        }
        if export_csv {
            let res = self.state.read().ok().map(|g| g.export_csv());
            match res {
                Some(Ok(p)) => self.show_toast(format!("Saved {}", p.display())),
                Some(Err(e)) => self.show_toast(format!("CSV export failed: {}", e)),
                None => {}
            }
        }
        if export_json {
            let res = self.state.read().ok().map(|g| g.export_json());
            match res {
                Some(Ok(p)) => self.show_toast(format!("Saved {}", p.display())),
                Some(Err(e)) => self.show_toast(format!("JSON export failed: {}", e)),
                None => {}
            }
        }
    }
}

fn kpi_pill(ui: &mut egui::Ui, label: &str, value: &str, color: Color32) {
    egui::Frame::none()
        .fill(Color32::from_rgb(15, 23, 38))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(30, 41, 59)))
        .rounding(5.0)
        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(label)
                        .size(10.0)
                        .color(Color32::from_rgb(100, 116, 139)),
                );
                ui.label(RichText::new(value).strong().monospace().size(11.5).color(color));
            });
        });
}

fn apply_glass_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.window_fill = Color32::from_rgb(11, 16, 26);
    visuals.panel_fill = Color32::from_rgb(11, 16, 26);
    visuals.faint_bg_color = Color32::from_rgb(15, 23, 38);
    visuals.extreme_bg_color = Color32::from_rgb(8, 12, 21);
    visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(15, 23, 38);
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(20, 30, 48);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(30, 45, 72);
    visuals.widgets.active.bg_fill = Color32::from_rgb(34, 211, 238);
    visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(34, 211, 238, 60);
    visuals.selection.stroke = Stroke::new(1.0_f32, Color32::from_rgb(34, 211, 238));
    ctx.set_visuals(visuals);
}
