pub mod bandwidth_graph;
pub mod panels;
pub mod world_map;

use crate::osint::{detect_local_geoip, OsintEngine};
use crate::state::TelemetryState;
use crate::types::{format_bytes, format_rate};
use crate::ui::bandwidth_graph::draw_bandwidth_graph;
use crate::ui::panels::{
    draw_apps_panel, draw_dir_arrow, draw_flows_table, draw_right_panel, DirectionFilter,
    ProtoFilter, RightTab,
};
use crate::ui::world_map::{draw_world_map, MapViewState, ORIGIN_PRESETS};
use eframe::egui::{self, Color32, RichText, Stroke};
use std::sync::{Arc, RwLock};
use std::thread;
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
    map_view: MapViewState,
    show_origin_window: bool,
    custom_origin_label: String,
    custom_origin_lat: String,
    custom_origin_lon: String,
    toast_msg: Option<(String, Instant)>,
}

impl GlassTraceApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        state: Arc<RwLock<TelemetryState>>,
        osint: Arc<OsintEngine>,
    ) -> Self {
        apply_glass_theme(&cc.egui_ctx);
        let (lat, lon, label) = state
            .read()
            .map(|g| (g.home_lat, g.home_lon, g.home_label.clone()))
            .unwrap_or((39.8, -98.5, "Default Origin (US)".to_string()));
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
            map_view: MapViewState::default(),
            show_origin_window: false,
            custom_origin_label: label,
            custom_origin_lat: format!("{:.4}", lat),
            custom_origin_lon: format!("{:.4}", lon),
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

        let mut toggle_pause = false;
        let mut export_csv = false;
        let mut export_json = false;
        let mut clear_alerts = false;
        let mut new_origin_update: Option<(f32, f32, String)> = None;

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
                        RichText::new("GLASSTRACE")
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

                    // Live status indicator + Pause/Resume
                    let (status_txt, status_col) = if is_paused {
                        ("PAUSED", Color32::from_rgb(245, 158, 11))
                    } else {
                        ("LIVE", Color32::from_rgb(16, 185, 129))
                    };
                    ui.label(RichText::new(status_txt).strong().size(11.5).color(status_col));

                    if ui
                        .button(if is_paused { "Resume" } else { "Pause" })
                        .clicked()
                    {
                        toggle_pause = true;
                    }

                    ui.separator();

                    // KPI pills with crisp vector arrows
                    kpi_arrow_pill(
                        ui,
                        "IN",
                        false,
                        &format_rate(snap.current_rx_bps),
                        Color32::from_rgb(34, 211, 238),
                    );
                    kpi_arrow_pill(
                        ui,
                        "OUT",
                        true,
                        &format_rate(snap.current_tx_bps),
                        Color32::from_rgb(168, 85, 247),
                    );

                    // Session total pill with vector arrows
                    egui::Frame::none()
                        .fill(Color32::from_rgb(15, 23, 38))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(30, 41, 59)))
                        .rounding(5.0)
                        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 3.0;
                                ui.label(
                                    RichText::new("SESSION")
                                        .size(10.0)
                                        .color(Color32::from_rgb(100, 116, 139)),
                                );
                                draw_dir_arrow(ui, false, Color32::from_rgb(34, 211, 238));
                                ui.label(
                                    RichText::new(format_bytes(snap.session_rx_bytes))
                                        .strong()
                                        .monospace()
                                        .size(11.0)
                                        .color(Color32::from_rgb(34, 211, 238)),
                                );
                                ui.add_space(4.0);
                                draw_dir_arrow(ui, true, Color32::from_rgb(168, 85, 247));
                                ui.label(
                                    RichText::new(format_bytes(snap.session_tx_bytes))
                                        .strong()
                                        .monospace()
                                        .size(11.0)
                                        .color(Color32::from_rgb(168, 85, 247)),
                                );
                            });
                        });

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
                        if ui
                            .button(format!("PC Origin: {}", snap.home_label))
                            .on_hover_text("Change your PC's origin location on the world map")
                            .clicked()
                        {
                            self.show_origin_window = !self.show_origin_window;
                            self.custom_origin_label = snap.home_label.clone();
                            self.custom_origin_lat = format!("{:.4}", snap.home_lat);
                            self.custom_origin_lon = format!("{:.4}", snap.home_lon);
                        }
                    });
                });

                // Second compact status line: capture backend badge + interfaces + map reset + toast
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let badge_col = if snap.backend.raw_capture_active {
                        Color32::from_rgb(16, 185, 129)
                    } else {
                        Color32::from_rgb(245, 158, 11)
                    };
                    ui.label(
                        RichText::new(format!("[* ] {}", snap.backend.backend_name))
                            .strong()
                            .size(11.0)
                            .color(badge_col),
                    )
                    .on_hover_text(&snap.backend.elevation_note);

                    ui.label(
                        RichText::new(format!("- {}", snap.backend.elevation_note))
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

        // Floating PC Origin Selector Window
        if self.show_origin_window {
            let mut open = self.show_origin_window;
            egui::Window::new("Set PC Origin Location")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .default_width(360.0)
                .show(ctx, |ui| {
                    ui.label(
                        RichText::new("Choose where your PC is anchored on the world map:")
                            .size(11.5)
                            .color(Color32::from_rgb(203, 213, 225)),
                    );
                    ui.add_space(6.0);

                    ui.horizontal(|ui| {
                        if ui.button("Auto-Detect My PC (GeoIP)").clicked() {
                            let state_clone = Arc::clone(&self.state);
                            thread::spawn(move || {
                                if let Some((lat, lon, label)) = detect_local_geoip() {
                                    if let Ok(mut g) = state_clone.write() {
                                        g.set_home_origin(lat, lon, label);
                                    }
                                }
                            });
                            self.show_toast("Detecting PC location via GeoIP...".to_string());
                        }
                        if ui.button("Pick Directly on Map").clicked() {
                            self.map_view.picking_origin = true;
                            self.show_origin_window = false;
                        }
                    });

                    ui.separator();
                    ui.label(
                        RichText::new("Quick City Presets")
                            .strong()
                            .size(11.0)
                            .color(Color32::from_rgb(148, 163, 184)),
                    );
                    ui.horizontal_wrapped(|ui| {
                        for &(name, lat, lon) in ORIGIN_PRESETS {
                            if ui.small_button(name).clicked() {
                                new_origin_update = Some((lat, lon, name.to_string()));
                                self.custom_origin_label = name.to_string();
                                self.custom_origin_lat = format!("{:.4}", lat);
                                self.custom_origin_lon = format!("{:.4}", lon);
                            }
                        }
                    });

                    ui.separator();
                    ui.label(
                        RichText::new("Custom Coordinates")
                            .strong()
                            .size(11.0)
                            .color(Color32::from_rgb(148, 163, 184)),
                    );
                    egui::Grid::new("origin_custom_grid")
                        .num_columns(2)
                        .spacing([8.0, 4.0])
                        .show(ui, |ui| {
                            ui.label("Label:");
                            ui.text_edit_singleline(&mut self.custom_origin_label);
                            ui.end_row();
                            ui.label("Latitude (-60..84):");
                            ui.text_edit_singleline(&mut self.custom_origin_lat);
                            ui.end_row();
                            ui.label("Longitude (-180..180):");
                            ui.text_edit_singleline(&mut self.custom_origin_lon);
                            ui.end_row();
                        });

                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Apply Custom Origin").clicked() {
                            if let (Ok(lat), Ok(lon)) = (
                                self.custom_origin_lat.trim().parse::<f32>(),
                                self.custom_origin_lon.trim().parse::<f32>(),
                            ) {
                                let lbl = if self.custom_origin_label.trim().is_empty() {
                                    format!("{:.2}, {:.2}", lat, lon)
                                } else {
                                    self.custom_origin_label.trim().to_string()
                                };
                                new_origin_update = Some((lat, lon, lbl));
                            } else {
                                self.show_toast("Invalid latitude or longitude number".to_string());
                            }
                        }
                        if ui.button("Reset Map Zoom").clicked() {
                            self.map_view.reset();
                        }
                    });
                });
            if !open {
                self.show_origin_window = false;
            }
        }

        // Left Sidebar: Per-Application Breakdown
        egui::SidePanel::left("apps_panel")
            .resizable(true)
            .default_width(240.0)
            .min_width(185.0)
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
                let map_h = (total_h * 0.42).clamp(230.0, 390.0);

                ui.allocate_ui(egui::Vec2::new(ui.available_width(), map_h), |ui| {
                    let prev_ip = self.selected_ip.clone();
                    if let Some((lat, lon)) = draw_world_map(
                        ui,
                        &snap.flows,
                        snap.home_lat,
                        snap.home_lon,
                        &snap.home_label,
                        &mut self.selected_ip,
                        &mut self.map_view,
                        self.start_time.elapsed().as_secs_f64(),
                    ) {
                        let lbl = format!("Custom ({:.2}, {:.2})", lat, lon);
                        new_origin_update = Some((lat, lon, lbl));
                    }
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
        if let Some((lat, lon, label)) = new_origin_update {
            if let Ok(mut guard) = self.state.write() {
                guard.set_home_origin(lat, lon, label.clone());
            }
            self.show_toast(format!("PC Origin set to {}", label));
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

fn kpi_arrow_pill(ui: &mut egui::Ui, label: &str, pointing_up: bool, value: &str, color: Color32) {
    egui::Frame::none()
        .fill(Color32::from_rgb(15, 23, 38))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(30, 41, 59)))
        .rounding(5.0)
        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 3.0;
                draw_dir_arrow(ui, pointing_up, color);
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
