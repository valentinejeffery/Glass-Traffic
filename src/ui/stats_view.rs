use crate::stats::{ChartBar, ExportCategory, ExportFormat, StatsStore, Timeframe};
use crate::types::{format_bytes, Direction, Flow};
use crate::ui::panels::{draw_dir_arrow, risk_color};
use eframe::egui::{self, Color32, Pos2, Rect, RichText, Stroke, Vec2};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatsTab {
    DirectionSplit,
    ByCompany,
    ByLocation,
    ByApplication,
    ByBandwidthSize,
}

pub struct StatsUiState {
    pub timeframe: Timeframe,
    pub active_tab: StatsTab,
    pub export_category: ExportCategory,
}

impl Default for StatsUiState {
    fn default() -> Self {
        Self {
            timeframe: Timeframe::Daily,
            active_tab: StatsTab::ByCompany,
            export_category: ExportCategory::ByCompany,
        }
    }
}

/// Returns `Some((category, format))` if the user clicked an export button.
pub fn draw_stats_view(
    ui: &mut egui::Ui,
    stats: &StatsStore,
    flows: &[Flow],
    ui_state: &mut StatsUiState,
) -> Option<(ExportCategory, ExportFormat)> {
    let mut export_req = None;

    let card_bg = ui.visuals().faint_bg_color;
    let card_border = ui.visuals().widgets.noninteractive.bg_stroke.color;

    // Header + Categorized Export Bar
    egui::Frame::none()
        .fill(card_bg)
        .stroke(Stroke::new(1.0_f32, card_border))
        .rounding(6.0_f32)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("STATISTICS & REPORTS")
                        .strong()
                        .size(14.0)
                        .color(Color32::from_rgb(34, 211, 238)),
                );
                ui.separator();

                // Summary metrics
                summary_chip(
                    ui,
                    "ALL-TIME IN",
                    false,
                    &format_bytes(stats.total_rx_bytes),
                    Color32::from_rgb(34, 211, 238),
                );
                summary_chip(
                    ui,
                    "ALL-TIME OUT",
                    true,
                    &format_bytes(stats.total_tx_bytes),
                    Color32::from_rgb(168, 85, 247),
                );
                stat_plain_chip(
                    ui,
                    "COMPANIES",
                    &format!("{}", stats.by_company.len()),
                    Color32::from_rgb(56, 189, 248),
                );
                stat_plain_chip(
                    ui,
                    "COUNTRIES",
                    &format!("{}", stats.by_location.len()),
                    Color32::from_rgb(16, 185, 129),
                );
                stat_plain_chip(
                    ui,
                    "APPS",
                    &format!("{}", stats.by_app.len()),
                    Color32::from_rgb(203, 213, 225),
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Export JSON").clicked() {
                        export_req = Some((ui_state.export_category, ExportFormat::Json));
                    }
                    if ui.button("Export CSV").clicked() {
                        export_req = Some((ui_state.export_category, ExportFormat::Csv));
                    }
                    egui::ComboBox::from_id_salt("export_category_combo")
                        .selected_text(ui_state.export_category.label())
                        .width(170.0)
                        .show_ui(ui, |ui| {
                            for &cat in ExportCategory::ALL {
                                ui.selectable_value(
                                    &mut ui_state.export_category,
                                    cat,
                                    cat.label(),
                                );
                            }
                        });
                    ui.label(
                        RichText::new("Export Category:")
                            .size(11.0)
                            .color(Color32::from_rgb(148, 163, 184)),
                    );
                });
            });
        });

    ui.add_space(10.0);

    // Timeframe Selector + Grouped Bar Chart (Daily / Weekly / Monthly)
    egui::Frame::none()
        .fill(card_bg)
        .stroke(Stroke::new(1.0_f32, card_border))
        .rounding(6.0_f32)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("BANDWIDTH HISTORY CHART")
                        .strong()
                        .size(12.0)
                        .color(Color32::from_rgb(148, 163, 184)),
                );
                ui.separator();
                for tf in [Timeframe::Daily, Timeframe::Weekly, Timeframe::Monthly] {
                    if ui
                        .selectable_label(ui_state.timeframe == tf, tf.label())
                        .clicked()
                    {
                        ui_state.timeframe = tf;
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new("Cyan = Incoming (RX)  |  Violet = Outgoing (TX)")
                            .size(10.5)
                            .color(Color32::from_rgb(148, 163, 184)),
                    );
                });
            });
            ui.add_space(6.0);

            let bars = stats.chart_bars(ui_state.timeframe);
            draw_bar_chart(ui, &bars);
        });

    ui.add_space(10.0);

    // Category Breakdown Tabs
    ui.horizontal_wrapped(|ui| {
        for (label, tab) in [
            ("Inbound vs Outbound", StatsTab::DirectionSplit),
            ("By Company / Org", StatsTab::ByCompany),
            ("By Location / Country", StatsTab::ByLocation),
            ("By Application", StatsTab::ByApplication),
            ("By Bandwidth Size", StatsTab::ByBandwidthSize),
        ] {
            if ui
                .selectable_label(ui_state.active_tab == tab, label)
                .clicked()
            {
                ui_state.active_tab = tab;
            }
        }
    });
    ui.add_space(6.0);

    egui::Frame::none()
        .fill(card_bg)
        .stroke(Stroke::new(1.0_f32, card_border))
        .rounding(6.0_f32)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_min_height(ui.available_height().max(180.0));
            egui::ScrollArea::vertical()
                .id_salt("stats_breakdown_scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| match ui_state.active_tab {
                    StatsTab::DirectionSplit => draw_direction_split(ui, stats, flows),
                    StatsTab::ByCompany => {
                        let rows = stats.sorted_companies();
                        draw_category_table(ui, "COMPANY / ORGANIZATION", &rows);
                    }
                    StatsTab::ByLocation => draw_location_table(ui, stats),
                    StatsTab::ByApplication => {
                        let rows = stats.sorted_apps();
                        draw_category_table(ui, "APPLICATION / PROCESS", &rows);
                    }
                    StatsTab::ByBandwidthSize => draw_bandwidth_tiers(ui, flows),
                });
        });

    export_req
}

fn draw_bar_chart(ui: &mut egui::Ui, bars: &[ChartBar]) {
    let available = ui.available_size();
    let height = 185.0;
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(available.x, height), egui::Sense::hover());
    let painter = ui.painter_at(rect);

    painter.rect_filled(rect, 4.0_f32, ui.visuals().extreme_bg_color);

    if bars.is_empty() {
        return;
    }

    let plot = Rect::from_min_max(
        Pos2::new(rect.left() + 62.0, rect.top() + 10.0),
        Pos2::new(rect.right() - 10.0, rect.bottom() - 24.0),
    );

    let max_val = bars
        .iter()
        .map(|b| b.rx_bytes.max(b.tx_bytes))
        .max()
        .unwrap_or(1024)
        .max(1024) as f32
        * 1.15;

    // Gridlines
    let grid_stroke = Stroke::new(0.6_f32, Color32::from_rgba_unmultiplied(51, 65, 85, 85));
    for step in 0..=3 {
        let frac = step as f32 / 3.0;
        let y = plot.bottom() - frac * plot.height();
        painter.line_segment(
            [Pos2::new(plot.left(), y), Pos2::new(plot.right(), y)],
            grid_stroke,
        );
        painter.text(
            Pos2::new(plot.left() - 6.0, y),
            egui::Align2::RIGHT_CENTER,
            format_bytes((max_val * frac) as u64),
            egui::FontId::proportional(10.0),
            Color32::from_rgb(100, 116, 139),
        );
    }

    let n = bars.len();
    let slot_w = plot.width() / n as f32;
    let bar_w = (slot_w * 0.36).clamp(3.0, 22.0);
    let label_step = if n > 20 { 3 } else if n > 12 { 2 } else { 1 };

    let mut hovered_idx = None;
    let hover_pos = response.hover_pos();

    for (i, bar) in bars.iter().enumerate() {
        let cx = plot.left() + (i as f32 + 0.5) * slot_w;
        let rx_h = ((bar.rx_bytes as f32 / max_val).clamp(0.0, 1.0)) * plot.height();
        let tx_h = ((bar.tx_bytes as f32 / max_val).clamp(0.0, 1.0)) * plot.height();

        let rx_rect = Rect::from_min_max(
            Pos2::new(cx - bar_w - 1.0, plot.bottom() - rx_h.max(1.0)),
            Pos2::new(cx - 1.0, plot.bottom()),
        );
        let tx_rect = Rect::from_min_max(
            Pos2::new(cx + 1.0, plot.bottom() - tx_h.max(1.0)),
            Pos2::new(cx + bar_w + 1.0, plot.bottom()),
        );

        painter.rect_filled(rx_rect, 2.0_f32, Color32::from_rgb(34, 211, 238));
        painter.rect_filled(tx_rect, 2.0_f32, Color32::from_rgb(168, 85, 247));

        if i % label_step == 0 {
            painter.text(
                Pos2::new(cx, plot.bottom() + 4.0),
                egui::Align2::CENTER_TOP,
                &bar.label,
                egui::FontId::proportional(9.5),
                Color32::from_rgb(148, 163, 184),
            );
        }

        if let Some(p) = hover_pos {
            if p.x >= plot.left() + i as f32 * slot_w
                && p.x < plot.left() + (i + 1) as f32 * slot_w
                && p.y >= plot.top()
                && p.y <= plot.bottom()
            {
                hovered_idx = Some(i);
            }
        }
    }

    if let Some(idx) = hovered_idx {
        let b = &bars[idx];
        let x = plot.left() + (idx as f32 + 0.5) * slot_w;
        painter.line_segment(
            [Pos2::new(x, plot.top()), Pos2::new(x, plot.bottom())],
            Stroke::new(1.0_f32, Color32::from_rgba_unmultiplied(226, 232, 240, 100)),
        );
        egui::show_tooltip_at_pointer(
            ui.ctx(),
            ui.layer_id(),
            egui::Id::new("stats_bar_tip"),
            |ui| {
                ui.strong(&b.label);
                ui.label(format!("Incoming (RX): {}", format_bytes(b.rx_bytes)));
                ui.label(format!("Outgoing (TX): {}", format_bytes(b.tx_bytes)));
                ui.label(format!("Total: {}", format_bytes(b.rx_bytes + b.tx_bytes)));
            },
        );
    }
}

fn draw_direction_split(ui: &mut egui::Ui, stats: &StatsStore, flows: &[Flow]) {
    let total = (stats.total_rx_bytes + stats.total_tx_bytes).max(1) as f32;
    let rx_pct = (stats.total_rx_bytes as f32 / total) * 100.0;
    let tx_pct = (stats.total_tx_bytes as f32 / total) * 100.0;

    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!(
                "Incoming (RX): {} ({:.1}%)",
                format_bytes(stats.total_rx_bytes),
                rx_pct
            ))
            .strong()
            .color(Color32::from_rgb(34, 211, 238)),
        );
        ui.add_space(16.0);
        ui.label(
            RichText::new(format!(
                "Outgoing (TX): {} ({:.1}%)",
                format_bytes(stats.total_tx_bytes),
                tx_pct
            ))
            .strong()
            .color(Color32::from_rgb(168, 85, 247)),
        );
    });
    ui.add_space(6.0);

    // Split bar
    let (bar_rect, _) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 16.0), egui::Sense::hover());
    let p = ui.painter();
    p.rect_filled(bar_rect, 4.0_f32, Color32::from_rgb(168, 85, 247));
    let mut rx_rect = bar_rect;
    rx_rect.set_width(bar_rect.width() * (rx_pct / 100.0).clamp(0.0, 1.0));
    p.rect_filled(rx_rect, 4.0_f32, Color32::from_rgb(34, 211, 238));

    ui.add_space(12.0);
    let in_count = flows.iter().filter(|f| f.direction == Direction::Inbound).count();
    let out_count = flows.iter().filter(|f| f.direction == Direction::Outbound).count();
    let listen_count = flows.iter().filter(|f| f.direction == Direction::Listening).count();

    egui::Grid::new("dir_split_grid")
        .num_columns(4)
        .striped(true)
        .spacing([18.0, 6.0])
        .show(ui, |ui| {
            for h in ["DIRECTION", "ACTIVE FLOWS", "RECORDED VOLUME", "SHARE"] {
                ui.label(RichText::new(h).strong().size(11.0).color(Color32::from_rgb(148, 163, 184)));
            }
            ui.end_row();

            ui.label(RichText::new("Inbound (RX)").strong().color(Color32::from_rgb(34, 211, 238)));
            ui.label(format!("{}", in_count));
            ui.label(format_bytes(stats.total_rx_bytes));
            ui.label(format!("{:.1}%", rx_pct));
            ui.end_row();

            ui.label(RichText::new("Outbound (TX)").strong().color(Color32::from_rgb(168, 85, 247)));
            ui.label(format!("{}", out_count));
            ui.label(format_bytes(stats.total_tx_bytes));
            ui.label(format!("{:.1}%", tx_pct));
            ui.end_row();

            ui.label(RichText::new("Listening Ports").strong().color(Color32::from_rgb(16, 185, 129)));
            ui.label(format!("{}", listen_count));
            ui.label("-");
            ui.label("-");
            ui.end_row();
        });
}

fn draw_category_table(
    ui: &mut egui::Ui,
    title: &str,
    rows: &[crate::stats::CategoryStat],
) {
    let max_tot = rows
        .iter()
        .map(|r| r.rx_bytes + r.tx_bytes)
        .max()
        .unwrap_or(1)
        .max(1) as f32;

    egui::Grid::new(format!("cat_grid_{}", title))
        .num_columns(6)
        .striped(true)
        .spacing([14.0, 6.0])
        .show(ui, |ui| {
            for h in [title, "INCOMING (RX)", "OUTGOING (TX)", "TOTAL", "SHARE", "MAX RISK"] {
                ui.label(RichText::new(h).strong().size(11.0).color(Color32::from_rgb(148, 163, 184)));
            }
            ui.end_row();

            for row in rows.iter().take(60) {
                let tot = row.rx_bytes + row.tx_bytes;
                ui.label(RichText::new(&row.name).strong().color(Color32::from_rgb(226, 232, 240)));
                ui.label(RichText::new(format_bytes(row.rx_bytes)).monospace().color(Color32::from_rgb(34, 211, 238)));
                ui.label(RichText::new(format_bytes(row.tx_bytes)).monospace().color(Color32::from_rgb(168, 85, 247)));
                ui.label(RichText::new(format_bytes(tot)).monospace().color(Color32::from_rgb(241, 245, 249)));

                let frac = (tot as f32 / max_tot).clamp(0.03, 1.0);
                let (r, _) = ui.allocate_exact_size(Vec2::new(110.0, 8.0), egui::Sense::hover());
                let p = ui.painter();
                p.rect_filled(r, 2.0_f32, Color32::from_rgb(30, 41, 59));
                let mut fill = r;
                fill.set_width(r.width() * frac);
                p.rect_filled(fill, 2.0_f32, Color32::from_rgb(34, 211, 238));

                ui.label(RichText::new(format!("{}", row.max_risk)).strong().color(risk_color(row.max_risk)));
                ui.end_row();
            }
        });
}

fn draw_location_table(ui: &mut egui::Ui, stats: &StatsStore) {
    let rows = stats.sorted_locations();
    let max_tot = rows
        .iter()
        .map(|r| r.rx_bytes + r.tx_bytes)
        .max()
        .unwrap_or(1)
        .max(1) as f32;

    egui::Grid::new("loc_stats_grid")
        .num_columns(7)
        .striped(true)
        .spacing([14.0, 6.0])
        .show(ui, |ui| {
            for h in ["CODE", "COUNTRY", "INCOMING (RX)", "OUTGOING (TX)", "TOTAL", "SHARE", "MAX RISK"] {
                ui.label(RichText::new(h).strong().size(11.0).color(Color32::from_rgb(148, 163, 184)));
            }
            ui.end_row();

            for row in rows.iter().take(60) {
                let tot = row.rx_bytes + row.tx_bytes;
                ui.label(RichText::new(&row.country_code).monospace().strong().color(Color32::from_rgb(56, 189, 248)));
                ui.label(RichText::new(&row.country).color(Color32::from_rgb(226, 232, 240)));
                ui.label(RichText::new(format_bytes(row.rx_bytes)).monospace().color(Color32::from_rgb(34, 211, 238)));
                ui.label(RichText::new(format_bytes(row.tx_bytes)).monospace().color(Color32::from_rgb(168, 85, 247)));
                ui.label(RichText::new(format_bytes(tot)).monospace().color(Color32::from_rgb(241, 245, 249)));

                let frac = (tot as f32 / max_tot).clamp(0.03, 1.0);
                let (r, _) = ui.allocate_exact_size(Vec2::new(110.0, 8.0), egui::Sense::hover());
                let p = ui.painter();
                p.rect_filled(r, 2.0_f32, Color32::from_rgb(30, 41, 59));
                let mut fill = r;
                fill.set_width(r.width() * frac);
                p.rect_filled(fill, 2.0_f32, Color32::from_rgb(16, 185, 129));

                ui.label(RichText::new(format!("{}", row.max_risk)).strong().color(risk_color(row.max_risk)));
                ui.end_row();
            }
        });
}

fn draw_bandwidth_tiers(ui: &mut egui::Ui, flows: &[Flow]) {
    let tiers = StatsStore::bandwidth_tiers(flows);
    egui::Grid::new("bw_tiers_grid")
        .num_columns(5)
        .striped(true)
        .spacing([18.0, 6.0])
        .show(ui, |ui| {
            for h in ["BANDWIDTH SIZE TIER", "FLOWS", "INCOMING (RX)", "OUTGOING (TX)", "TOTAL"] {
                ui.label(RichText::new(h).strong().size(11.0).color(Color32::from_rgb(148, 163, 184)));
            }
            ui.end_row();

            for t in tiers {
                ui.label(RichText::new(&t.tier).strong().color(Color32::from_rgb(226, 232, 240)));
                ui.label(format!("{}", t.flow_count));
                ui.label(RichText::new(format_bytes(t.rx_bytes)).monospace().color(Color32::from_rgb(34, 211, 238)));
                ui.label(RichText::new(format_bytes(t.tx_bytes)).monospace().color(Color32::from_rgb(168, 85, 247)));
                ui.label(RichText::new(format_bytes(t.rx_bytes + t.tx_bytes)).monospace().color(Color32::from_rgb(241, 245, 249)));
                ui.end_row();
            }
        });
}

fn summary_chip(ui: &mut egui::Ui, label: &str, pointing_up: bool, value: &str, color: Color32) {
    egui::Frame::none()
        .fill(ui.visuals().extreme_bg_color)
        .stroke(Stroke::new(
            1.0_f32,
            ui.visuals().widgets.noninteractive.bg_stroke.color,
        ))
        .rounding(5.0)
        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 3.0;
                draw_dir_arrow(ui, pointing_up, color);
                ui.label(RichText::new(label).size(10.0).color(Color32::from_rgb(100, 116, 139)));
                ui.label(RichText::new(value).strong().monospace().size(11.5).color(color));
            });
        });
}

fn stat_plain_chip(ui: &mut egui::Ui, label: &str, value: &str, color: Color32) {
    egui::Frame::none()
        .fill(ui.visuals().extreme_bg_color)
        .stroke(Stroke::new(
            1.0_f32,
            ui.visuals().widgets.noninteractive.bg_stroke.color,
        ))
        .rounding(5.0)
        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(label).size(10.0).color(Color32::from_rgb(100, 116, 139)));
                ui.label(RichText::new(value).strong().monospace().size(11.5).color(color));
            });
        });
}
