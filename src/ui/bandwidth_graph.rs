use crate::types::{format_rate, BandwidthPoint};
use eframe::egui::{self, Color32, Pos2, Stroke, Vec2};

pub fn draw_bandwidth_graph(ui: &mut egui::Ui, history: &[BandwidthPoint]) {
    let available = ui.available_size();
    let height = 132.0;
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(available.x, height), egui::Sense::hover());
    let painter = ui.painter_at(rect);

    // Card background
    painter.rect_filled(rect, 6.0, Color32::from_rgb(12, 18, 30));
    painter.rect_stroke(rect, 6.0, Stroke::new(1.0_f32, Color32::from_rgb(30, 41, 59)));

    if history.len() < 2 {
        return;
    }

    let plot = rect.shrink2(Vec2::new(10.0, 16.0));
    let max_val = history
        .iter()
        .map(|p| p.rx_bps.max(p.tx_bps))
        .max()
        .unwrap_or(1024)
        .max(1024) as f32;
    let y_max = max_val * 1.15;

    // Horizontal grid lines & labels
    let grid_stroke = Stroke::new(0.6_f32, Color32::from_rgba_unmultiplied(51, 65, 85, 85));
    for step in 0..=3 {
        let frac = step as f32 / 3.0;
        let y = plot.bottom() - frac * plot.height();
        painter.line_segment([Pos2::new(plot.left(), y), Pos2::new(plot.right(), y)], grid_stroke);
        if step > 0 {
            let label = format_rate((y_max * frac) as u64);
            painter.text(
                Pos2::new(plot.left() + 2.0, y - 2.0),
                egui::Align2::LEFT_BOTTOM,
                label,
                egui::FontId::proportional(10.0),
                Color32::from_rgb(100, 116, 139),
            );
        }
    }

    let n = history.len();
    let dx = plot.width() / (n - 1) as f32;

    let mut rx_pts = Vec::with_capacity(n);
    let mut tx_pts = Vec::with_capacity(n);

    for (i, pt) in history.iter().enumerate() {
        let x = plot.left() + i as f32 * dx;
        let rx_y = plot.bottom() - ((pt.rx_bps as f32 / y_max).clamp(0.0, 1.0)) * plot.height();
        let tx_y = plot.bottom() - ((pt.tx_bps as f32 / y_max).clamp(0.0, 1.0)) * plot.height();
        rx_pts.push(Pos2::new(x, rx_y));
        tx_pts.push(Pos2::new(x, tx_y));

        // Alert tick marker along the top
        if pt.alerts_in_tick > 0 {
            painter.line_segment(
                [Pos2::new(x, plot.top()), Pos2::new(x, plot.top() + 8.0)],
                Stroke::new(2.0_f32, Color32::from_rgb(239, 68, 68)),
            );
        }
    }

    // Translucent area fills (vertical quads per segment so concave shapes render cleanly)
    let rx_fill = Color32::from_rgba_unmultiplied(34, 211, 238, 36);
    let tx_fill = Color32::from_rgba_unmultiplied(168, 85, 247, 34);
    for i in 0..(n - 1) {
        let a = rx_pts[i];
        let b = rx_pts[i + 1];
        painter.add(egui::Shape::convex_polygon(
            vec![
                a,
                b,
                Pos2::new(b.x, plot.bottom()),
                Pos2::new(a.x, plot.bottom()),
            ],
            rx_fill,
            Stroke::NONE,
        ));

        let c = tx_pts[i];
        let d = tx_pts[i + 1];
        painter.add(egui::Shape::convex_polygon(
            vec![
                c,
                d,
                Pos2::new(d.x, plot.bottom()),
                Pos2::new(c.x, plot.bottom()),
            ],
            tx_fill,
            Stroke::NONE,
        ));
    }

    // Crisp wave strokes
    painter.add(egui::Shape::line(
        rx_pts.clone(),
        Stroke::new(2.0_f32, Color32::from_rgb(34, 211, 238)),
    ));
    painter.add(egui::Shape::line(
        tx_pts.clone(),
        Stroke::new(1.8_f32, Color32::from_rgb(168, 85, 247)),
    ));

    // Title & Legend (top-right)
    painter.text(
        Pos2::new(rect.right() - 10.0, rect.top() + 5.0),
        egui::Align2::RIGHT_TOP,
        "120s Live Throughput  •  Cyan = Incoming (RX)  •  Violet = Outgoing (TX)",
        egui::FontId::proportional(10.5),
        Color32::from_rgb(148, 163, 184),
    );

    // Interactive hover crosshair
    if let Some(pos) = response.hover_pos() {
        if plot.contains(pos) {
            let idx = (((pos.x - plot.left()) / dx).round() as usize).min(n - 1);
            let pt = &history[idx];
            let x = plot.left() + idx as f32 * dx;
            painter.line_segment(
                [Pos2::new(x, plot.top()), Pos2::new(x, plot.bottom())],
                Stroke::new(1.0_f32, Color32::from_rgba_unmultiplied(226, 232, 240, 120)),
            );
            painter.circle_filled(rx_pts[idx], 3.5, Color32::from_rgb(34, 211, 238));
            painter.circle_filled(tx_pts[idx], 3.5, Color32::from_rgb(168, 85, 247));

            egui::show_tooltip_at_pointer(
                ui.ctx(),
                ui.layer_id(),
                egui::Id::new("bw_graph_tip"),
                |ui| {
                    ui.label(format!("Incoming (RX): {}", format_rate(pt.rx_bps)));
                    ui.label(format!("Outgoing (TX): {}", format_rate(pt.tx_bps)));
                    ui.label(format!(
                        "Flows: {} total ({} IN / {} OUT)",
                        pt.active_flows, pt.inbound_flows, pt.outbound_flows
                    ));
                },
            );
        }
    }
}
