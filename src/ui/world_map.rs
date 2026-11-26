use crate::types::{format_rate, Direction, Flow};
use eframe::egui::{self, Color32, Pos2, Rect, Stroke, Vec2};

/// Simplified world continent polygons (lon, lat) in degrees for zero-dependency native vector map rendering.
const CONTINENTS: &[&[(f32, f32)]] = &[
    // North America
    &[
        (-168.0, 65.0), (-156.0, 71.0), (-136.0, 69.0), (-118.0, 69.0), (-95.0, 68.0),
        (-82.0, 64.0), (-64.0, 60.0), (-55.0, 52.0), (-60.0, 45.0), (-70.0, 42.0),
        (-76.0, 35.0), (-81.0, 25.0), (-84.0, 30.0), (-97.0, 26.0), (-96.0, 19.0),
        (-87.0, 21.0), (-83.0, 10.0), (-78.0, 8.0), (-85.0, 11.0), (-93.0, 15.0),
        (-105.0, 20.0), (-112.0, 31.0), (-117.0, 32.0), (-124.0, 42.0), (-125.0, 49.0),
        (-136.0, 58.0), (-150.0, 60.0), (-164.0, 55.0), (-168.0, 65.0),
    ],
    // Greenland
    &[
        (-52.0, 60.0), (-42.0, 60.0), (-22.0, 70.0), (-18.0, 81.0), (-45.0, 83.0),
        (-68.0, 76.0), (-54.0, 68.0), (-52.0, 60.0),
    ],
    // South America
    &[
        (-78.0, 9.0), (-72.0, 12.0), (-61.0, 10.0), (-50.0, 1.0), (-35.0, -6.0),
        (-38.0, -14.0), (-41.0, -23.0), (-53.0, -34.0), (-65.0, -43.0), (-68.0, -54.0),
        (-74.0, -52.0), (-73.0, -38.0), (-71.0, -18.0), (-81.0, -5.0), (-78.0, 9.0),
    ],
    // Europe
    &[
        (-9.0, 37.0), (-9.0, 43.0), (-2.0, 43.0), (-5.0, 48.0), (2.0, 51.0),
        (9.0, 54.0), (10.0, 58.0), (5.0, 62.0), (16.0, 69.0), (30.0, 70.0),
        (42.0, 66.0), (52.0, 68.0), (60.0, 60.0), (48.0, 46.0), (38.0, 45.0),
        (28.0, 41.0), (23.0, 37.0), (15.0, 38.0), (12.0, 44.0), (5.0, 43.0),
        (-5.0, 36.0), (-9.0, 37.0),
    ],
    // United Kingdom
    &[
        (-6.0, 50.0), (1.5, 51.0), (-1.5, 55.5), (-5.0, 58.5), (-6.0, 54.0), (-6.0, 50.0),
    ],
    // Africa
    &[
        (-17.0, 15.0), (-13.0, 28.0), (-6.0, 36.0), (10.0, 37.0), (25.0, 32.0),
        (33.0, 31.0), (43.0, 12.0), (51.0, 12.0), (41.0, -2.0), (40.0, -15.0),
        (33.0, -26.0), (20.0, -35.0), (15.0, -26.0), (12.0, -12.0), (9.0, 4.0),
        (-8.0, 5.0), (-17.0, 15.0),
    ],
    // Asia
    &[
        (28.0, 41.0), (36.0, 37.0), (43.0, 30.0), (48.0, 29.0), (59.0, 22.0),
        (52.0, 15.0), (43.0, 13.0), (35.0, 28.0), (60.0, 25.0), (68.0, 23.0),
        (77.0, 8.0), (88.0, 22.0), (98.0, 16.0), (103.0, 1.5), (109.0, 12.0),
        (108.0, 21.0), (121.0, 24.0), (122.0, 31.0), (118.0, 39.0), (126.0, 35.0),
        (131.0, 43.0), (141.0, 53.0), (160.0, 60.0), (178.0, 66.0), (165.0, 70.0),
        (135.0, 72.0), (104.0, 77.0), (72.0, 72.0), (60.0, 68.0), (60.0, 55.0),
        (48.0, 46.0), (28.0, 41.0),
    ],
    // Japan
    &[
        (130.0, 31.0), (136.0, 34.0), (141.0, 36.0), (145.0, 43.5), (140.0, 42.0),
        (136.0, 37.0), (130.0, 33.5), (130.0, 31.0),
    ],
    // Australia
    &[
        (114.0, -22.0), (123.0, -16.0), (136.0, -12.0), (143.0, -11.0), (153.0, -26.0),
        (150.0, -37.0), (140.0, -38.0), (130.0, -32.0), (115.0, -34.0), (114.0, -22.0),
    ],
    // New Zealand
    &[
        (167.0, -46.0), (174.0, -41.0), (178.0, -37.0), (173.0, -35.0), (167.0, -46.0),
    ],
];

fn project(rect: Rect, lon: f32, lat: f32) -> Pos2 {
    let x = rect.left() + ((lon + 180.0) / 360.0) * rect.width();
    // Clamp latitude to [-62, 84] for balanced visual framing
    let clamped_lat = lat.clamp(-62.0, 84.0);
    let y = rect.top() + ((84.0 - clamped_lat) / 146.0) * rect.height();
    Pos2::new(x, y)
}

pub fn draw_world_map(
    ui: &mut egui::Ui,
    flows: &[Flow],
    home_lat: f32,
    home_lon: f32,
    selected_ip: &mut Option<String>,
    time_sec: f64,
) {
    let available = ui.available_size();
    let height = available.y.max(210.0);
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(available.x, height), egui::Sense::click_and_drag());
    let painter = ui.painter_at(rect);

    // Deep ocean backdrop
    painter.rect_filled(rect, 6.0, Color32::from_rgb(9, 14, 24));
    painter.rect_stroke(rect, 6.0, Stroke::new(1.0_f32, Color32::from_rgb(30, 41, 59)));

    // Subtle lat/lon graticule grid
    let grid_stroke = Stroke::new(0.6_f32, Color32::from_rgba_unmultiplied(51, 65, 85, 70));
    for lon in (-150..=150).step_by(30) {
        let p1 = project(rect, lon as f32, 84.0);
        let p2 = project(rect, lon as f32, -62.0);
        painter.line_segment([p1, p2], grid_stroke);
    }
    for lat in (-40..=60).step_by(20) {
        let p1 = project(rect, -180.0, lat as f32);
        let p2 = project(rect, 180.0, lat as f32);
        painter.line_segment([p1, p2], grid_stroke);
    }

    // Draw continents
    let land_fill = Color32::from_rgb(20, 30, 48);
    let land_stroke = Stroke::new(1.0_f32, Color32::from_rgb(45, 64, 92));
    for poly in CONTINENTS {
        let pts: Vec<Pos2> = poly
            .iter()
            .map(|&(lon, lat)| project(rect, lon, lat))
            .collect();
        painter.add(egui::Shape::convex_polygon(
            pts.clone(),
            land_fill,
            Stroke::NONE,
        ));
        // Polyline outline for crisp coasts
        painter.add(egui::Shape::line(pts, land_stroke));
    }

    let home_pos = project(rect, home_lon, home_lat);

    // Draw animated arcs for all geolocated public flows
    let mut hovered_flow: Option<(&Flow, Pos2)> = None;
    let pointer_pos = response.hover_pos();

    // Deduplicate remote IPs for cleaner arcs while keeping highest-risk / highest-rate flow
    let mut seen_coords: Vec<(&Flow, Pos2)> = Vec::new();
    for f in flows {
        if f.osint.is_private
            || f.osint.source == "pending"
            || (f.osint.lat == 0.0 && f.osint.lon == 0.0)
        {
            continue;
        }
        let dst = project(rect, f.osint.lon, f.osint.lat);
        seen_coords.push((f, dst));
    }

    for (idx, &(flow, dst)) in seen_coords.iter().enumerate() {
        let is_selected = selected_ip.as_deref() == Some(flow.remote_ip.as_str());
        let is_high_risk = flow.osint.risk_score >= 60;
        let is_inbound = flow.direction == Direction::Inbound;

        let base_color = if is_high_risk {
            Color32::from_rgb(239, 68, 68) // Crimson
        } else if is_inbound {
            Color32::from_rgb(34, 211, 238) // Electric Cyan (Incoming)
        } else {
            Color32::from_rgb(168, 85, 247) // Neon Violet (Outgoing)
        };

        let alpha = if is_selected { 245 } else { 155 };
        let arc_color =
            Color32::from_rgba_unmultiplied(base_color.r(), base_color.g(), base_color.b(), alpha);

        // Quadratic Bezier curve elevated north for great-circle look
        let mid = Pos2::new(
            (home_pos.x + dst.x) * 0.5,
            (home_pos.y + dst.y) * 0.5 - (home_pos.distance(dst) * 0.22).min(90.0),
        );

        let steps = 20;
        let mut pts = Vec::with_capacity(steps + 1);
        for s in 0..=steps {
            let t = s as f32 / steps as f32;
            let inv = 1.0 - t;
            let x = inv * inv * home_pos.x + 2.0 * inv * t * mid.x + t * t * dst.x;
            let y = inv * inv * home_pos.y + 2.0 * inv * t * mid.y + t * t * dst.y;
            pts.push(Pos2::new(x, y));
        }

        let width = if is_selected { 2.4 } else { 1.35_f32 };
        painter.add(egui::Shape::line(pts, Stroke::new(width, arc_color)));

        // Animated packet pulse traveling along the arc (outward for OUT, inward for IN)
        let speed = 0.35 + ((flow.rx_bps + flow.tx_bps) as f64 / 500_000.0).min(0.65);
        let raw_t = ((time_sec * speed + (idx as f64) * 0.19) % 1.0) as f32;
        let t = if is_inbound { 1.0 - raw_t } else { raw_t };
        let inv = 1.0 - t;
        let px = inv * inv * home_pos.x + 2.0 * inv * t * mid.x + t * t * dst.x;
        let py = inv * inv * home_pos.y + 2.0 * inv * t * mid.y + t * t * dst.y;
        painter.circle_filled(Pos2::new(px, py), 2.8, base_color);

        // Remote endpoint node + subtle pulse ring for high-risk or selected
        let node_r = if is_selected {
            6.0
        } else if is_high_risk {
            5.0
        } else {
            4.0
        };
        if is_high_risk || is_selected {
            let pulse = 7.0 + ((time_sec * 3.0 + idx as f64).sin().abs() as f32) * 5.0;
            painter.circle_stroke(
                dst,
                pulse,
                Stroke::new(
                    1.2_f32,
                    Color32::from_rgba_unmultiplied(
                        base_color.r(),
                        base_color.g(),
                        base_color.b(),
                        120,
                    ),
                ),
            );
        }
        painter.circle_filled(dst, node_r, base_color);
        painter.circle_stroke(dst, node_r, Stroke::new(1.0_f32, Color32::WHITE));

        if let Some(p) = pointer_pos {
            if p.distance(dst) < 12.0 {
                hovered_flow = Some((flow, dst));
                if response.clicked() {
                    *selected_ip = Some(flow.remote_ip.clone());
                }
            }
        }
    }

    // Home anchor beacon
    let home_pulse = 6.0 + ((time_sec * 2.2).sin().abs() as f32) * 4.5;
    painter.circle_stroke(
        home_pos,
        home_pulse,
        Stroke::new(1.2_f32, Color32::from_rgba_unmultiplied(16, 185, 129, 140)),
    );
    painter.circle_filled(home_pos, 4.5, Color32::from_rgb(16, 185, 129));
    painter.circle_stroke(home_pos, 4.5, Stroke::new(1.2_f32, Color32::WHITE));

    // Legend overlay (bottom-left)
    let legend_pos = Pos2::new(rect.left() + 10.0, rect.bottom() - 22.0);
    let legend_items = [
        (Color32::from_rgb(34, 211, 238), "Inbound (RX)"),
        (Color32::from_rgb(168, 85, 247), "Outbound (TX)"),
        (Color32::from_rgb(239, 68, 68), "High Risk"),
        (Color32::from_rgb(16, 185, 129), "Local Host"),
    ];
    let mut lx = legend_pos.x;
    for (col, label) in legend_items {
        painter.circle_filled(Pos2::new(lx + 4.0, legend_pos.y + 6.0), 3.5, col);
        let galley = painter.layout_no_wrap(
            label.to_string(),
            egui::FontId::proportional(11.0),
            Color32::from_rgb(148, 163, 184),
        );
        let w = galley.size().x;
        painter.galley(Pos2::new(lx + 11.0, legend_pos.y), galley, Color32::WHITE);
        lx += w + 24.0;
    }

    // Hover tooltip for endpoint
    if let Some((flow, _)) = hovered_flow {
        egui::show_tooltip_at_pointer(
            ui.ctx(),
            ui.layer_id(),
            egui::Id::new("map_endpoint_tip"),
            |ui| {
                ui.strong(format!(
                    "{} ({})",
                    flow.remote_ip, flow.osint.country_code
                ));
                ui.label(format!(
                    "{}, {} — {}",
                    flow.osint.city, flow.osint.country, flow.osint.org
                ));
                ui.label(format!(
                    "Process: {} ({}:{})",
                    flow.process_name,
                    flow.protocol.as_str(),
                    flow.remote_port
                ));
                ui.label(format!(
                    "Direction: {}  |  RX: {}  |  TX: {}",
                    flow.direction.as_str(),
                    format_rate(flow.rx_bps),
                    format_rate(flow.tx_bps)
                ));
                ui.label(format!("Risk Score: {}/100  (Click to inspect)", flow.osint.risk_score));
            },
        );
    }
}
