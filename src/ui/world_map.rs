use crate::types::{format_rate, Direction, Flow};
use eframe::egui::{self, epaint::Vertex, Color32, Mesh, Pos2, Rect, Stroke, Vec2};

/// Persistent pan/zoom and origin-picking state for the world map.
#[derive(Debug, Clone)]
pub struct MapViewState {
    pub zoom: f32,
    pub pan_x: f32,
    pub pan_y: f32,
    pub picking_origin: bool,
}

impl Default for MapViewState {
    fn default() -> Self {
        Self {
            zoom: 1.0,
            pan_x: 0.0,
            pan_y: 0.0,
            picking_origin: false,
        }
    }
}

impl MapViewState {
    pub fn reset(&mut self) {
        self.zoom = 1.0;
        self.pan_x = 0.0;
        self.pan_y = 0.0;
    }
}

/// Higher-resolution vector landmasses (lon, lat) in degrees, rendered via ear-clipping triangulation
/// so concave bays, gulfs, and peninsulas render cleanly with zero ocean-crossing artifacts.
const LANDMASSES: &[&[(f32, f32)]] = &[
    // North America
    &[
        (-168.0, 65.5), (-162.0, 69.5), (-156.5, 71.3), (-141.0, 69.6), (-128.0, 70.0),
        (-115.0, 68.8), (-96.0, 68.5), (-86.0, 66.0), (-92.0, 62.0), (-94.5, 58.8),
        (-82.5, 55.2), (-79.0, 51.5), (-78.0, 56.5), (-76.5, 62.0), (-65.0, 60.5),
        (-55.5, 52.0), (-61.0, 47.0), (-60.0, 45.5), (-66.5, 44.8), (-70.0, 41.8),
        (-74.0, 40.5), (-75.5, 35.2), (-81.0, 31.0), (-80.1, 25.8), (-81.8, 24.7),
        (-82.7, 28.0), (-85.0, 30.0), (-90.0, 29.2), (-97.2, 26.0), (-97.5, 22.0),
        (-95.0, 18.5), (-90.5, 21.2), (-87.0, 21.3), (-88.2, 15.8), (-83.5, 15.0),
        (-83.0, 10.0), (-78.0, 8.2), (-80.5, 7.5), (-85.5, 10.5), (-92.2, 14.5),
        (-100.0, 16.8), (-105.5, 20.5), (-109.0, 25.5), (-113.5, 31.2), (-110.0, 23.0),
        (-114.5, 28.0), (-117.2, 32.5), (-120.5, 34.5), (-122.5, 37.8), (-124.5, 42.0),
        (-124.7, 48.4), (-130.5, 54.5), (-138.0, 59.5), (-148.0, 60.5), (-154.0, 57.0),
        (-162.0, 55.0), (-166.0, 60.0), (-164.0, 63.0),
    ],
    // Greenland
    &[
        (-52.0, 60.0), (-43.5, 59.8), (-36.0, 65.5), (-22.0, 70.5), (-18.0, 77.0),
        (-20.0, 81.5), (-35.0, 83.2), (-52.0, 82.2), (-68.0, 78.5), (-58.0, 74.0),
        (-53.0, 68.5), (-52.5, 64.0),
    ],
    // Cuba
    &[
        (-84.9, 21.9), (-82.5, 23.1), (-77.5, 21.5), (-74.1, 20.2), (-77.8, 19.9),
        (-81.5, 22.0),
    ],
    // South America
    &[
        (-78.0, 9.0), (-75.5, 10.8), (-71.5, 12.2), (-62.0, 10.5), (-52.0, 4.5),
        (-49.5, 0.5), (-41.5, -2.8), (-34.8, -6.0), (-35.0, -9.5), (-38.5, -13.0),
        (-39.5, -18.5), (-41.0, -23.0), (-48.5, -26.5), (-53.5, -34.0), (-57.5, -38.5),
        (-65.0, -43.0), (-67.5, -49.5), (-68.5, -54.8), (-73.5, -53.5), (-75.0, -46.5),
        (-73.5, -37.0), (-71.5, -30.0), (-70.5, -18.5), (-77.0, -12.0), (-81.2, -4.8),
        (-79.8, 1.5), (-77.5, 5.5),
    ],
    // Iceland
    &[
        (-24.0, 65.5), (-18.0, 66.3), (-13.5, 65.0), (-16.0, 63.6), (-22.5, 63.9),
    ],
    // Great Britain
    &[
        (-5.5, 50.1), (-1.5, 50.8), (1.7, 51.3), (1.7, 52.6), (-0.1, 53.6),
        (-1.6, 55.6), (-2.0, 57.6), (-4.0, 58.6), (-5.8, 57.5), (-5.0, 55.0),
        (-3.2, 53.4), (-5.2, 51.8),
    ],
    // Ireland
    &[
        (-10.2, 51.8), (-8.0, 51.8), (-6.1, 52.3), (-6.0, 54.4), (-7.5, 55.3),
        (-9.8, 54.2), (-10.0, 52.8),
    ],
    // Continental Europe (Iberia -> Scandinavia -> Urals -> Balkans -> Italy -> France)
    &[
        (-9.3, 38.7), (-8.9, 42.9), (-2.0, 43.4), (-4.7, 48.4), (2.0, 51.0),
        (5.5, 53.3), (8.5, 54.0), (8.2, 57.0), (10.6, 57.7), (10.5, 54.5),
        (14.5, 54.0), (19.0, 54.5), (21.5, 56.5), (24.5, 59.5), (29.5, 60.0),
        (22.0, 61.5), (21.5, 64.5), (25.0, 65.8), (18.5, 62.5), (17.5, 59.0),
        (14.0, 55.5), (11.5, 58.5), (8.0, 58.0), (5.0, 60.5), (8.0, 63.5),
        (14.5, 67.5), (20.0, 70.0), (28.0, 71.0), (32.0, 69.5), (41.0, 66.5),
        (44.0, 68.5), (56.0, 68.5), (60.0, 60.0), (50.0, 47.0), (40.0, 45.0),
        (36.0, 45.2), (31.0, 46.5), (28.5, 42.0), (26.0, 40.5), (23.8, 38.0),
        (22.5, 36.5), (20.0, 39.5), (17.5, 43.0), (13.8, 45.6), (12.5, 44.0),
        (16.0, 41.2), (18.5, 40.0), (15.8, 38.0), (13.5, 41.2), (9.0, 44.4),
        (5.0, 43.3), (3.2, 42.3), (0.0, 39.0), (-2.0, 36.7), (-5.5, 36.0),
        (-9.0, 37.0),
    ],
    // Africa
    &[
        (-17.5, 14.7), (-16.5, 21.0), (-13.0, 28.0), (-9.5, 31.5), (-5.8, 35.8),
        (3.0, 36.8), (10.5, 37.2), (11.5, 33.2), (19.5, 32.5), (25.2, 31.6),
        (32.5, 31.2), (34.5, 28.0), (38.0, 21.0), (43.3, 12.6), (51.3, 11.9),
        (48.5, 5.5), (41.0, -2.0), (40.5, -10.5), (40.5, -15.5), (35.5, -20.5),
        (32.8, -26.5), (28.0, -33.0), (20.0, -34.8), (18.4, -34.0), (15.0, -26.5),
        (12.0, -17.0), (13.2, -9.0), (9.0, -1.0), (9.5, 4.0), (3.4, 6.4),
        (-4.0, 5.2), (-7.8, 4.5), (-13.5, 9.0), (-16.5, 12.5),
    ],
    // Madagascar
    &[
        (49.3, -12.0), (50.4, -15.5), (47.0, -25.0), (44.0, -25.2), (43.5, -21.0),
        (46.0, -16.0),
    ],
    // Asia (Anatolia + Arabia + India + SE Asia + China + Siberia)
    &[
        (26.5, 40.0), (36.0, 41.8), (41.5, 41.5), (48.0, 46.5), (53.0, 46.5),
        (60.0, 55.0), (60.0, 68.5), (72.0, 72.5), (85.0, 73.5), (104.0, 77.5),
        (125.0, 73.5), (145.0, 72.0), (170.0, 69.5), (179.0, 66.0), (171.0, 60.5),
        (162.0, 59.5), (156.5, 51.0), (160.0, 56.0), (143.0, 59.0), (136.0, 54.0),
        (140.5, 50.0), (135.5, 44.0), (131.0, 42.8), (129.0, 35.1), (126.5, 35.0),
        (126.0, 39.0), (122.0, 40.5), (118.0, 39.0), (122.0, 37.0), (120.0, 34.0),
        (122.0, 30.5), (119.5, 25.0), (114.0, 22.3), (108.5, 21.5), (109.2, 13.0),
        (105.0, 8.8), (101.0, 13.0), (103.8, 1.3), (100.0, 5.5), (98.5, 10.0),
        (97.5, 16.5), (94.2, 16.0), (92.0, 21.5), (88.0, 21.8), (85.0, 19.5),
        (80.3, 13.0), (77.5, 8.1), (74.5, 14.5), (72.8, 19.0), (68.8, 23.0),
        (66.8, 25.0), (61.5, 25.2), (56.5, 27.0), (49.5, 30.0), (50.5, 26.0),
        (56.3, 26.0), (59.8, 22.5), (54.0, 17.0), (45.0, 12.8), (43.3, 12.7),
        (39.0, 21.5), (34.8, 29.5), (35.5, 33.0), (36.0, 36.8), (30.5, 36.8),
        (27.0, 37.5),
    ],
    // Sri Lanka
    &[
        (80.0, 9.8), (81.8, 7.8), (80.5, 5.9), (79.8, 7.2),
    ],
    // Japan (main archipelago simplified cleanly)
    &[
        (130.0, 31.2), (132.0, 33.0), (136.0, 33.8), (140.5, 35.5), (141.8, 39.5),
        (145.5, 43.3), (142.0, 45.2), (140.0, 42.0), (137.0, 37.5), (131.0, 34.0),
    ],
    // Taiwan
    &[
        (121.5, 25.2), (121.6, 23.0), (120.8, 21.9), (120.1, 23.2),
    ],
    // Philippines (Luzon + Mindanao)
    &[
        (120.5, 18.4), (122.5, 16.5), (124.0, 13.0), (121.0, 13.5), (119.8, 16.0),
    ],
    &[
        (125.5, 9.8), (126.5, 7.0), (124.0, 6.0), (122.0, 7.0), (123.5, 8.8),
    ],
    // Sumatra
    &[
        (95.3, 5.5), (99.5, 3.0), (105.8, -5.8), (104.0, -5.5), (100.0, -1.0),
        (96.0, 3.5),
    ],
    // Java
    &[
        (105.5, -6.2), (114.4, -7.8), (114.0, -8.7), (106.0, -7.2),
    ],
    // Borneo
    &[
        (117.0, 6.8), (119.0, 5.0), (117.5, 1.0), (116.0, -3.8), (111.5, -3.2),
        (109.0, 1.2), (113.5, 3.5),
    ],
    // New Guinea
    &[
        (131.0, -1.0), (136.0, -2.5), (141.0, -2.6), (147.0, -6.5), (150.5, -10.2),
        (146.0, -8.5), (139.0, -8.0), (135.0, -4.5),
    ],
    // Australia
    &[
        (114.0, -22.0), (122.2, -17.5), (129.0, -14.5), (131.0, -12.0), (136.5, -12.2),
        (136.0, -15.5), (141.0, -16.5), (142.5, -10.8), (145.5, -15.5), (150.5, -22.5),
        (153.5, -28.0), (151.2, -34.0), (149.8, -37.5), (145.0, -38.5), (140.5, -38.0),
        (138.0, -35.5), (135.5, -34.8), (131.0, -31.8), (124.0, -33.8), (115.0, -34.3),
        (114.5, -28.0), (113.5, -24.5),
    ],
    // Tasmania
    &[
        (144.8, -40.8), (148.3, -41.0), (147.0, -43.5), (145.2, -42.5),
    ],
    // New Zealand (North & South Island)
    &[
        (173.0, -34.5), (178.5, -37.7), (175.3, -41.5), (174.0, -39.2), (174.5, -36.8),
    ],
    &[
        (173.0, -40.8), (174.2, -41.8), (170.5, -45.8), (167.0, -46.3), (168.5, -44.0),
        (171.5, -42.0),
    ],
];

/// Pre-defined quick origin presets for the PC Origin selector.
pub const ORIGIN_PRESETS: &[(&str, f32, f32)] = &[
    ("New York, US", 40.7128, -74.0060),
    ("San Francisco, US", 37.7749, -122.4194),
    ("London, GB", 51.5074, -0.1278),
    ("Lagos, NG", 6.5244, 3.3792),
    ("Berlin, DE", 52.5200, 13.4050),
    ("Toronto, CA", 43.6532, -79.3832),
    ("Tokyo, JP", 35.6762, 139.6503),
    ("Singapore, SG", 1.3521, 103.8198),
    ("Sydney, AU", -33.8688, 151.2093),
    ("Sao Paulo, BR", -23.5505, -46.6333),
    ("Nairobi, KE", -1.2921, 36.8219),
    ("Dubai, AE", 25.2048, 55.2708),
];

fn project(rect: Rect, view: &MapViewState, lon: f32, lat: f32) -> Pos2 {
    let base_x = ((lon + 180.0) / 360.0) * rect.width();
    let clamped_lat = lat.clamp(-60.0, 84.0);
    let base_y = ((84.0 - clamped_lat) / 144.0) * rect.height();

    let cx = rect.width() * 0.5;
    let cy = rect.height() * 0.5;
    let x = rect.left() + cx + (base_x - cx) * view.zoom + view.pan_x;
    let y = rect.top() + cy + (base_y - cy) * view.zoom + view.pan_y;
    Pos2::new(x, y)
}

fn unproject(rect: Rect, view: &MapViewState, pos: Pos2) -> (f32, f32) {
    let cx = rect.width() * 0.5;
    let cy = rect.height() * 0.5;
    let base_x = ((pos.x - rect.left() - cx - view.pan_x) / view.zoom) + cx;
    let base_y = ((pos.y - rect.top() - cy - view.pan_y) / view.zoom) + cy;

    let lon = ((base_x / rect.width()) * 360.0 - 180.0).clamp(-180.0, 180.0);
    let lat = (84.0 - (base_y / rect.height()) * 144.0).clamp(-60.0, 84.0);
    (lat, lon)
}

/// Ear-clipping triangulation for arbitrary simple concave polygons.
/// Returns a filled egui::Mesh with zero ocean-crossing artifacts.
fn triangulate_polygon(pts: &[Pos2], color: Color32) -> Option<Mesh> {
    if pts.len() < 3 {
        return None;
    }

    // Compute signed area in screen coordinates (Y-down): positive = clockwise, negative = CCW
    let mut signed_area = 0.0f32;
    for i in 0..pts.len() {
        let a = pts[i];
        let b = pts[(i + 1) % pts.len()];
        signed_area += (a.x * b.y) - (b.x * a.y);
    }
    if signed_area.abs() < 1e-4 {
        return None;
    }
    let orientation = if signed_area > 0.0 { 1.0f32 } else { -1.0f32 };

    let mut mesh = Mesh::default();
    for &p in pts {
        mesh.vertices.push(Vertex {
            pos: p,
            uv: egui::epaint::WHITE_UV,
            color,
        });
    }

    let mut indices: Vec<usize> = (0..pts.len()).collect();
    let mut guard = indices.len() * indices.len() + 16;

    while indices.len() > 3 && guard > 0 {
        guard -= 1;
        let n = indices.len();
        let mut ear_found = false;

        for i in 0..n {
            let prev = indices[(i + n - 1) % n];
            let curr = indices[i];
            let next = indices[(i + 1) % n];

            let a = pts[prev];
            let b = pts[curr];
            let c = pts[next];

            // Must be a convex vertex matching polygon winding
            let cross = (b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x);
            if cross * orientation <= 1e-5 {
                continue;
            }

            // Ensure no other polygon vertex lies inside triangle (a, b, c)
            let mut contains_other = false;
            for &other in &indices {
                if other == prev || other == curr || other == next {
                    continue;
                }
                if point_in_triangle(pts[other], a, b, c) {
                    contains_other = true;
                    break;
                }
            }

            if !contains_other {
                mesh.indices.push(prev as u32);
                mesh.indices.push(curr as u32);
                mesh.indices.push(next as u32);
                indices.remove(i);
                ear_found = true;
                break;
            }
        }

        if !ear_found {
            break;
        }
    }

    if indices.len() == 3 {
        mesh.indices.push(indices[0] as u32);
        mesh.indices.push(indices[1] as u32);
        mesh.indices.push(indices[2] as u32);
    }

    if mesh.indices.is_empty() {
        None
    } else {
        Some(mesh)
    }
}

fn point_in_triangle(p: Pos2, a: Pos2, b: Pos2, c: Pos2) -> bool {
    let d1 = sign(p, a, b);
    let d2 = sign(p, b, c);
    let d3 = sign(p, c, a);
    let has_neg = (d1 < 0.0) || (d2 < 0.0) || (d3 < 0.0);
    let has_pos = (d1 > 0.0) || (d2 > 0.0) || (d3 > 0.0);
    !(has_neg && has_pos)
}

#[inline]
fn sign(p1: Pos2, p2: Pos2, p3: Pos2) -> f32 {
    (p1.x - p3.x) * (p2.y - p3.y) - (p2.x - p3.x) * (p1.y - p3.y)
}

/// Returns `Some((lat, lon))` if the user clicked on the map to set a new PC Origin.
#[allow(clippy::too_many_arguments)]
pub fn draw_world_map(
    ui: &mut egui::Ui,
    flows: &[Flow],
    home_lat: f32,
    home_lon: f32,
    home_label: &str,
    selected_ip: &mut Option<String>,
    view: &mut MapViewState,
    time_sec: f64,
) -> Option<(f32, f32)> {
    let available = ui.available_size();
    let height = available.y.max(220.0);
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(available.x, height), egui::Sense::click_and_drag());

    // Handle pan & scroll-wheel zoom
    if response.dragged() {
        let delta = response.drag_delta();
        view.pan_x = (view.pan_x + delta.x).clamp(-rect.width() * 1.5, rect.width() * 1.5);
        view.pan_y = (view.pan_y + delta.y).clamp(-rect.height() * 1.5, rect.height() * 1.5);
    }
    if response.hovered() {
        let scroll = ui.input(|i| i.raw_scroll_delta.y);
        if scroll.abs() > 0.1 {
            let factor = if scroll > 0.0 { 1.15 } else { 1.0 / 1.15 };
            view.zoom = (view.zoom * factor).clamp(1.0, 5.0);
            if view.zoom <= 1.01 {
                view.pan_x = 0.0;
                view.pan_y = 0.0;
            }
        }
    }
    if response.double_clicked() {
        view.reset();
    }

    let painter = ui.painter_at(rect);

    // Deep ocean backdrop
    painter.rect_filled(rect, 6.0_f32, Color32::from_rgb(7, 13, 24));
    painter.rect_stroke(rect, 6.0_f32, Stroke::new(1.0_f32, Color32::from_rgb(30, 41, 59)));

    // Lat/lon graticule grid
    let grid_stroke = Stroke::new(0.6_f32, Color32::from_rgba_unmultiplied(51, 65, 85, 65));
    let axis_stroke = Stroke::new(0.9_f32, Color32::from_rgba_unmultiplied(71, 85, 105, 110));
    for lon in (-150..=150).step_by(30) {
        let p1 = project(rect, view, lon as f32, 84.0);
        let p2 = project(rect, view, lon as f32, -60.0);
        painter.line_segment([p1, p2], if lon == 0 { axis_stroke } else { grid_stroke });
    }
    for lat in (-40..=60).step_by(20) {
        let p1 = project(rect, view, -180.0, lat as f32);
        let p2 = project(rect, view, 180.0, lat as f32);
        painter.line_segment([p1, p2], if lat == 0 { axis_stroke } else { grid_stroke });
    }

    // Draw accurately triangulated continents & islands
    let land_fill = Color32::from_rgb(22, 34, 54);
    let land_stroke = Stroke::new(1.0_f32, Color32::from_rgb(56, 82, 118));
    for poly in LANDMASSES {
        let pts: Vec<Pos2> = poly
            .iter()
            .map(|&(lon, lat)| project(rect, view, lon, lat))
            .collect();
        if let Some(mesh) = triangulate_polygon(&pts, land_fill) {
            painter.add(egui::Shape::mesh(mesh));
        }
        let mut closed = pts;
        if let Some(&first) = closed.first() {
            closed.push(first);
        }
        painter.add(egui::Shape::line(closed, land_stroke));
    }

    let home_pos = project(rect, view, home_lon, home_lat);

    // Draw animated geodesic arcs for geolocated public flows
    let mut hovered_flow: Option<(&Flow, Pos2)> = None;
    let pointer_pos = response.hover_pos();

    let mut seen_coords: Vec<(&Flow, Pos2)> = Vec::new();
    for f in flows {
        if f.osint.is_private
            || f.osint.source == "pending"
            || (f.osint.lat == 0.0 && f.osint.lon == 0.0)
        {
            continue;
        }
        let dst = project(rect, view, f.osint.lon, f.osint.lat);
        seen_coords.push((f, dst));
    }

    for (idx, &(flow, dst)) in seen_coords.iter().enumerate() {
        let is_selected = selected_ip.as_deref() == Some(flow.remote_ip.as_str());
        let is_high_risk = flow.osint.risk_score >= 60;
        let is_inbound = flow.direction == Direction::Inbound;

        let base_color = if is_high_risk {
            Color32::from_rgb(239, 68, 68)
        } else if is_inbound {
            Color32::from_rgb(34, 211, 238)
        } else {
            Color32::from_rgb(168, 85, 247)
        };

        let alpha = if is_selected { 245 } else { 175 };
        let arc_color =
            Color32::from_rgba_unmultiplied(base_color.r(), base_color.g(), base_color.b(), alpha);
        let glow_color =
            Color32::from_rgba_unmultiplied(base_color.r(), base_color.g(), base_color.b(), 42);

        let mid = Pos2::new(
            (home_pos.x + dst.x) * 0.5,
            (home_pos.y + dst.y) * 0.5 - (home_pos.distance(dst) * 0.22).min(95.0),
        );

        let steps = 24;
        let mut pts = Vec::with_capacity(steps + 1);
        for s in 0..=steps {
            let t = s as f32 / steps as f32;
            let inv = 1.0 - t;
            let x = inv * inv * home_pos.x + 2.0 * inv * t * mid.x + t * t * dst.x;
            let y = inv * inv * home_pos.y + 2.0 * inv * t * mid.y + t * t * dst.y;
            pts.push(Pos2::new(x, y));
        }

        // Soft outer glow + crisp core arc
        painter.add(egui::Shape::line(pts.clone(), Stroke::new(4.2_f32, glow_color)));
        let width = if is_selected { 2.4_f32 } else { 1.5_f32 };
        painter.add(egui::Shape::line(pts, Stroke::new(width, arc_color)));

        // Animated packet pulse traveling along arc (outward for OUT, inward for IN)
        let speed = 0.35 + ((flow.rx_bps + flow.tx_bps) as f64 / 500_000.0).min(0.65);
        let raw_t = ((time_sec * speed + (idx as f64) * 0.19) % 1.0) as f32;
        let t = if is_inbound { 1.0 - raw_t } else { raw_t };
        let inv = 1.0 - t;
        let px = inv * inv * home_pos.x + 2.0 * inv * t * mid.x + t * t * dst.x;
        let py = inv * inv * home_pos.y + 2.0 * inv * t * mid.y + t * t * dst.y;
        painter.circle_filled(Pos2::new(px, py), 3.0, Color32::WHITE);
        painter.circle_stroke(Pos2::new(px, py), 4.2, Stroke::new(1.2_f32, base_color));

        // Remote endpoint node
        let node_r = if is_selected {
            6.0
        } else if is_high_risk {
            5.0
        } else {
            4.2
        };
        if is_high_risk || is_selected {
            let pulse = 7.5 + ((time_sec * 3.0 + idx as f64).sin().abs() as f32) * 5.5;
            painter.circle_stroke(
                dst,
                pulse,
                Stroke::new(
                    1.3_f32,
                    Color32::from_rgba_unmultiplied(
                        base_color.r(),
                        base_color.g(),
                        base_color.b(),
                        135,
                    ),
                ),
            );
        }
        painter.circle_filled(dst, node_r, base_color);
        painter.circle_stroke(dst, node_r, Stroke::new(1.0_f32, Color32::WHITE));

        if !view.picking_origin {
            if let Some(p) = pointer_pos {
                if p.distance(dst) < 12.0 {
                    hovered_flow = Some((flow, dst));
                    if response.clicked() {
                        *selected_ip = Some(flow.remote_ip.clone());
                    }
                }
            }
        }
    }

    // Local PC Origin beacon + crisp pill label
    let home_pulse = 6.5 + ((time_sec * 2.2).sin().abs() as f32) * 5.0;
    painter.circle_stroke(
        home_pos,
        home_pulse,
        Stroke::new(1.4_f32, Color32::from_rgba_unmultiplied(16, 185, 129, 150)),
    );
    painter.circle_filled(home_pos, 5.0, Color32::from_rgb(16, 185, 129));
    painter.circle_stroke(home_pos, 5.0, Stroke::new(1.3_f32, Color32::WHITE));

    let tag_galley = painter.layout_no_wrap(
        format!("PC: {}", home_label),
        egui::FontId::proportional(10.5),
        Color32::from_rgb(167, 243, 208),
    );
    let tag_pos = Pos2::new(home_pos.x + 9.0, home_pos.y - tag_galley.size().y * 0.5);
    let tag_rect = Rect::from_min_size(tag_pos - Vec2::new(4.0, 2.0), tag_galley.size() + Vec2::new(8.0, 4.0));
    painter.rect_filled(tag_rect, 3.0_f32, Color32::from_rgba_unmultiplied(7, 13, 24, 210));
    painter.rect_stroke(
        tag_rect,
        3.0_f32,
        Stroke::new(0.8_f32, Color32::from_rgba_unmultiplied(16, 185, 129, 150)),
    );
    painter.galley(tag_pos, tag_galley, Color32::WHITE);

    // Top-left map hint / origin-picking banner
    let hint_text = if view.picking_origin {
        "CLICK ANYWHERE ON MAP TO SET PC ORIGIN (ESC to cancel)"
    } else {
        "Scroll: Zoom  |  Drag: Pan  |  Right-Click: Set PC Origin  |  Double-Click: Reset"
    };
    let hint_col = if view.picking_origin {
        Color32::from_rgb(16, 185, 129)
    } else {
        Color32::from_rgb(100, 116, 139)
    };
    painter.text(
        Pos2::new(rect.left() + 10.0, rect.top() + 8.0),
        egui::Align2::LEFT_TOP,
        hint_text,
        egui::FontId::proportional(10.5),
        hint_col,
    );

    // Legend overlay (bottom-left)
    let legend_pos = Pos2::new(rect.left() + 10.0, rect.bottom() - 22.0);
    let legend_items = [
        (Color32::from_rgb(34, 211, 238), "Inbound (RX)"),
        (Color32::from_rgb(168, 85, 247), "Outbound (TX)"),
        (Color32::from_rgb(239, 68, 68), "High Risk"),
        (Color32::from_rgb(16, 185, 129), "PC Origin"),
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

    // Handle click-to-set PC Origin (either via Origin Picking mode or Right-Click)
    let mut new_origin = None;
    if view.picking_origin {
        ui.ctx().set_cursor_icon(egui::CursorIcon::Crosshair);
        if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
            view.picking_origin = false;
        } else if response.clicked() {
            if let Some(pos) = response.interact_pointer_pos() {
                new_origin = Some(unproject(rect, view, pos));
                view.picking_origin = false;
            }
        }
    } else if response.secondary_clicked() {
        if let Some(pos) = response.interact_pointer_pos() {
            new_origin = Some(unproject(rect, view, pos));
        }
    }

    // Hover tooltip for endpoint
    if let Some((flow, _)) = hovered_flow {
        egui::show_tooltip_at_pointer(
            ui.ctx(),
            ui.layer_id(),
            egui::Id::new("map_endpoint_tip"),
            |ui| {
                ui.strong(format!("{} ({})", flow.remote_ip, flow.osint.country_code));
                ui.label(format!(
                    "{}, {} - {}",
                    flow.osint.city, flow.osint.country, flow.osint.org
                ));
                ui.label(format!(
                    "Process: {} ({}:{})",
                    flow.process_name,
                    flow.protocol.as_str(),
                    flow.remote_port
                ));
                ui.label(format!(
                    "Direction: {}  |  IN: {}  |  OUT: {}",
                    flow.direction.as_str(),
                    format_rate(flow.rx_bps),
                    format_rate(flow.tx_bps)
                ));
                ui.label(format!(
                    "Risk Score: {}/100  (Click to inspect)",
                    flow.osint.risk_score
                ));
            },
        );
    }

    new_origin
}
