// the communication map (FR-7) three ways:
//   comms.dot  Graphviz, for people who have it
//   comms.mmd  Mermaid, pastes into GitHub, Obsidian and most wikis
//   svg()      drawn by otinv itself and inlined in appendix.html, so the
//              map works offline with nothing installed
//
// the svg layout is deliberately simple: one column per role, left to right
// from the internet to the controllers, which is how operators already
// picture a plant network.

use crate::model::{Role, Run};
use crate::net::cmp_addr;
use crate::util::html;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

/// Map columns, left to right.
const COLUMNS: &[(&str, Option<Role>)] = &[
    ("Internet", None),
    ("IT", Some(Role::ItHost)),
    ("Net services", Some(Role::NetworkService)),
    ("Engineering", Some(Role::EngineeringWorkstation)),
    ("HMI/SCADA", Some(Role::Hmi)),
    ("PLC/RTU", Some(Role::Controller)),
];

fn column(run: &Run, ip: &str) -> usize {
    let role = run.asset(ip).map(|a| a.role);
    COLUMNS.iter().position(|(_, r)| *r == role).unwrap_or(0)
}

fn node_label(run: &Run, ip: &str) -> String {
    match run.asset(ip) {
        Some(a) if !a.name.is_empty() => format!("{} ({})", a.name, a.ip),
        Some(a) => format!("{} {}", a.role.short(), a.ip),
        None => format!("Internet {ip}"),
    }
}

/// Edges merged per (src, dst): protocols joined, connections summed.
fn merged(run: &Run) -> Vec<(String, String, String, u64)> {
    let mut m: BTreeMap<(String, String), (BTreeSet<String>, u64)> = BTreeMap::new();
    for e in &run.edges {
        let v = m.entry((e.src.clone(), e.dst.clone())).or_default();
        v.0.insert(e.protocol.clone());
        v.1 += e.conns;
    }
    m.into_iter()
        .map(|((s, d), (p, n))| (s, d, p.into_iter().collect::<Vec<_>>().join(", "), n))
        .collect()
}

fn nodes(run: &Run) -> Vec<String> {
    let mut set: BTreeSet<String> = run.assets.iter().map(|a| a.ip.clone()).collect();
    for e in &run.edges {
        set.insert(e.src.clone());
        set.insert(e.dst.clone());
    }
    let mut v: Vec<String> = set.into_iter().collect();
    v.sort_by(|a, b| cmp_addr(a, b));
    v
}

fn quote(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn dot(run: &Run) -> String {
    let ids: BTreeMap<String, usize> = nodes(run)
        .into_iter()
        .enumerate()
        .map(|(i, n)| (n, i))
        .collect();
    let mut o = String::from(
        "// SENSITIVE: critical infrastructure information\n\
         // render with: dot -Tsvg comms.dot -o comms.svg\n\
         digraph comms {\n  rankdir=LR;\n  node [shape=box, fontname=\"Helvetica\"];\n",
    );
    for (ci, (name, _)) in COLUMNS.iter().enumerate() {
        let members: Vec<&String> = ids.keys().filter(|ip| column(run, ip) == ci).collect();
        if members.is_empty() {
            continue;
        }
        let _ = writeln!(
            o,
            "  subgraph cluster_{ci} {{\n    label=\"{}\";",
            quote(name)
        );
        for ip in members {
            let _ = writeln!(
                o,
                "    n{} [label=\"{}\"];",
                ids[ip],
                quote(&node_label(run, ip))
            );
        }
        o.push_str("  }\n");
    }
    for (s, d, p, n) in merged(run) {
        let _ = writeln!(
            o,
            "  n{} -> n{} [label=\"{} ({n})\"];",
            ids[&s],
            ids[&d],
            quote(&p)
        );
    }
    o.push_str("}\n");
    o
}

pub fn mermaid(run: &Run) -> String {
    let ids: BTreeMap<String, usize> = nodes(run)
        .into_iter()
        .enumerate()
        .map(|(i, n)| (n, i))
        .collect();
    // mermaid labels can't hold quotes or pipes
    let clean = |s: &str| s.replace(['"', '|'], "'");
    let mut o = String::from("%% SENSITIVE: critical infrastructure information\nflowchart LR\n");
    for (ci, (name, _)) in COLUMNS.iter().enumerate() {
        let members: Vec<&String> = ids.keys().filter(|ip| column(run, ip) == ci).collect();
        if members.is_empty() {
            continue;
        }
        let _ = writeln!(o, "  subgraph c{ci}[\"{}\"]", clean(name));
        for ip in members {
            let _ = writeln!(o, "    n{}[\"{}\"]", ids[ip], clean(&node_label(run, ip)));
        }
        o.push_str("  end\n");
    }
    for (s, d, p, n) in merged(run) {
        let _ = writeln!(o, "  n{} -->|\"{} x{n}\"| n{}", ids[&s], clean(&p), ids[&d]);
    }
    o
}

const BOX_W: f64 = 170.0;
const BOX_H: f64 = 38.0;
const COL_GAP: f64 = 90.0;
const ROW_GAP: f64 = 16.0;
const TOP: f64 = 40.0;

/// Inline SVG for the HTML appendix. Colors come from CSS variables so it
/// follows the page's light/dark theme.
pub fn svg(run: &Run) -> String {
    let all = nodes(run);
    let used: Vec<usize> = (0..COLUMNS.len())
        .filter(|ci| all.iter().any(|ip| column(run, ip) == *ci))
        .collect();
    if used.is_empty() {
        return String::new();
    }
    let mut pos: BTreeMap<String, (f64, f64)> = BTreeMap::new();
    let mut rows = 0usize;
    for (slot, ci) in used.iter().enumerate() {
        let x = 10.0 + slot as f64 * (BOX_W + COL_GAP);
        let members: Vec<&String> = all.iter().filter(|ip| column(run, ip) == *ci).collect();
        rows = rows.max(members.len());
        for (r, ip) in members.into_iter().enumerate() {
            pos.insert(ip.clone(), (x, TOP + r as f64 * (BOX_H + ROW_GAP)));
        }
    }
    let width = 20.0 + used.len() as f64 * BOX_W + (used.len() - 1) as f64 * COL_GAP;
    let height = TOP + rows as f64 * (BOX_H + ROW_GAP) + 10.0;
    let flagged: BTreeSet<&str> = run.findings.iter().map(|f| f.host.as_str()).collect();

    let mut o = String::new();
    let _ = write!(
        o,
        "<svg class=\"map\" viewBox=\"0 0 {width:.0} {height:.0}\" role=\"img\" \
         aria-label=\"Communication map\" xmlns=\"http://www.w3.org/2000/svg\">"
    );
    o.push_str(
        "<defs><marker id=\"arrow\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"6\" \
         markerHeight=\"6\" orient=\"auto-start-reverse\"><path d=\"M0,0 L10,5 L0,10 z\" \
         class=\"arrowhead\"/></marker></defs>",
    );
    for (slot, ci) in used.iter().enumerate() {
        let x = 10.0 + slot as f64 * (BOX_W + COL_GAP) + BOX_W / 2.0;
        let _ = write!(
            o,
            "<text class=\"colhead\" x=\"{x:.0}\" y=\"22\" text-anchor=\"middle\">{}</text>",
            html(COLUMNS[*ci].0)
        );
    }
    for (s, d, p, n) in merged(run) {
        let (Some(&(sx, sy)), Some(&(dx, dy))) = (pos.get(&s), pos.get(&d)) else {
            continue;
        };
        let (x1, x2) = if dx >= sx {
            (sx + BOX_W, dx)
        } else {
            (sx, dx + BOX_W)
        };
        let (y1, y2) = (sy + BOX_H / 2.0, dy + BOX_H / 2.0);
        let mid = (x1 + x2) / 2.0;
        let w = 1.0 + (n as f64).log10().max(0.0);
        let _ = write!(
            o,
            "<path class=\"edge\" d=\"M{x1:.0},{y1:.0} C{mid:.0},{y1:.0} {mid:.0},{y2:.0} {x2:.0},{y2:.0}\" \
             stroke-width=\"{w:.1}\" marker-end=\"url(#arrow)\"><title>{} \u{2192} {}: {} ({n})</title></path>",
            html(&s),
            html(&d),
            html(&p)
        );
    }
    for (ip, (x, y)) in &pos {
        let class = if flagged.contains(ip.as_str()) {
            "node flagged"
        } else {
            "node"
        };
        let label = node_label(run, ip);
        let shown: String = if label.chars().count() > 26 {
            label.chars().take(25).chain(['\u{2026}']).collect()
        } else {
            label.clone()
        };
        let _ = write!(
            o,
            "<g class=\"{class}\"><title>{}</title><rect x=\"{x:.0}\" y=\"{y:.0}\" width=\"{BOX_W:.0}\" \
             height=\"{BOX_H:.0}\" rx=\"6\"/><text x=\"{:.0}\" y=\"{:.0}\" text-anchor=\"middle\">{}</text></g>",
            html(&label),
            x + BOX_W / 2.0,
            y + BOX_H / 2.0 + 4.0,
            html(&shown)
        );
    }
    o.push_str("</svg>");
    o
}
