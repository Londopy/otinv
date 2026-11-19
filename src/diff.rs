// what changed between two runs (FR-12, FR-17): "since last month".

use crate::model::{Asset, Edge, Finding, Run};
use crate::net::cmp_addr;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default)]
pub struct Change {
    pub ip: String,
    /// "MAC 00:..:01 -> 00:..:02", "firmware 20.11 -> 33.11"
    pub what: Vec<String>,
}

#[derive(Debug, Default)]
pub struct RunDiff {
    pub new_assets: Vec<Asset>,
    pub gone_assets: Vec<Asset>,
    pub changed: Vec<Change>,
    pub new_edges: Vec<Edge>,
    pub gone_edges: Vec<Edge>,
    pub new_findings: Vec<Finding>,
    pub resolved_findings: Vec<Finding>,
}

impl RunDiff {
    pub fn is_empty(&self) -> bool {
        self.new_assets.is_empty()
            && self.gone_assets.is_empty()
            && self.changed.is_empty()
            && self.new_edges.is_empty()
            && self.gone_edges.is_empty()
            && self.new_findings.is_empty()
            && self.resolved_findings.is_empty()
    }
}

fn opt(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("none")
}

pub fn diff(old: &Run, new: &Run) -> RunDiff {
    let old_assets: BTreeMap<&str, &Asset> =
        old.assets.iter().map(|a| (a.ip.as_str(), a)).collect();
    let new_assets: BTreeMap<&str, &Asset> =
        new.assets.iter().map(|a| (a.ip.as_str(), a)).collect();
    let mut d = RunDiff::default();

    for (ip, a) in &new_assets {
        match old_assets.get(ip) {
            None => d.new_assets.push((*a).clone()),
            Some(o) => {
                let mut what = Vec::new();
                if o.mac.is_some() && a.mac.is_some() && o.mac != a.mac {
                    what.push(format!(
                        "MAC changed {} -> {} (a different device may now use this address)",
                        opt(&o.mac),
                        opt(&a.mac)
                    ));
                }
                if o.role != a.role {
                    what.push(format!(
                        "role changed {} -> {}",
                        o.role.label(),
                        a.role.label()
                    ));
                }
                let keys: BTreeSet<&String> = o.identity.keys().chain(a.identity.keys()).collect();
                for k in keys {
                    let (x, y) = (o.identity.get(k), a.identity.get(k));
                    if x.is_some() && y.is_some() && x != y {
                        what.push(format!(
                            "{k} changed {} -> {}",
                            x.map_or("", |s| s.as_str()),
                            y.map_or("", |s| s.as_str())
                        ));
                    }
                }
                for s in a.serves.difference(&o.serves) {
                    what.push(format!("now answers {s}"));
                }
                if !what.is_empty() {
                    d.changed.push(Change {
                        ip: ip.to_string(),
                        what,
                    });
                }
            }
        }
    }
    for (ip, a) in &old_assets {
        if !new_assets.contains_key(ip) {
            d.gone_assets.push((*a).clone());
        }
    }

    let key = |e: &Edge| (e.src.clone(), e.dst.clone(), e.protocol.clone());
    let old_edges: BTreeSet<_> = old.edges.iter().map(key).collect();
    let new_edges: BTreeSet<_> = new.edges.iter().map(key).collect();
    d.new_edges = new
        .edges
        .iter()
        .filter(|e| !old_edges.contains(&key(e)))
        .cloned()
        .collect();
    d.gone_edges = old
        .edges
        .iter()
        .filter(|e| !new_edges.contains(&key(e)))
        .cloned()
        .collect();

    let old_f: BTreeSet<&str> = old.findings.iter().map(|f| f.key.as_str()).collect();
    let new_f: BTreeSet<&str> = new.findings.iter().map(|f| f.key.as_str()).collect();
    d.new_findings = new
        .findings
        .iter()
        .filter(|f| !old_f.contains(f.key.as_str()))
        .cloned()
        .collect();
    // "new device" can't be resolved by the next run; it just stops being new
    d.resolved_findings = old
        .findings
        .iter()
        .filter(|f| !new_f.contains(f.key.as_str()) && f.check != crate::config::Check::NewDevice)
        .cloned()
        .collect();

    d.new_assets.sort_by(|a, b| cmp_addr(&a.ip, &b.ip));
    d.gone_assets.sort_by(|a, b| cmp_addr(&a.ip, &b.ip));
    d.changed.sort_by(|a, b| cmp_addr(&a.ip, &b.ip));
    d
}
