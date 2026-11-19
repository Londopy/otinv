// pseudonymization for sharing (NFR-4). every address, MAC, host name,
// friendly name and serial number is swapped for a stable alias: local
// devices become host-01, host-02..., internet addresses ext-01...
// make, model, firmware and roles stay, because that's what a reviewer needs.
//
// one Map covers several runs, so a pseudonymized diff stays consistent.

use crate::model::{Evidence, Run};
use crate::net::{cmp_addr, is_local, parse_ip};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, Clone)]
pub struct Map {
    table: BTreeMap<String, String>,
}

impl Map {
    /// A fresh map for these runs.
    pub fn build(runs: &[&Run]) -> Self {
        Self::extend(&Map::default(), runs)
    }

    /// `previous` plus aliases for anything new in these runs. Existing
    /// aliases never change; new ones take the next free number.
    pub fn extend(previous: &Map, runs: &[&Run]) -> Self {
        let mut local: BTreeSet<String> = BTreeSet::new();
        let mut public: BTreeSet<String> = BTreeSet::new();
        let mut macs: BTreeSet<String> = BTreeSet::new();
        let mut names: BTreeSet<String> = BTreeSet::new();
        let mut serials: BTreeSet<String> = BTreeSet::new();
        for run in runs {
            for a in &run.assets {
                local.insert(a.ip.clone());
                macs.extend(a.mac.clone());
                names.extend(a.hostnames.iter().cloned());
                if !a.name.is_empty() {
                    names.insert(a.name.clone());
                }
                serials.extend(a.identity.get("serial").cloned());
            }
            for e in &run.externals {
                public.insert(e.ip.clone());
            }
            for s in &run.shared_macs {
                macs.insert(s.mac.clone());
                local.extend(s.ips.iter().cloned());
            }
            // anything else that shows up in edges, findings or evidence,
            // like an internet address a controller tried and failed to reach
            let mut seen: Vec<&String> = Vec::new();
            for e in &run.edges {
                seen.extend([&e.src, &e.dst]);
            }
            for f in &run.findings {
                seen.push(&f.host);
                seen.extend(f.peers.iter());
                for e in &f.evidence {
                    seen.extend(e.src.iter().chain(e.dst.iter()));
                }
            }
            for a in &run.assets {
                for r in &a.reasons {
                    seen.extend(r.peer.iter());
                    seen.extend(r.evidence.src.iter().chain(r.evidence.dst.iter()));
                }
                let e = &a.first_evidence;
                seen.extend(e.src.iter().chain(e.dst.iter()));
            }
            for ip in seen {
                if local.contains(ip) || public.contains(ip) {
                    continue;
                }
                match parse_ip(ip) {
                    Some(addr) if is_local(&addr, &[]) => local.insert(ip.clone()),
                    Some(_) => public.insert(ip.clone()),
                    None => false,
                };
            }
        }
        // values the previous map already covers keep their alias, so the
        // same device is host-03 in October's share and in November's
        let mut table = previous.table.clone();
        // an alias must never equal a real value (a device really named
        // "host-01" would otherwise be indistinguishable from an alias)
        let reals: BTreeSet<String> = local
            .iter()
            .chain(&public)
            .chain(&macs)
            .chain(&names)
            .chain(&serials)
            .chain(table.keys())
            .cloned()
            .collect();
        let mut used: BTreeSet<String> = table.values().cloned().collect();
        let mut assign = |set: BTreeSet<String>, prefix: &str, numeric: bool| {
            let mut v: Vec<String> = set.into_iter().filter(|r| !table.contains_key(r)).collect();
            if numeric {
                v.sort_by(|a, b| cmp_addr(a, b));
            }
            let mut n = 1usize;
            for real in v {
                let alias = loop {
                    let candidate = format!("{prefix}-{n:02}");
                    n += 1;
                    if !used.contains(&candidate) && !reals.contains(&candidate) {
                        break candidate;
                    }
                };
                used.insert(alias.clone());
                table.insert(real, alias);
            }
        };
        assign(local, "host", true);
        assign(public, "ext", true);
        assign(macs, "mac", false);
        assign(names, "name", false);
        assign(serials, "serial", false);
        Self { table }
    }

    /// The private mapping file: `real,alias` rows after a warning comment.
    pub fn to_csv(&self) -> String {
        let mut body = String::from(
            "# SENSITIVE: this file undoes the pseudonymization. Never share it with the reports.\n\
             # Keep it: pass it back (or leave it next to run.londopy for --previous) and\n\
             # next month's shared copy uses the same aliases.\n\
             # A real value starting with = + - or @ is written with a leading ' (spreadsheet safety).\n",
        );
        body.push_str(&crate::util::csv_line(&["real", "alias"]));
        body.push('\n');
        for (real, alias) in &self.table {
            body.push_str(&crate::util::csv_line(&[real, alias]));
            body.push('\n');
        }
        body
    }

    /// Reads a mapping file written by [`Map::to_csv`].
    pub fn from_csv(text: &str) -> anyhow::Result<Self> {
        let mut table = BTreeMap::new();
        let mut aliases = BTreeSet::new();
        for (i, line) in text.lines().enumerate() {
            if line.starts_with('#') || line.trim().is_empty() || line == "real,alias" {
                continue;
            }
            let f = crate::util::parse_csv_line(line);
            let [real, alias] = f.as_slice() else {
                anyhow::bail!("pseudonym map line {}: expected real,alias", i + 1);
            };
            // undo the spreadsheet guard csv_field added on the way out
            let real = match real.strip_prefix('\'') {
                Some(r) if r.starts_with(['=', '+', '-', '@', '\t', '\r']) => r.to_string(),
                _ => real.clone(),
            };
            if !aliases.insert(alias.clone()) {
                anyhow::bail!("pseudonym map line {}: alias {alias} is used twice", i + 1);
            }
            table.insert(real, alias.clone());
        }
        Ok(Self { table })
    }

    fn get(&self, s: &str) -> String {
        self.table.get(s).cloned().unwrap_or_else(|| s.to_string())
    }

    /// (real, alias) pairs for the private mapping file.
    pub fn pairs(&self) -> impl Iterator<Item = (&String, &String)> {
        self.table.iter()
    }

    fn evidence(&self, e: &mut Evidence) {
        e.src = e.src.as_deref().map(|s| self.get(s));
        e.dst = e.dst.as_deref().map(|s| self.get(s));
    }

    pub fn apply(&self, run: &Run) -> Run {
        let mut r = run.clone();
        r.pseudonymized = true;
        if !r.site.is_empty() {
            r.site = "(site name withheld)".into();
        }
        r.source = "(withheld)".into();
        r.compared_to = r.compared_to.map(|_| "(previous run)".into());
        for a in &mut r.assets {
            a.ip = self.get(&a.ip);
            a.mac = a.mac.as_deref().map(|m| self.get(m));
            a.hostnames = a.hostnames.iter().map(|h| self.get(h)).collect();
            if !a.name.is_empty() {
                a.name = self.get(&a.name);
            }
            if let Some(s) = a.identity.get_mut("serial") {
                *s = self.get(s);
            }
            for reason in &mut a.reasons {
                reason.peer = reason.peer.as_deref().map(|p| self.get(p));
                self.evidence(&mut reason.evidence);
            }
            self.evidence(&mut a.first_evidence);
        }
        for e in &mut r.externals {
            e.ip = self.get(&e.ip);
            e.peers = e.peers.iter().map(|p| self.get(p)).collect();
        }
        for e in &mut r.edges {
            e.src = self.get(&e.src);
            e.dst = self.get(&e.dst);
        }
        for f in &mut r.findings {
            f.host = self.get(&f.host);
            f.key = format!("{}:{}", f.rule, f.host);
            f.peers = f.peers.iter().map(|p| self.get(p)).collect();
            for e in &mut f.evidence {
                self.evidence(e);
            }
        }
        for s in &mut r.shared_macs {
            s.mac = self.get(&s.mac);
            s.ips = s.ips.iter().map(|i| self.get(i)).collect();
        }
        // log file names and uids are kept: they're how the volunteer finds the line
        r
    }

    /// Real values still present in a pseudonymized run, as whole JSON string
    /// values. Checked before anything is written.
    pub fn leaks(&self, run: &Run) -> Vec<String> {
        let json = serde_json::to_string(run).unwrap_or_default();
        let aliases: BTreeSet<&String> = self.table.values().collect();
        self.table
            .keys()
            // a real value that is also some alias (a host really named
            // "host-03") can't be told apart in the output; it isn't a leak
            .filter(|real| !aliases.contains(real))
            .filter(|real| {
                // the key as it appears inside JSON, quotes and escapes included
                let quoted = serde_json::to_string(real).unwrap_or_default();
                json.contains(&quoted)
            })
            .cloned()
            .collect()
    }
}

impl Map {
    /// Address-like leaks in rendered text: see [`addresses_in`], with this
    /// map's real values as the known addresses.
    pub fn addresses_in(&self, text: &str) -> Vec<String> {
        let known: BTreeSet<String> = self.table.keys().cloned().collect();
        addresses_in(text, &known)
    }
}

/// IP and MAC addresses in rendered text that a pseudonymized report must not
/// contain: any MAC, any IPv6 address, any private/link-local/shared IPv4
/// address, and any address in `known` (the real values). A public-looking
/// dotted quad that isn't known is left alone, because a firmware version
/// like "1.2.3.4" has the same shape.
pub fn addresses_in(text: &str, known: &BTreeSet<String>) -> Vec<String> {
    let mut found = BTreeSet::new();

    // IPv4: digits and dots only, so "abc10.0.0.5" and "10.0.0.5:502" are caught
    for token in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        let token = token.trim_matches('.');
        if let Ok(ip) = token.parse::<std::net::Ipv4Addr>() {
            let ip = std::net::IpAddr::V4(ip);
            if is_local(&ip, &[]) || known.contains(token) {
                found.insert(token.to_string());
            }
        }
    }

    // IPv6 and MACs: hex digits with ':' (or '-' for dashed MACs)
    for token in text.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '-')) {
        for sep in [':', '-'] {
            let parts: Vec<&str> = token.trim_matches(sep).split(sep).collect();
            let mac = parts.len() == 6
                && parts
                    .iter()
                    .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()));
            if mac {
                found.insert(token.trim_matches(sep).to_string());
            }
        }
        // "2001:db8::" ends in "::", so try the token as-is before trimming
        let candidates = [token, token.trim_end_matches(':')];
        if let Some(v6) = candidates
            .iter()
            .find(|t| t.matches(':').count() >= 2 && t.parse::<std::net::Ipv6Addr>().is_ok())
        {
            let ip: std::net::Ipv6Addr = v6.parse().unwrap_or(std::net::Ipv6Addr::UNSPECIFIED);
            // "::" and "::1" carry nothing about a site
            if !(ip.is_unspecified() || ip.is_loopback()) {
                found.insert(v6.to_string());
            }
        }
    }
    found.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none() -> BTreeSet<String> {
        BTreeSet::new()
    }

    #[test]
    fn finds_addresses_in_text() {
        let text = "Controller 10.10.1.10 talked to 192.168.5.5:502 and x10.0.0.7. MAC \
                    00:1d:9c:aa:bb:cc, 00-1D-9C-AA-BB-DD, v6 fd00::1, 2001:db8::5 and \
                    2001:db9::; time 08:00:00 on 2026-11-01; otinv 0.1.0; firmware \
                    1.2.3.4 and V2.4.1.7; uid CHhAvVGS1DHFjwGM9; host-01, mac-02, ::1.";
        assert_eq!(
            addresses_in(text, &none()),
            [
                "00-1D-9C-AA-BB-DD",
                "00:1d:9c:aa:bb:cc",
                "10.0.0.7",
                "10.10.1.10",
                "192.168.5.5",
                "2001:db8::5",
                "2001:db9::",
                "fd00::1"
            ]
        );
    }

    #[test]
    fn public_addresses_count_when_known() {
        let known: BTreeSet<String> = ["203.0.113.5".to_string()].into();
        let text = "reached 203.0.113.5. firmware 1.2.3.4";
        assert_eq!(addresses_in(text, &known), ["203.0.113.5"]);
        assert!(addresses_in(text, &none()).is_empty());
    }
}
