// the findings (FR-8 to FR-13). each check is a plain loop over log lines
// with a rule from rules.toml; a finding is grouped per local device, and
// keeps the log lines that produced it.

use crate::analyze::{endpoints, evidence, request_function, Conn, Inventory};
use crate::config::{Check, Kind, RuleDef, Rules, Severity, Site};
use crate::model::{Evidence, Finding, Role, Run};
use crate::net::{cmp_addr, is_device_address, is_local, parse_ip};
use crate::zeek::Log;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// Which way the traffic went, seen from the finding's host.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    /// The peer reached the host.
    In,
    /// The host reached the peer.
    Out,
}

/// Evidence lines kept per finding. Far more than anyone reads, and it keeps
/// a month of a misconfigured poller from filling memory; the total is
/// still counted.
pub const MAX_EVIDENCE: usize = 10_000;

struct Acc {
    severity: Severity,
    peers: BTreeSet<String>,
    protocols: BTreeSet<String>,
    from_internet: bool,
    inbound: bool,
    outbound: bool,
    evidence: Vec<Evidence>,
    total: usize,
}

/// One observation for a finding.
struct Hit<'a> {
    host: IpAddr,
    peer: Option<IpAddr>,
    protocol: &'a str,
    /// Uses the rule's `severity_internet` when it has one.
    internet: bool,
    dir: Dir,
    evidence: Evidence,
}

struct Findings<'a> {
    rules: &'a Rules,
    site: &'a Site,
    roles: BTreeMap<String, Role>,
    acc: BTreeMap<(String, String), Acc>,
}

impl Findings<'_> {
    fn local(&self, ip: &IpAddr) -> bool {
        is_device_address(ip) && is_local(ip, &self.site.ranges)
    }

    fn public(&self, ip: &IpAddr) -> bool {
        is_device_address(ip) && !is_local(ip, &self.site.ranges)
    }

    fn ot_role(&self, ip: &IpAddr) -> bool {
        self.roles.get(&ip.to_string()).is_some_and(|r| r.is_ot())
    }

    fn rules_for(&self, check: Check) -> Vec<RuleDef> {
        self.rules
            .enabled()
            .filter(|r| r.check == check)
            .cloned()
            .collect()
    }

    fn add(&mut self, rule: &RuleDef, hit: Hit) {
        let severity = match (hit.internet, rule.severity_internet) {
            (true, Some(s)) => s,
            _ => rule.severity,
        };
        let a = self
            .acc
            .entry((rule.id.clone(), hit.host.to_string()))
            .or_insert_with(|| Acc {
                severity,
                peers: BTreeSet::new(),
                protocols: BTreeSet::new(),
                from_internet: false,
                inbound: false,
                outbound: false,
                evidence: Vec::new(),
                total: 0,
            });
        a.severity = a.severity.max(severity);
        if let Some(p) = hit.peer {
            a.peers.insert(p.to_string());
        }
        a.protocols.insert(hit.protocol.to_string());
        a.from_internet |= hit.internet;
        a.inbound |= hit.dir == Dir::In;
        a.outbound |= hit.dir == Dir::Out;
        a.total += 1;
        if a.evidence.len() < MAX_EVIDENCE {
            a.evidence.push(hit.evidence);
        }
    }

    /// FR-8: industrial protocols to or from the internet.
    fn ot_internet(&mut self, conns: &[Conn]) {
        for rule in self.rules_for(Check::OtInternet) {
            for c in conns.iter().filter(|c| c.is(Kind::Ot)) {
                let label = c.label();
                if self.local(&c.orig) && self.public(&c.resp) {
                    // outbound counts even unanswered: the device is trying
                    let what = format!("{} to the internet", c.describe());
                    let hit = Hit {
                        host: c.orig,
                        peer: Some(c.resp),
                        protocol: &label,
                        internet: false,
                        dir: Dir::Out,
                        evidence: c.evidence(what),
                    };
                    self.add(&rule, hit);
                } else if self.public(&c.orig) && self.local(&c.resp) && c.answered {
                    let what = format!("{} from the internet", c.describe());
                    let hit = Hit {
                        host: c.resp,
                        peer: Some(c.orig),
                        protocol: &label,
                        internet: true,
                        dir: Dir::In,
                        evidence: c.evidence(what),
                    };
                    self.add(&rule, hit);
                }
            }
        }
    }

    /// FR-9: remote-access services answering on control-system computers or
    /// to the internet, and control-system computers keeping an outbound
    /// remote-control session (TeamViewer-style tools dial out to a relay).
    fn remote_access(&mut self, conns: &[Conn]) {
        for rule in self.rules_for(Check::RemoteAccess) {
            for c in conns
                .iter()
                .filter(|c| c.answered && c.is(Kind::RemoteAccess))
            {
                let label = c.label();
                let outside_only = c.protocol.is_some_and(|p| p.outside_only);
                let dials_out = c.protocol.is_some_and(|p| p.outbound);
                if self.local(&c.resp) {
                    let outside = self.public(&c.orig);
                    if outside || (self.ot_role(&c.resp) && !outside_only) {
                        let hit = Hit {
                            host: c.resp,
                            peer: Some(c.orig),
                            protocol: &label,
                            internet: outside,
                            dir: Dir::In,
                            evidence: c.evidence(c.describe()),
                        };
                        self.add(&rule, hit);
                    }
                } else if dials_out
                    && self.local(&c.orig)
                    && self.public(&c.resp)
                    && self.ot_role(&c.orig)
                {
                    let what = format!("{} to the internet", c.describe());
                    let hit = Hit {
                        host: c.orig,
                        peer: Some(c.resp),
                        protocol: &label,
                        internet: true,
                        dir: Dir::Out,
                        evidence: c.evidence(what),
                    };
                    self.add(&rule, hit);
                }
            }
        }
    }

    /// FR-10: logins readable on the wire. The user names and passwords were
    /// dropped by the log reader; only "a login happened" is left.
    fn cleartext_login(&mut self, logs: &[Log], conns: &[Conn]) {
        for rule in self.rules_for(Check::CleartextLogin) {
            for log in logs {
                let (label, marker) = match log.name.as_str() {
                    "ftp" => ("FTP", "user"),
                    "http" => ("Web (HTTP)", "username"),
                    _ => continue,
                };
                for rec in log.records.iter().filter(|r| r.had(marker)) {
                    let Some((client, server)) = endpoints(rec) else {
                        continue;
                    };
                    if !self.local(&server) {
                        continue;
                    }
                    let what = format!("{label} login (user name and password not kept)");
                    let hit = Hit {
                        host: server,
                        peer: Some(client),
                        protocol: label,
                        internet: self.public(&client),
                        dir: Dir::In,
                        evidence: evidence(&log.file, rec, Some(client), Some(server), what),
                    };
                    self.add(&rule, hit);
                }
            }
            for c in conns
                .iter()
                .filter(|c| c.answered && c.is(Kind::CleartextLogin))
            {
                if self.local(&c.resp) {
                    let label = c.label();
                    let what = format!("{} session; its logins are always readable", c.describe());
                    let hit = Hit {
                        host: c.resp,
                        peer: Some(c.orig),
                        protocol: &label,
                        internet: self.public(&c.orig),
                        dir: Dir::In,
                        evidence: c.evidence(what),
                    };
                    self.add(&rule, hit);
                }
            }
        }
    }

    /// FR-11: Modbus writes and DNP3 control from a computer that isn't
    /// expected to send them. Expected means listed in site.toml, or (with no
    /// list) a computer that polled that same controller at least
    /// `min_polls` times. Only request lines count, so a transaction logged
    /// as a REQ and a RESP line counts once.
    fn unexpected_writes(&mut self, logs: &[Log]) {
        let site_list: BTreeSet<String> = self
            .site
            .expected_writers
            .iter()
            .filter_map(|w| parse_ip(w).map(|i| i.to_string()))
            .collect();
        let writes = |name: &str| -> Option<(&'static str, &'static str, Vec<String>)> {
            let (label, field, list) = match name {
                "modbus" => ("Modbus", "func", &self.rules.writes.modbus),
                "dnp3" => ("DNP3", "fc_request", &self.rules.writes.dnp3),
                _ => return None,
            };
            Some((
                label,
                field,
                list.iter().map(|s| s.to_ascii_uppercase()).collect(),
            ))
        };
        let mut polls: BTreeMap<(IpAddr, IpAddr), u64> = BTreeMap::new();
        let mut hits = Vec::new();
        for log in logs {
            let Some((label, field, list)) = writes(&log.name) else {
                continue;
            };
            for rec in &log.records {
                let (Some(func), Some((client, server))) =
                    (request_function(rec, field), endpoints(rec))
                else {
                    continue;
                };
                if list.contains(&func) {
                    let ev = evidence(
                        &log.file,
                        rec,
                        Some(client),
                        Some(server),
                        format!("{label} {func}"),
                    );
                    hits.push((client, server, label, ev));
                } else {
                    *polls.entry((client, server)).or_default() += 1;
                }
            }
        }
        let min_polls = self.rules.writes.min_polls;
        let expected = |writer: IpAddr, target: IpAddr| {
            if site_list.is_empty() {
                polls.get(&(writer, target)).copied().unwrap_or(0) >= min_polls
            } else {
                site_list.contains(&writer.to_string())
            }
        };
        hits.retain(|(w, t, _, _)| !expected(*w, *t));
        for rule in self.rules_for(Check::UnexpectedOtWrite) {
            for (writer, target, label, ev) in &hits {
                let hit = if self.local(writer) {
                    Hit {
                        host: *writer,
                        peer: Some(*target),
                        protocol: label,
                        internet: false,
                        dir: Dir::Out,
                        evidence: ev.clone(),
                    }
                } else if self.local(target) {
                    // a writer on the internet: file it under the device it hit
                    Hit {
                        host: *target,
                        peer: Some(*writer),
                        protocol: label,
                        internet: true,
                        dir: Dir::In,
                        evidence: ev.clone(),
                    }
                } else {
                    continue;
                };
                self.add(&rule, hit);
            }
        }
    }

    /// FR-12: devices that weren't in the previous run. A device that kept
    /// its MAC but changed address isn't new.
    fn new_devices(&mut self, inv: &Inventory, previous: &Run) {
        let old_ips: BTreeSet<&str> = previous.assets.iter().map(|a| a.ip.as_str()).collect();
        let old_macs: BTreeSet<&str> = previous
            .assets
            .iter()
            .filter_map(|a| a.mac.as_deref())
            .collect();
        for rule in self.rules_for(Check::NewDevice) {
            for a in &inv.assets {
                let moved = a.mac.as_deref().is_some_and(|m| old_macs.contains(m));
                if old_ips.contains(a.ip.as_str()) || moved {
                    continue;
                }
                let Some(ip) = parse_ip(&a.ip) else { continue };
                let mut ev = a.first_evidence.clone();
                ev.what = format!("not in the previous run; {}", ev.what);
                let hit = Hit {
                    host: ip,
                    peer: None,
                    protocol: a.role.short(),
                    internet: false,
                    dir: Dir::In,
                    evidence: ev,
                };
                self.add(&rule, hit);
            }
        }
    }

    /// FR-13: control-system devices using ordinary internet services.
    /// Remote-control tools dialing out are REMOTE-ACCESS, not counted twice.
    fn it_ot_mixing(&mut self, conns: &[Conn]) {
        for rule in self.rules_for(Check::ItOtMixing) {
            for c in conns.iter().filter(|c| c.answered && !c.is(Kind::Ot)) {
                let remote_tool =
                    c.is(Kind::RemoteAccess) && c.protocol.is_some_and(|p| p.outbound);
                if !remote_tool
                    && self.local(&c.orig)
                    && self.public(&c.resp)
                    && self.ot_role(&c.orig)
                {
                    let label = c.label();
                    let what = format!("{} to the internet", c.describe());
                    let hit = Hit {
                        host: c.orig,
                        peer: Some(c.resp),
                        protocol: &label,
                        internet: false,
                        dir: Dir::Out,
                        evidence: c.evidence(what),
                    };
                    self.add(&rule, hit);
                }
            }
        }
    }

    fn finish(self) -> Vec<Finding> {
        let order: BTreeMap<&str, usize> = self
            .rules
            .rule
            .iter()
            .enumerate()
            .map(|(i, r)| (r.id.as_str(), i))
            .collect();
        let mut out: Vec<Finding> = self
            .acc
            .into_iter()
            .map(|((rule, host), a)| {
                let check = self
                    .rules
                    .rule
                    .iter()
                    .find(|r| r.id == rule)
                    .map(|r| r.check);
                let mut peers: Vec<String> = a.peers.into_iter().collect();
                peers.sort_by(|x, y| cmp_addr(x, y));
                Finding {
                    key: format!("{rule}:{host}"),
                    check: check.unwrap_or(Check::NewDevice),
                    rule,
                    severity: a.severity,
                    host,
                    peers,
                    protocols: a.protocols.into_iter().collect(),
                    from_internet: a.from_internet,
                    inbound: a.inbound,
                    outbound: a.outbound,
                    evidence: a.evidence,
                    evidence_total: a.total,
                }
            })
            .collect();
        out.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(order.get(a.rule.as_str()).cmp(&order.get(b.rule.as_str())))
                .then(cmp_addr(&a.host, &b.host))
        });
        out
    }
}

/// Runs every enabled rule.
pub fn run(
    logs: &[Log],
    conns: &[Conn],
    inv: &Inventory,
    rules: &Rules,
    site: &Site,
    previous: Option<&Run>,
) -> Vec<Finding> {
    let mut f = Findings {
        rules,
        site,
        roles: inv.assets.iter().map(|a| (a.ip.clone(), a.role)).collect(),
        acc: BTreeMap::new(),
    };
    f.ot_internet(conns);
    f.remote_access(conns);
    f.cleartext_login(logs, conns);
    f.unexpected_writes(logs);
    if let Some(prev) = previous {
        f.new_devices(inv, prev);
    }
    f.it_ot_mixing(conns);
    f.finish()
}
