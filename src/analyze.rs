// turns zeek logs into an asset inventory and a communication map.
//
// passive only: every fact here comes from traffic that was already on the
// wire. an address becomes an asset only if it sent something (started a
// connection, answered one, asked DHCP for an address), so probes to empty
// addresses don't invent phantom devices.

use crate::config::{Kind, Protocol, Rules, Site};
use crate::model::{Asset, Edge, Evidence, External, Role, RoleReason, SharedMac};
use crate::net::{is_device_address, is_local, parse_ip};
use crate::oui::{normalize_mac, Oui};
use crate::zeek::{Log, Record};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

const MAX_REASONS: usize = 6;

/// Builds an Evidence pointing at one log line.
pub fn evidence(
    file: &str,
    rec: &Record,
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    what: String,
) -> Evidence {
    Evidence {
        file: file.to_string(),
        line: rec.line,
        uid: rec.uid().map(String::from),
        ts: rec.ts(),
        src: src.map(|i| i.to_string()),
        dst: dst.map(|i| i.to_string()),
        what,
    }
}

/// One conn.log line, parsed once and shared by the inventory and the checks.
pub struct Conn<'a> {
    pub file: &'a str,
    pub rec: &'a Record,
    pub orig: IpAddr,
    pub resp: IpAddr,
    pub resp_port: u16,
    pub transport: String,
    pub protocol: Option<&'a Protocol>,
    /// The responder replied: a SYN-ACK or data came back.
    pub answered: bool,
    /// The responder sent data, not just a handshake (a port scan has none).
    pub exchanged: bool,
    pub bytes: u64,
    pub ts: Option<f64>,
    pub end: Option<f64>,
}

impl Conn<'_> {
    /// "Modbus" or "tcp/5020" for things the rules don't name.
    pub fn label(&self) -> String {
        match self.protocol {
            Some(p) => p.label.clone(),
            None => format!("{}/{}", self.transport, self.resp_port),
        }
    }

    pub fn is(&self, kind: Kind) -> bool {
        self.protocol.is_some_and(|p| p.is(kind))
    }

    pub fn evidence(&self, what: String) -> Evidence {
        evidence(self.file, self.rec, Some(self.orig), Some(self.resp), what)
    }

    /// "Modbus, tcp/502, answered"
    pub fn describe(&self) -> String {
        let state = if self.answered {
            "answered"
        } else {
            "no reply"
        };
        match self.protocol {
            Some(p) => format!(
                "{}, {}/{}, {state}",
                p.label, self.transport, self.resp_port
            ),
            None => format!("{}/{}, {state}", self.transport, self.resp_port),
        }
    }
}

/// Every connection in every conn log, in log order.
pub fn conns<'a>(logs: &'a [Log], rules: &'a Rules) -> Vec<Conn<'a>> {
    let mut out = Vec::new();
    for log in logs.iter().filter(|l| l.name == "conn") {
        for rec in &log.records {
            let (Some(orig), Some(resp)) = (
                rec.get("id.orig_h").and_then(parse_ip),
                rec.get("id.resp_h").and_then(parse_ip),
            ) else {
                continue;
            };
            let resp_port = rec.u64("id.resp_p").unwrap_or(0) as u16;
            let transport = rec.get("proto").unwrap_or("tcp").to_ascii_lowercase();
            let protocol = rules.classify(rec.get("service"), &transport, resp_port);
            let ts = rec.ts();
            let end = ts.map(|t| t + rec.f64("duration").unwrap_or(0.0));
            out.push(Conn {
                file: &log.file,
                rec,
                orig,
                resp,
                resp_port,
                answered: answered(rec, &transport),
                exchanged: exchanged(rec, &transport),
                transport,
                protocol,
                bytes: rec
                    .u64("orig_bytes")
                    .unwrap_or(0)
                    .saturating_add(rec.u64("resp_bytes").unwrap_or(0)),
                ts,
                end,
            });
        }
    }
    out
}

/// Did the responder send data, not just a handshake? A trimmed conn.log
/// with neither `history` nor `resp_bytes` can't tell; then "answered" is the
/// best there is.
fn exchanged(rec: &Record, transport: &str) -> bool {
    match (rec.get("history"), rec.u64("resp_bytes")) {
        (None, None) => answered(rec, transport),
        (h, b) => h.is_some_and(|h| h.contains('d')) || b.unwrap_or(0) > 0,
    }
}

/// Did the responder say anything back? Zeek's `history` uses lowercase for
/// responder events: h = SYN-ACK, a = ACK, d = data. Without a history, fall
/// back to the connection state and packet counts.
fn answered(rec: &Record, transport: &str) -> bool {
    if let Some(h) = rec.get("history") {
        if h.chars().any(|c| matches!(c, 'h' | 'a' | 'd')) {
            return true;
        }
        if transport == "tcp" {
            return false;
        }
    }
    if rec.u64("resp_pkts").unwrap_or(0) > 0 || rec.u64("resp_bytes").unwrap_or(0) > 0 {
        return true;
    }
    matches!(
        rec.get("conn_state"),
        Some("SF" | "S1" | "S2" | "S3" | "RSTO" | "RSTR")
    )
}

/// The function a Modbus/DNP3 log line sent as a client request, upper case,
/// or None for anything else. Zeek 6+ logs a REQ and a RESP line per Modbus
/// transaction (`pdu_type`) and ICSNPP marks direction with `is_orig`; only
/// the request counts, so each transaction counts once. Zeek 7.2+ names a
/// refused function `<FUNC>_EXCEPTION`; it is still an attempt at FUNC. DNP3
/// lines without a request (unsolicited responses) are None.
pub fn request_function(rec: &Record, field: &str) -> Option<String> {
    if let Some(p) = rec.get("pdu_type") {
        if !p.eq_ignore_ascii_case("REQ") {
            return None;
        }
    } else if matches!(rec.get("is_orig"), Some("F" | "false")) {
        return None;
    }
    let f = rec.get(field)?.trim().to_ascii_uppercase();
    if f.is_empty() {
        return None;
    }
    Some(match f.strip_suffix("_EXCEPTION") {
        Some(base) => base.to_string(),
        None => f,
    })
}

/// (client, server) for a protocol log line. ICSNPP logs each direction with
/// source_h/destination_h and is_orig; stock zeek logs use id.orig_h/id.resp_h,
/// where the originator is the client.
pub fn endpoints(rec: &Record) -> Option<(IpAddr, IpAddr)> {
    if let (Some(s), Some(d)) = (
        rec.get("source_h").and_then(parse_ip),
        rec.get("destination_h").and_then(parse_ip),
    ) {
        return Some(match rec.get("is_orig") {
            Some("F" | "false") => (d, s),
            _ => (s, d),
        });
    }
    Some((
        rec.get("id.orig_h").and_then(parse_ip)?,
        rec.get("id.resp_h").and_then(parse_ip)?,
    ))
}

#[derive(Default)]
struct Host {
    first: Option<f64>,
    last: Option<f64>,
    first_evidence: Option<Evidence>,
    roles: BTreeSet<Role>,
    reasons: Vec<RoleReason>,
    serves: BTreeSet<String>,
    uses: BTreeSet<String>,
    peers: BTreeSet<IpAddr>,
    wire_macs: BTreeSet<String>,
    dhcp_mac: Option<String>,
    hostnames: BTreeSet<String>,
    identity: BTreeMap<String, String>,
    // protocols (rule names) through which this host looked like an HMI
    hmi_protocols: BTreeSet<String>,
    // Modbus/DNP3 requests this host sent: polls (reads etc.) vs writes
    polls: u64,
    writes: u64,
    first_write: Option<(String, Option<IpAddr>, Evidence)>,
}

impl Host {
    fn seen(&mut self, ts: Option<f64>, end: Option<f64>, ev: impl FnOnce() -> Evidence) {
        // logs aren't in time order (conn.log is written when connections
        // end), so keep the earliest line as "first traffic"
        let earlier = match (ts, self.first) {
            (Some(t), Some(f)) => t < f,
            (Some(_), None) => true,
            (None, _) => false,
        };
        if self.first_evidence.is_none() || earlier {
            self.first_evidence = Some(ev());
        }
        if let Some(t) = ts {
            self.first = Some(self.first.map_or(t, |f| f.min(t)));
            self.last = Some(self.last.map_or(t, |l| l.max(t)));
        }
        if let Some(e) = end {
            self.last = Some(self.last.map_or(e, |l| l.max(e)));
        }
    }

    fn role(
        &mut self,
        role: Role,
        what: String,
        peer: Option<IpAddr>,
        ev: impl FnOnce() -> Evidence,
    ) {
        self.roles.insert(role);
        let dup = self
            .reasons
            .iter()
            .any(|r| r.role == role && r.what == what);
        if !dup && self.reasons.len() < MAX_REASONS {
            self.reasons.push(RoleReason {
                role,
                what,
                peer: peer.map(|p| p.to_string()),
                evidence: ev(),
            });
        }
    }
}

pub struct Inventory {
    pub assets: Vec<Asset>,
    pub externals: Vec<External>,
    pub edges: Vec<Edge>,
    pub shared_macs: Vec<SharedMac>,
    pub first_ts: Option<f64>,
    pub last_ts: Option<f64>,
}

struct Builder<'a> {
    rules: &'a Rules,
    site: &'a Site,
    hosts: BTreeMap<IpAddr, Host>,
    externals: BTreeMap<IpAddr, External>,
    edges: BTreeMap<(IpAddr, IpAddr, String), Edge>,
    first_ts: Option<f64>,
    last_ts: Option<f64>,
    // MACs carrying internet addresses: a router's, whatever local IPs it also shows
    router_macs: BTreeSet<String>,
}

impl<'a> Builder<'a> {
    fn local(&self, ip: &IpAddr) -> bool {
        is_device_address(ip) && is_local(ip, &self.site.ranges)
    }

    fn public(&self, ip: &IpAddr) -> bool {
        is_device_address(ip) && !is_local(ip, &self.site.ranges)
    }

    /// The host entry for a local device address, or None for anything else.
    fn host(&mut self, ip: IpAddr) -> Option<&mut Host> {
        if self.local(&ip) {
            Some(self.hosts.entry(ip).or_default())
        } else {
            None
        }
    }

    fn period(&mut self, ts: Option<f64>, end: Option<f64>) {
        for t in [ts, end].into_iter().flatten() {
            self.first_ts = Some(self.first_ts.map_or(t, |f| f.min(t)));
            self.last_ts = Some(self.last_ts.map_or(t, |l| l.max(t)));
        }
    }

    fn conn(&mut self, c: &Conn) {
        self.period(c.ts, c.end);
        let label = c.label();
        for (ip, field) in [(c.orig, "orig_l2_addr"), (c.resp, "resp_l2_addr")] {
            if self.public(&ip) {
                if let Some(m) = c.rec.get(field).and_then(normalize_mac) {
                    self.router_macs.insert(m);
                }
            }
        }
        // the originator always sent something
        if let Some(h) = self.host(c.orig) {
            h.seen(c.ts, c.end, || {
                c.evidence(format!("first traffic ({})", c.describe()))
            });
            if let Some(m) = c.rec.get("orig_l2_addr").and_then(normalize_mac) {
                h.wire_macs.insert(m);
            }
        }
        if !c.answered {
            return;
        }
        if let Some(h) = self.host(c.resp) {
            h.seen(c.ts, c.end, || {
                c.evidence(format!("first traffic ({})", c.describe()))
            });
            if let Some(m) = c.rec.get("resp_l2_addr").and_then(normalize_mac) {
                h.wire_macs.insert(m);
            }
        }
        if !(is_device_address(&c.orig) && is_device_address(&c.resp)) {
            return;
        }

        let edge = self
            .edges
            .entry((c.orig, c.resp, label.clone()))
            .or_insert_with(|| Edge {
                src: c.orig.to_string(),
                dst: c.resp.to_string(),
                protocol: label.clone(),
                conns: 0,
                bytes: 0,
                first: c.ts.unwrap_or(0.0),
                last: c.end.or(c.ts).unwrap_or(0.0),
            });
        edge.conns += 1;
        edge.bytes = edge.bytes.saturating_add(c.bytes);
        if let Some(t) = c.ts {
            edge.first = edge.first.min(t);
        }
        if let Some(e) = c.end.or(c.ts) {
            edge.last = edge.last.max(e);
        }

        for (outside, inside) in [(c.orig, c.resp), (c.resp, c.orig)] {
            if self.public(&outside) && self.local(&inside) {
                let ext = self.externals.entry(outside).or_insert_with(|| External {
                    ip: outside.to_string(),
                    peers: BTreeSet::new(),
                    protocols: BTreeSet::new(),
                });
                ext.peers.insert(inside.to_string());
                ext.protocols.insert(label.clone());
            }
        }

        let ev = || c.evidence(c.describe());
        if let Some(h) = self.host(c.orig) {
            h.uses.insert(label.clone());
            h.peers.insert(c.resp);
            // client roles need a real conversation: a handshake-only scan of
            // port 502 doesn't make the scanner an HMI
            if c.is(Kind::Ot) && c.exchanged {
                if let Some(p) = c.protocol {
                    h.hmi_protocols.insert(p.name.clone());
                }
                h.role(
                    Role::Hmi,
                    format!("starts {label} conversations"),
                    Some(c.resp),
                    ev,
                );
            } else if c.is(Kind::Engineering) && c.exchanged {
                h.role(
                    Role::EngineeringWorkstation,
                    format!("uses {label}"),
                    Some(c.resp),
                    ev,
                );
            }
        }
        if let Some(h) = self.host(c.resp) {
            h.serves.insert(label.clone());
            h.peers.insert(c.orig);
            if c.is(Kind::Ot) {
                h.role(
                    Role::Controller,
                    format!("answers {label}"),
                    Some(c.orig),
                    ev,
                );
            } else if c.is(Kind::Infrastructure) {
                h.role(
                    Role::NetworkService,
                    format!("answers {label}"),
                    Some(c.orig),
                    ev,
                );
            }
        }
    }

    /// Modbus and DNP3 logs: confirms controllers even without conn.log, and
    /// spots engineering functions (programming, restarts, file transfer).
    fn protocol_log(&mut self, log: &Log) {
        let rules = self.rules;
        let (name, label, field, engineering, writes) = match log.name.as_str() {
            "modbus" => (
                "modbus",
                "Modbus",
                "func",
                &rules.roles.engineering_modbus_functions,
                &rules.writes.modbus,
            ),
            "dnp3" => (
                "dnp3",
                "DNP3",
                "fc_request",
                &rules.roles.engineering_dnp3_functions,
                &rules.writes.dnp3,
            ),
            _ => return,
        };
        let upper =
            |v: &Vec<String>| -> Vec<String> { v.iter().map(|s| s.to_ascii_uppercase()).collect() };
        let (engineering, writes) = (upper(engineering), upper(writes));
        for rec in &log.records {
            let Some((client, server)) = endpoints(rec) else {
                continue;
            };
            let ts = rec.ts();
            self.period(ts, None);
            let func = rec.get(field).unwrap_or("");
            let request = request_function(rec, field);
            let ev = |what: String| evidence(&log.file, rec, Some(client), Some(server), what);
            if let Some(h) = self.host(client) {
                h.seen(ts, None, || ev(format!("first traffic ({label} {func})")));
                h.uses.insert(label.to_string());
                match request {
                    // a response line: says nothing about what the client asked
                    None => {}
                    Some(f) if engineering.contains(&f) => h.role(
                        Role::EngineeringWorkstation,
                        format!("sends {label} {f}"),
                        Some(server),
                        || ev(format!("{label} {func}")),
                    ),
                    Some(f) if writes.contains(&f) => {
                        // writes alone don't make an HMI; see finish()
                        h.writes += 1;
                        if h.first_write.is_none() {
                            let what =
                                format!("sends {label} write commands without regular polling");
                            h.first_write = Some((what, Some(server), ev(format!("{label} {f}"))));
                        }
                    }
                    Some(_) => {
                        h.polls += 1;
                        h.hmi_protocols.insert(name.to_string());
                        h.role(Role::Hmi, format!("polls {label}"), Some(server), || {
                            ev(format!("{label} {func}"))
                        });
                    }
                }
            }
            if let Some(h) = self.host(server) {
                h.seen(ts, None, || ev(format!("first traffic ({label} {func})")));
                h.serves.insert(label.to_string());
                h.role(
                    Role::Controller,
                    format!("answers {label}"),
                    Some(client),
                    || ev(format!("{label} {func}")),
                );
            }
        }
    }

    /// Identity fields devices announce about themselves.
    fn identity_log(&mut self, log: &Log) {
        // ICSNPP-ENIP: List Identity replies
        let enip = log.name.starts_with("cip_identity") || log.name == "enip_list_identity";
        // ICSNPP-Modbus: Read Device Identification (function 43/14)
        let modbus = log.name.starts_with("modbus_read_device_identification");
        if !enip && !modbus {
            return;
        }
        for rec in &log.records {
            let Some((client, server)) = endpoints(rec) else {
                continue;
            };
            // the device's own address, when the reply carries one
            let device = rec
                .get("socket_address")
                .and_then(parse_ip)
                .filter(|ip| self.local(ip))
                .unwrap_or(server);
            let ts = rec.ts();
            self.period(ts, None);
            let mut found: Vec<(&str, String)> = Vec::new();
            if enip {
                for (key, names) in [
                    ("vendor", &["vendor_name", "vendor_id"][..]),
                    ("model", &["product_name"][..]),
                    ("device type", &["device_type_name", "device_type_id"][..]),
                    ("product code", &["product_code"][..]),
                    ("firmware", &["revision"][..]),
                    ("serial", &["serial_number"][..]),
                ] {
                    if let Some(v) = rec.get_any(names).filter(|v| !v.is_empty()) {
                        found.push((key, v.to_string()));
                    }
                }
            } else if let (Some(id), Some(val)) = (
                rec.get_any(&["object_id", "object_id_code", "object_name"]),
                rec.get_any(&["object_value", "value"]),
            ) {
                let key = match id.to_ascii_lowercase().trim_start_matches("0x") {
                    "0" | "00" | "vendorname" | "vendor_name" => Some("vendor"),
                    "1" | "01" | "productcode" | "product_code" => Some("product code"),
                    "2" | "02" | "majorminorrevision" | "major_minor_revision" => Some("firmware"),
                    "4" | "04" | "productname" | "product_name" => Some("model"),
                    "5" | "05" | "modelname" | "model_name" => Some("model"),
                    _ => None,
                };
                if let Some(k) = key.filter(|_| !val.is_empty()) {
                    found.push((k, val.to_string()));
                }
            }
            if found.is_empty() {
                continue;
            }
            let file = log.file.clone();
            if let Some(h) = self.host(device) {
                h.seen(ts, None, || {
                    evidence(
                        &file,
                        rec,
                        Some(client),
                        Some(device),
                        "identity reply".into(),
                    )
                });
                for (k, v) in found {
                    h.identity.entry(k.to_string()).or_insert(v);
                }
            }
        }
    }

    fn dhcp_log(&mut self, log: &Log) {
        for rec in &log.records {
            let Some(ip) = rec
                .get_any(&["assigned_addr", "client_addr"])
                .and_then(parse_ip)
            else {
                continue;
            };
            let ts = rec.ts();
            self.period(ts, None);
            let mac = rec.get("mac").and_then(normalize_mac);
            let name = rec
                .get_any(&["host_name", "client_fqdn"])
                .filter(|n| !n.is_empty())
                .map(String::from);
            let file = log.file.clone();
            if let Some(h) = self.host(ip) {
                h.seen(ts, None, || {
                    evidence(&file, rec, Some(ip), None, "DHCP address".into())
                });
                if mac.is_some() {
                    h.dhcp_mac = mac;
                }
                if let Some(n) = name {
                    h.hostnames.insert(n);
                }
            }
        }
    }

    /// Management sessions (web, telnet, SSH, FTP) to a controller mark the
    /// client as an engineering workstation. Needs controllers known first.
    fn management(&mut self, conns: &[Conn]) {
        for c in conns
            .iter()
            .filter(|c| c.exchanged && c.is(Kind::Management))
        {
            let to_controller = self
                .hosts
                .get(&c.resp)
                .is_some_and(|h| h.roles.contains(&Role::Controller));
            if !to_controller {
                continue;
            }
            let label = c.label();
            if let Some(h) = self.host(c.orig) {
                h.role(
                    Role::EngineeringWorkstation,
                    format!("opens {label} sessions to a controller"),
                    Some(c.resp),
                    || c.evidence(c.describe()),
                );
            }
        }
    }

    fn finish(self, oui: &Oui) -> Inventory {
        // a MAC seen with several local IPs, or carrying internet traffic, is a
        // router's; trust it for none of them
        let mut mac_ips: BTreeMap<&str, BTreeSet<IpAddr>> = BTreeMap::new();
        for (ip, h) in &self.hosts {
            for m in &h.wire_macs {
                mac_ips.entry(m.as_str()).or_default().insert(*ip);
            }
        }
        let is_router =
            |mac: &str, ips: &BTreeSet<IpAddr>| ips.len() > 1 || self.router_macs.contains(mac);
        let shared_macs: Vec<SharedMac> = mac_ips
            .iter()
            .filter(|(mac, ips)| is_router(mac, ips))
            .map(|(mac, ips)| SharedMac {
                mac: mac.to_string(),
                vendor: oui.vendor(mac),
                ips: ips.iter().map(|i| i.to_string()).collect(),
            })
            .collect();

        let mut assets = Vec::new();
        for (ip, h) in &self.hosts {
            let Some(first_evidence) = h.first_evidence.clone() else {
                continue;
            };
            let mac = h.dhcp_mac.clone().or_else(|| {
                let mut own = h
                    .wire_macs
                    .iter()
                    .filter(|m| !is_router(m, &mac_ips[m.as_str()]));
                match (own.next(), own.next()) {
                    (Some(m), None) => Some(m.clone()),
                    _ => None,
                }
            });
            let ip_s = ip.to_string();
            let mut roles = h.roles.clone();
            let mut reasons = h.reasons.clone();
            // a host that writes without polling regularly isn't an operator
            // screen: an HMI polls all day. calling it one would excuse it.
            // same threshold as the unexpected-write check.
            let only_logged = h.hmi_protocols.iter().all(|p| p == "modbus" || p == "dnp3");
            if h.writes > 0 && h.polls < self.rules.writes.min_polls && only_logged {
                roles.remove(&Role::Hmi);
                reasons.retain(|r| r.role != Role::Hmi);
                if let Some((what, peer, ev)) = &h.first_write {
                    reasons.push(RoleReason {
                        role: Role::ItHost,
                        what: what.clone(),
                        peer: peer.map(|p| p.to_string()),
                        evidence: ev.clone(),
                    });
                }
            }
            let role = Role::primary(&roles);
            if roles.is_empty() {
                roles.insert(Role::ItHost);
            }
            assets.push(Asset {
                name: self.site.names.get(&ip_s).cloned().unwrap_or_default(),
                vendor: mac.as_deref().and_then(|m| oui.vendor(m)),
                mac,
                hostnames: h.hostnames.iter().cloned().collect(),
                role,
                roles,
                reasons,
                identity: h.identity.clone(),
                serves: h.serves.clone(),
                uses: h.uses.clone(),
                peers: h.peers.len(),
                first_seen: h.first.unwrap_or(0.0),
                last_seen: h.last.unwrap_or(0.0),
                first_evidence,
                ip: ip_s,
            });
        }
        Inventory {
            assets,
            externals: self.externals.into_values().collect(),
            edges: self.edges.into_values().collect(),
            shared_macs,
            first_ts: self.first_ts,
            last_ts: self.last_ts,
        }
    }
}

/// Builds the inventory from all logs.
pub fn inventory(logs: &[Log], conns: &[Conn], rules: &Rules, site: &Site, oui: &Oui) -> Inventory {
    let mut b = Builder {
        rules,
        site,
        hosts: BTreeMap::new(),
        externals: BTreeMap::new(),
        edges: BTreeMap::new(),
        first_ts: None,
        last_ts: None,
        router_macs: BTreeSet::new(),
    };
    for c in conns {
        b.conn(c);
    }
    for log in logs {
        match log.name.as_str() {
            "dhcp" => b.dhcp_log(log),
            "modbus" | "dnp3" => b.protocol_log(log),
            _ => b.identity_log(log),
        }
    }
    b.management(conns);
    b.finish(oui)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answered_logic() {
        let r = |pairs: &[(&str, &str)]| Record::from_pairs(1, pairs);
        assert!(answered(&r(&[("history", "ShADadfF")]), "tcp"));
        assert!(!answered(&r(&[("history", "S")]), "tcp"));
        // REJ: the responder only sent a reset
        assert!(!answered(
            &r(&[("history", "Sr"), ("conn_state", "REJ")]),
            "tcp"
        ));
        assert!(answered(&r(&[("history", "Dd")]), "udp"));
        assert!(answered(&r(&[("resp_pkts", "3")]), "udp"));
        assert!(answered(&r(&[("conn_state", "SF")]), "tcp"));
        assert!(!answered(&r(&[("conn_state", "S0")]), "tcp"));
    }

    #[test]
    fn endpoints_follow_direction() {
        let r = Record::from_pairs(
            1,
            &[
                ("source_h", "10.0.1.10"),
                ("destination_h", "10.0.2.20"),
                ("is_orig", "F"),
            ],
        );
        let (c, s) = endpoints(&r).unwrap();
        assert_eq!(
            (c.to_string(), s.to_string()),
            ("10.0.2.20".into(), "10.0.1.10".into())
        );
        let r = Record::from_pairs(1, &[("id.orig_h", "10.0.2.20"), ("id.resp_h", "10.0.1.10")]);
        assert_eq!(endpoints(&r).unwrap().1.to_string(), "10.0.1.10");
    }
}
