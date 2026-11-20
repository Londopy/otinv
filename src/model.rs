// what one analysis run produces. this is also what gets saved inside the
// run's .londopy file, so diff mode can compare runs months apart: add
// fields with #[serde(default)], never rename or remove them.
//
// nothing here holds prose that mentions an address. sentences are built at
// render time from the structured fields, which is what makes pseudonymizing
// a report a simple field-by-field swap.

use crate::config::{Check, RuleDef, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const RUN_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Controller,
    EngineeringWorkstation,
    Hmi,
    NetworkService,
    ItHost,
}

impl Role {
    /// Plain-English name used in reports.
    pub fn label(self) -> &'static str {
        match self {
            Role::Controller => "Controller (PLC/RTU)",
            Role::EngineeringWorkstation => "Engineering workstation",
            Role::Hmi => "Operator screen (HMI/SCADA)",
            Role::NetworkService => "Network service (DNS/DHCP/NTP)",
            Role::ItHost => "Other computer",
        }
    }

    /// Short form for tables and the map.
    pub fn short(self) -> &'static str {
        match self {
            Role::Controller => "PLC/RTU",
            Role::EngineeringWorkstation => "Engineering",
            Role::Hmi => "HMI/SCADA",
            Role::NetworkService => "Net service",
            Role::ItHost => "IT",
        }
    }

    /// Part of the control system (as opposed to plain IT).
    pub fn is_ot(self) -> bool {
        matches!(
            self,
            Role::Controller | Role::EngineeringWorkstation | Role::Hmi
        )
    }

    /// Picks the primary role from everything a host was seen doing.
    pub fn primary(roles: &BTreeSet<Role>) -> Role {
        [
            Role::Controller,
            Role::EngineeringWorkstation,
            Role::Hmi,
            Role::NetworkService,
        ]
        .into_iter()
        .find(|r| roles.contains(r))
        .unwrap_or(Role::ItHost)
    }
}

/// Where a fact came from: a log file and line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub file: String,
    pub line: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst: Option<String>,
    /// Ports on the src and dst side, when the line is about a connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<(u16, u16)>,
    /// The packet's number in the capture, as Wireshark counts (from 1).
    /// Only known when otinv ran zeek on the capture itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame: Option<u64>,
    /// What was seen, without addresses: "Modbus WRITE_SINGLE_REGISTER".
    pub what: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoleReason {
    pub role: Role,
    /// "answers Modbus", "sends DNP3 COLD_RESTART"
    pub what: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Asset {
    pub ip: String,
    /// Friendly name from site.toml.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub hostnames: Vec<String>,
    pub role: Role,
    #[serde(default)]
    pub roles: BTreeSet<Role>,
    #[serde(default)]
    pub reasons: Vec<RoleReason>,
    /// Identity read from the traffic: vendor, model, firmware, serial.
    #[serde(default)]
    pub identity: BTreeMap<String, String>,
    /// What the utility recorded about the device in site.toml.
    #[serde(default, skip_serializing_if = "Details::is_empty")]
    pub details: Details,
    /// Computers seen programming or configuring this device.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub configured_from: BTreeSet<String>,
    /// Protocol labels this host answered.
    #[serde(default)]
    pub serves: BTreeSet<String>,
    /// Protocol labels this host started.
    #[serde(default)]
    pub uses: BTreeSet<String>,
    #[serde(default)]
    pub peers: usize,
    pub first_seen: f64,
    pub last_seen: f64,
    pub first_evidence: Evidence,
}

impl Asset {
    /// "Controller (PLC/RTU) Well 2 PLC (10.0.1.10)"
    pub fn describe(&self) -> String {
        let role = self.role.label();
        if self.name.is_empty() {
            format!("{role} {}", self.ip)
        } else {
            format!("{role} \"{}\" ({})", self.name, self.ip)
        }
    }

    /// Make and model when the traffic told us, else the MAC vendor.
    pub fn make_model(&self) -> String {
        let parts: Vec<&str> = ["vendor", "model"]
            .iter()
            .filter_map(|k| self.identity.get(*k).map(String::as_str))
            .collect();
        parts.join(" ")
    }
}

/// Facts about a device that no capture shows: CPG 2.0 asks for OT
/// configurations, drawings and tools alongside the inventory.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Details {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub location: String,
    /// Drawings or diagrams that show the device: "P&ID W2-004 rev C".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub drawings: String,
    /// Where its configuration or program backup is, and how recent.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config_backup: String,
    /// Software used to program or configure it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tools: String,
}

impl Details {
    pub fn is_empty(&self) -> bool {
        self.fields().iter().all(|(_, v)| v.is_empty())
    }

    pub fn fields(&self) -> [(&'static str, &String); 4] {
        [
            ("Location", &self.location),
            ("Drawings", &self.drawings),
            ("Configuration backup", &self.config_backup),
            ("Tools", &self.tools),
        ]
    }

    pub fn fields_mut(&mut self) -> [&mut String; 4] {
        [
            &mut self.location,
            &mut self.drawings,
            &mut self.config_backup,
            &mut self.tools,
        ]
    }
}

/// An internet address local devices talked to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct External {
    pub ip: String,
    pub peers: BTreeSet<String>,
    pub protocols: BTreeSet<String>,
}

/// Who talks to whom over what. Only conversations the responder answered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub conns: u64,
    pub bytes: u64,
    pub first: f64,
    pub last: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable across runs: "<rule id>:<host>".
    pub key: String,
    pub rule: String,
    pub check: Check,
    pub severity: Severity,
    /// The local device the finding is about.
    pub host: String,
    /// The other side(s): internet addresses, clients, controllers.
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub from_internet: bool,
    /// Some of the traffic came in to the host.
    #[serde(default)]
    pub inbound: bool,
    /// Some of the traffic went out from the host.
    #[serde(default)]
    pub outbound: bool,
    pub evidence: Vec<Evidence>,
    pub evidence_total: usize,
}

/// A MAC address seen with several IPs: almost always a router, so the
/// devices behind it can't be identified by MAC.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SharedMac {
    pub mac: String,
    #[serde(default)]
    pub vendor: Option<String>,
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogSummary {
    pub file: String,
    pub name: String,
    pub records: usize,
    /// Lines left out: cut off mid-write, or unreadable.
    #[serde(default)]
    pub skipped: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Run {
    pub schema: u32,
    pub tool_version: String,
    /// RFC 3339, when the report was made.
    pub generated: String,
    #[serde(default)]
    pub site: String,
    /// What was analyzed: the capture or log folder name, never a full path.
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub first_ts: Option<f64>,
    #[serde(default)]
    pub last_ts: Option<f64>,
    #[serde(default)]
    pub logs: Vec<LogSummary>,
    pub assets: Vec<Asset>,
    #[serde(default)]
    pub externals: Vec<External>,
    #[serde(default)]
    pub edges: Vec<Edge>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// The rule text in force, so a saved run renders without the rules file.
    #[serde(default)]
    pub rules: Vec<RuleDef>,
    #[serde(default)]
    pub shared_macs: Vec<SharedMac>,
    #[serde(default)]
    pub pseudonymized: bool,
    /// Path of the previous run this one was compared to, if any.
    #[serde(default)]
    pub compared_to: Option<String>,
}

impl Run {
    pub fn asset(&self, ip: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.ip == ip)
    }

    pub fn rule(&self, id: &str) -> Option<&RuleDef> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// "Controller (PLC/RTU) 10.0.1.10", or "internet address 203.0.113.5".
    pub fn describe(&self, ip: &str) -> String {
        match self.asset(ip) {
            Some(a) => a.describe(),
            None if self.externals.iter().any(|e| e.ip == ip) => format!("internet address {ip}"),
            None => ip.to_string(),
        }
    }

    /// Every evidence line in the run.
    pub fn evidence_mut(&mut self) -> impl Iterator<Item = &mut Evidence> {
        let assets = self.assets.iter_mut().flat_map(|a| {
            let Asset {
                first_evidence,
                reasons,
                ..
            } = a;
            std::iter::once(first_evidence).chain(reasons.iter_mut().map(|r| &mut r.evidence))
        });
        assets.chain(self.findings.iter_mut().flat_map(|f| f.evidence.iter_mut()))
    }

    pub fn count_role(&self, role: Role) -> usize {
        self.assets.iter().filter(|a| a.role == role).count()
    }
}
