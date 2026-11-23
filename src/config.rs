// the two files a user can hand otinv:
//   rules.toml - protocols, role hints and the finding definitions (defaults built in)
//   site.toml  - facts about one utility: friendly names, its own address
//                ranges, which computers are allowed to send control commands

use crate::net::Cidr;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const DEFAULT_RULES: &str = include_str!("../rules/default.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Ot,
    Engineering,
    RemoteAccess,
    Management,
    Infrastructure,
    CleartextLogin,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protocol {
    pub name: String,
    pub label: String,
    pub kinds: Vec<Kind>,
    #[serde(default)]
    pub tcp: Vec<u16>,
    #[serde(default)]
    pub udp: Vec<u16>,
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub outside_only: bool,
    /// A remote_access tool that dials out to a relay: an outbound session
    /// from a control-system computer counts too.
    #[serde(default)]
    pub outbound: bool,
}

impl Protocol {
    pub fn is(&self, kind: Kind) -> bool {
        self.kinds.contains(&kind)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleSettings {
    #[serde(default)]
    pub engineering_modbus_functions: Vec<String>,
    #[serde(default)]
    pub engineering_dnp3_functions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Writes {
    #[serde(default)]
    pub modbus: Vec<String>,
    #[serde(default)]
    pub dnp3: Vec<String>,
    /// Without a site list, a computer may write to a controller it polled
    /// (sent other requests to) at least this many times.
    #[serde(default = "default_min_polls")]
    pub min_polls: u64,
}

fn default_min_polls() -> u64 {
    10
}

impl Default for Writes {
    fn default() -> Self {
        Self {
            modbus: Vec::new(),
            dnp3: Vec::new(),
            min_polls: default_min_polls(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Check {
    OtInternet,
    RemoteAccess,
    CleartextLogin,
    UnexpectedOtWrite,
    NewDevice,
    ItOtMixing,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDef {
    pub id: String,
    pub check: Check,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub severity: Severity,
    /// Used instead of `severity` when the problem is reachable from the internet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_internet: Option<Severity>,
    pub title: String,
    pub why: String,
    pub action: String,
    #[serde(default)]
    pub cpg: String,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    pub schema: u32,
    #[serde(default)]
    pub protocol: Vec<Protocol>,
    #[serde(default)]
    pub roles: RoleSettings,
    #[serde(default)]
    pub writes: Writes,
    #[serde(default)]
    pub rule: Vec<RuleDef>,
}

impl Rules {
    pub fn builtin() -> Self {
        // the default file is checked by a test, so this can't fail in a release
        Self::parse(DEFAULT_RULES).expect("built-in rules are valid")
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("Reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("In {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let rules: Rules = toml::from_str(text)?;
        if rules.schema != 1 {
            bail!(
                "rules schema {} is not supported (this otinv reads schema 1)",
                rules.schema
            );
        }
        let mut seen = BTreeSet::new();
        for p in &rules.protocol {
            if !seen.insert(p.name.as_str()) {
                bail!("protocol '{}' is defined twice", p.name);
            }
        }
        let mut seen = BTreeSet::new();
        for r in &rules.rule {
            if !seen.insert(r.id.as_str()) {
                bail!("rule '{}' is defined twice", r.id);
            }
        }
        Ok(rules)
    }

    /// Matches a connection to a protocol: zeek's service name first, then the
    /// responder port.
    pub fn classify(
        &self,
        service: Option<&str>,
        transport: &str,
        resp_port: u16,
    ) -> Option<&Protocol> {
        if let Some(svc) = service {
            for token in svc.split(',').map(|t| t.trim().to_ascii_lowercase()) {
                // zeek prefixes services it is unsure of with "-"
                let token = token.trim_start_matches('-');
                if let Some(p) = self
                    .protocol
                    .iter()
                    .find(|p| p.services.iter().any(|s| s.eq_ignore_ascii_case(token)))
                {
                    return Some(p);
                }
            }
        }
        self.protocol.iter().find(|p| match transport {
            "tcp" => p.tcp.contains(&resp_port),
            "udp" => p.udp.contains(&resp_port),
            _ => false,
        })
    }

    pub fn protocol(&self, name: &str) -> Option<&Protocol> {
        self.protocol.iter().find(|p| p.name == name)
    }

    pub fn enabled(&self) -> impl Iterator<Item = &RuleDef> {
        self.rule.iter().filter(|r| r.enabled)
    }
}

pub const SITE_TEMPLATE: &str = r#"# otinv site file: facts about one utility's network.
# Pass it with `--site site.toml`. Every field is optional.
# This file names your devices, so keep it with the reports, not in public.

# shown at the top of every report
name = "Example Water District"

# address ranges that belong to you, besides the private ranges (10/8,
# 172.16/12, 192.168/16) that are always counted as yours
local_networks = [
  # "203.0.113.0/28",
]

# computers that are supposed to send control commands (Modbus writes, DNP3
# operate). Without this list, a computer is expected to send them to a
# controller it also polls regularly (min_polls in the rules).
expected_writers = [
  # "10.0.2.20",
]

# friendly names used in every report
[names]
# "10.0.1.10" = "Well 2 PLC"
# "10.0.2.20" = "Control room HMI"

# what CISA's CPG 2.0 asks an OT inventory to hold besides what a capture
# shows: where each device is, the drawings it's on, where its configuration
# is backed up, and the software used to program it. These go into
# inventory.csv every month, so write them once here instead of in the CSV.
# [details."10.0.1.10"]
# location = "Well 2 pump house, panel 3"
# drawings = "P&ID W2-004 rev C"
# config_backup = "program exported 2026-10-03, office file server"
# tools = "CLICK Programming Software 3.60"
"#;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_networks: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_writers: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub names: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, crate::model::Details>,
    #[serde(skip)]
    pub ranges: Vec<Cidr>,
}

impl Site {
    /// The site file as TOML, for saving after an edit. Checked by parsing it
    /// back, so a saved file always loads.
    pub fn to_toml(&self) -> Result<String> {
        let body = toml::to_string(self).context("Writing the site file")?;
        let text = format!(
            "# otinv site file, saved by otinv-gui. `otinv site-template` shows every\n\
             # field with an explanation. It names your devices: keep it private.\n\n{body}"
        );
        Self::parse(&text).context("The site file didn't read back")?;
        Ok(text)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("Reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("In {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut site: Site = toml::from_str(text)?;
        for n in &site.local_networks {
            match Cidr::parse(n) {
                Some(c) => site.ranges.push(c),
                None => bail!("local_networks: '{n}' is not an address range like 10.0.0.0/8"),
            }
        }
        for w in &site.expected_writers {
            if crate::net::parse_ip(w).is_none() {
                bail!("expected_writers: '{w}' is not an IP address");
            }
        }
        for ip in site.details.keys() {
            if crate::net::parse_ip(ip).is_none() {
                bail!("details: '{ip}' is not an IP address");
            }
        }
        Ok(site)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_parse_and_cover_every_check() {
        let r = Rules::builtin();
        for c in [
            Check::OtInternet,
            Check::RemoteAccess,
            Check::CleartextLogin,
            Check::UnexpectedOtWrite,
            Check::NewDevice,
            Check::ItOtMixing,
        ] {
            assert!(r.rule.iter().any(|d| d.check == c), "{c:?} has no rule");
        }
        assert!(r
            .writes
            .modbus
            .contains(&"WRITE_SINGLE_REGISTER".to_string()));
    }

    #[test]
    fn classifies_by_service_then_port() {
        let r = Rules::builtin();
        assert_eq!(
            r.classify(Some("modbus"), "tcp", 5020).unwrap().name,
            "modbus"
        );
        assert_eq!(r.classify(None, "tcp", 502).unwrap().name, "modbus");
        assert_eq!(
            r.classify(Some("ssl,-http"), "tcp", 9999).unwrap().name,
            "https"
        );
        assert_eq!(r.classify(Some("-rfb"), "tcp", 1).unwrap().name, "vnc");
        assert!(r.classify(None, "udp", 502).is_none());
        assert!(r
            .classify(None, "tcp", 5901)
            .unwrap()
            .is(Kind::RemoteAccess));
    }

    #[test]
    fn rejects_duplicates_and_unknown_checks() {
        let base = "schema = 1\n";
        let dup = format!("{base}[[rule]]\nid='A'\ncheck='new_device'\nseverity='low'\ntitle=''\nwhy=''\naction=''\n[[rule]]\nid='A'\ncheck='new_device'\nseverity='low'\ntitle=''\nwhy=''\naction=''\n");
        assert!(Rules::parse(&dup)
            .unwrap_err()
            .to_string()
            .contains("twice"));
        let unknown = format!(
            "{base}[[rule]]\nid='A'\ncheck='bogus'\nseverity='low'\ntitle=''\nwhy=''\naction=''\n"
        );
        assert!(Rules::parse(&unknown).is_err());
        assert!(Rules::parse("schema = 2\n").is_err());
    }

    #[test]
    fn site_template_parses() {
        let s = Site::parse(SITE_TEMPLATE).unwrap();
        assert_eq!(s.name, "Example Water District");
        assert!(Site::parse("local_networks = ['nope']").is_err());
        assert!(Site::parse("expected_writers = ['nope']").is_err());
        assert!(Site::parse("surprise = 1").is_err());
        let d = Site::parse("[details.'10.0.1.10']\ndrawings = 'P&ID 4'").unwrap();
        assert_eq!(d.details["10.0.1.10"].drawings, "P&ID 4");
        assert!(Site::parse("[details.'10.0.1.10']\ndrawing = 'x'").is_err());
        assert!(Site::parse("[details.well2]\ntools = 'x'").is_err());
    }

    #[test]
    fn site_file_saves_and_loads_back() {
        let mut s = Site::parse(
            "name = 'Lab'\nlocal_networks = ['203.0.113.0/28']\n\
             expected_writers = ['10.0.2.20']\n[names]\n'10.0.1.10' = 'Well \"2\" PLC'\n",
        )
        .unwrap();
        s.details.insert(
            "10.0.1.10".into(),
            crate::model::Details {
                location: "Pump house".into(),
                tools: "CLICK 3.60".into(),
                ..Default::default()
            },
        );
        let back = Site::parse(&s.to_toml().unwrap()).unwrap();
        assert_eq!(back.name, "Lab");
        assert_eq!(back.local_networks, ["203.0.113.0/28"]);
        assert_eq!(back.ranges.len(), 1);
        assert_eq!(back.expected_writers, ["10.0.2.20"]);
        assert_eq!(back.names["10.0.1.10"], "Well \"2\" PLC");
        assert_eq!(back.details, s.details);
        // a bad address never gets saved
        s.expected_writers.push("not an address".into());
        assert!(s.to_toml().is_err());
    }
}
