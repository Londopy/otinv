// everything a person reads. the words for each finding are built here from
// the structured run, so a pseudonymized run reads exactly the same.

pub mod csv;
pub mod html;
pub mod map;
pub mod text;

use crate::config::{Check, RuleDef, Severity};
use crate::diff::RunDiff;
use crate::model::{Finding, Role, Run};
use crate::timefmt;
use crate::util::{english_list, plural};
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const SENSITIVE: &str = "SENSITIVE: critical infrastructure information. Keep it private. Don't post it, and don't email it unencrypted.";

pub const README_SENSITIVE: &str = "\
SENSITIVE: CRITICAL INFRASTRUCTURE INFORMATION

This folder describes a utility's control network: its devices, how they
talk, and its weak spots. Treat it like the keys to the plant.

- Keep it on an encrypted disk, and delete it when you no longer need it.
- Don't post it, attach it to a ticket, or email it unencrypted.
- To share for review, re-run otinv with --pseudonymize and share only the
  share/ folder it writes. Nothing else in this folder is safe to share:
  run.londopy and pseudonym-map.csv always hold the real addresses.

Files
  summary.txt          one page: what's on the network, what to fix first
  appendix.html / .txt every finding with the log lines behind it
  inventory.csv        the asset inventory, one row per device
  comms.csv            who talks to whom, over what, how often
  comms.dot / .mmd     the same map for Graphviz / Mermaid
  diff.txt / .html     what changed since the previous run (with --previous)
  run.londopy          this run, real data, for `otinv diff` and --previous
  share/               pseudonymized copies of the reports (with --pseudonymize)
  pseudonym-map.csv    real value -> alias; the key to share/, never share it
  zeek-logs/           zeek's raw logs (only with --keep-logs). These can hold
                       user names, passwords and URLs; otinv's reports don't.
";

pub const README_SHARED: &str = "\
PSEUDONYMIZED OTINV REPORT

Addresses, MAC addresses, host names, device names and serial numbers in
these files are replaced with aliases (host-01, ext-01, mac-01, ...). Device
makes, models, firmware and roles are kept, because a reviewer needs them.

Before finishing, otinv checked every file in this folder for IP and MAC
addresses and found none.

It still describes a real utility's weak spots. Send it only to people you
trust, over an encrypted channel, and ask them to delete it when done.
";

/// Every file name otinv writes into a report folder, so a re-run can clear
/// stale ones (an old diff next to a new summary would mislead).
pub const OUTPUT_FILES: &[&str] = &[
    "README-SENSITIVE.txt",
    "README-SHARED.txt",
    "summary.txt",
    "appendix.txt",
    "appendix.html",
    "inventory.csv",
    "comms.csv",
    "comms.dot",
    "comms.mmd",
    "diff.txt",
    "diff.html",
    "pseudonym-map.csv",
];

/// "Controller (PLC/RTU) 10.0.1.10" or "internet address 203.0.113.5".
pub fn who(run: &Run, ip: &str) -> String {
    run.describe(ip)
}

/// The other side of a finding. Internet addresses first: they are what
/// makes a finding urgent, so they must never be cut off by "and 3 more".
fn peers(run: &Run, f: &Finding) -> String {
    let (mut ext, local): (Vec<&String>, Vec<&String>) =
        f.peers.iter().partition(|p| run.asset(p).is_none());
    ext.extend(local);
    let v: Vec<String> = ext.into_iter().map(|p| who(run, p)).collect();
    english_list(&v, 3)
}

/// One plain sentence per finding.
pub fn describe(run: &Run, f: &Finding) -> String {
    let host = who(run, &f.host);
    let protos = english_list(&f.protocols, 4);
    let p = peers(run, f);
    match f.check {
        Check::OtInternet if f.inbound && f.outbound => {
            format!("{host} exchanged {protos} with the internet in both directions ({p}).")
        }
        Check::OtInternet if f.from_internet => format!("{host} answered {protos} from {p}."),
        Check::OtInternet => format!("{host} sent {protos} traffic to {p}."),
        Check::RemoteAccess if f.outbound && !f.inbound => format!(
            "{host} keeps {protos} sessions open to {p}, so someone outside the plant can \
             control it."
        ),
        Check::RemoteAccess if f.outbound => {
            format!("{host} accepts and makes {protos} connections ({p}).")
        }
        Check::RemoteAccess => format!("{host} accepts {protos} connections from {p}."),
        Check::CleartextLogin => {
            format!("{host} received {protos} logins from {}.", peers(run, f))
        }
        Check::UnexpectedOtWrite if f.from_internet => {
            format!(
                "{host} received {protos} control commands from {}.",
                peers(run, f)
            )
        }
        Check::UnexpectedOtWrite => {
            format!(
                "{host} sent {protos} control commands to {}.",
                peers(run, f)
            )
        }
        Check::NewDevice => format!("{host} was not in the previous report."),
        Check::ItOtMixing => format!(
            "{host} reached {} using {protos}.",
            plural(f.peers.len(), "internet address", "internet addresses")
        ),
    }
}

/// One ranked line of "what to fix first": a rule and the findings under it.
pub struct Action<'a> {
    pub rule: &'a RuleDef,
    pub severity: Severity,
    pub findings: Vec<&'a Finding>,
}

/// Rules ranked by worst severity, then by how many devices they touch.
pub fn actions(run: &Run) -> Vec<Action<'_>> {
    let mut out: Vec<Action> = Vec::new();
    for rule in &run.rules {
        let fs: Vec<&Finding> = run.findings.iter().filter(|f| f.rule == rule.id).collect();
        if let Some(sev) = fs.iter().map(|f| f.severity).max() {
            out.push(Action {
                rule,
                severity: sev,
                findings: fs,
            });
        }
    }
    let order = |id: &str| run.rules.iter().position(|r| r.id == id);
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.findings.len().cmp(&a.findings.len()))
            .then(order(&a.rule.id).cmp(&order(&b.rule.id)))
    });
    out
}

/// "3 controllers (PLC/RTU), 1 operator screen (HMI/SCADA), ..."
pub fn device_counts(run: &Run) -> String {
    let parts: Vec<String> = [
        (
            Role::Controller,
            "controller (PLC/RTU)",
            "controllers (PLC/RTU)",
        ),
        (
            Role::Hmi,
            "operator screen (HMI/SCADA)",
            "operator screens (HMI/SCADA)",
        ),
        (
            Role::EngineeringWorkstation,
            "engineering workstation",
            "engineering workstations",
        ),
        (Role::NetworkService, "network service", "network services"),
        (Role::ItHost, "other computer", "other computers"),
    ]
    .iter()
    .filter_map(|(r, one, many)| {
        let n = run.count_role(*r);
        (n > 0).then(|| plural(n, one, many))
    })
    .collect();
    english_list(&parts, 10)
}

/// "2026-11-01 08:00:00 UTC to 2026-11-01 09:00:00 UTC (1 h 0 min)"
pub fn period(run: &Run) -> String {
    match (run.first_ts, run.last_ts) {
        (Some(a), Some(b)) => format!(
            "{} to {} ({})",
            timefmt::utc(a),
            timefmt::utc(b),
            timefmt::duration(b - a)
        ),
        _ => "unknown (the logs had no time stamps)".into(),
    }
}

/// ", 2 incomplete lines skipped" or nothing.
pub fn skipped_note(n: usize) -> String {
    if n == 0 {
        String::new()
    } else {
        format!(
            ", {} skipped",
            plural(n, "incomplete line", "incomplete lines")
        )
    }
}

pub fn title(run: &Run) -> String {
    if run.site.is_empty() {
        run.source.clone()
    } else {
        run.site.clone()
    }
}

/// Finding counts by severity: "1 critical, 2 high".
pub fn severity_counts(findings: &[Finding]) -> String {
    let mut parts = Vec::new();
    for s in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let n = findings.iter().filter(|f| f.severity == s).count();
        if n > 0 {
            parts.push(format!("{n} {}", s.label().to_ascii_lowercase()));
        }
    }
    parts.join(", ")
}

pub fn finding_hosts(fs: &[&Finding]) -> BTreeSet<String> {
    fs.iter().map(|f| f.host.clone()).collect()
}

/// Writes every report file into `out`. `previous` adds the diff files;
/// `shared` marks a pseudonymized folder, which gets its own README.
pub fn write_all(
    run: &Run,
    previous: Option<(&Run, &RunDiff)>,
    out: &Path,
    shared: bool,
) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(out).with_context(|| format!("Creating {}", out.display()))?;
    let mut written = Vec::new();
    let mut put = |name: &str, body: String| -> Result<()> {
        let p = out.join(name);
        std::fs::write(&p, body).with_context(|| format!("Writing {}", p.display()))?;
        written.push(p);
        Ok(())
    };
    if shared {
        put("README-SHARED.txt", README_SHARED.to_string())?;
    } else {
        put("README-SENSITIVE.txt", README_SENSITIVE.to_string())?;
    }
    put("summary.txt", text::summary(run))?;
    put("appendix.txt", text::appendix(run))?;
    put("appendix.html", html::appendix(run))?;
    put("inventory.csv", csv::inventory(run))?;
    put("comms.csv", csv::comms(run))?;
    put("comms.dot", map::dot(run))?;
    put("comms.mmd", map::mermaid(run))?;
    if let Some((old, d)) = previous {
        put("diff.txt", text::diff(old, run, d))?;
        put("diff.html", html::diff(old, run, d))?;
    }
    Ok(written)
}
