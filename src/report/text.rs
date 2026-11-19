// plain-text reports: the one-page summary (FR-15), the appendix (FR-16) and
// the diff (FR-17). plain text survives every email client and printer.

use super::{actions, describe, device_counts, period, severity_counts, title, who, SENSITIVE};
use crate::diff::RunDiff;
use crate::model::Run;
use crate::timefmt;
use crate::util::{english_list, plural, wrap};
use std::fmt::Write;

const W: usize = 78;
const TOP: usize = 5;

fn header(out: &mut String, run: &Run, heading: &str) {
    let _ = writeln!(out, "{}\n", wrap(SENSITIVE, W, "", ""));
    let _ = writeln!(out, "{heading}: {}", title(run));
    let _ = writeln!(
        out,
        "{}",
        wrap(&format!("Traffic covered: {}", period(run)), W, "", "  ")
    );
    let _ = writeln!(out, "Made: {} by otinv {}", run.generated, run.tool_version);
    if run.compared_to.is_some() {
        let _ = writeln!(
            out,
            "Compared with: {}",
            run.compared_to.as_deref().unwrap_or("")
        );
    }
    if run.pseudonymized {
        let _ = writeln!(
            out,
            "Addresses and names are replaced with aliases (pseudonymized)."
        );
    }
    out.push('\n');
}

/// The one-pager.
pub fn summary(run: &Run) -> String {
    let mut o = String::new();
    header(&mut o, run, "OTINV REPORT");

    o.push_str("WHAT IS ON THE NETWORK\n");
    let devices = format!(
        "{} seen: {}.",
        plural(run.assets.len(), "device", "devices"),
        if run.assets.is_empty() {
            "none".into()
        } else {
            device_counts(run)
        }
    );
    let _ = writeln!(o, "{}", wrap(&devices, W, "  ", "  "));
    if !run.externals.is_empty() {
        let line = format!(
            "They talked to {} on the internet.",
            plural(run.externals.len(), "address", "addresses")
        );
        let _ = writeln!(o, "{}", wrap(&line, W, "  ", "  "));
    }
    if !run.findings.is_empty() {
        let line = format!(
            "{} ({}).",
            plural(run.findings.len(), "problem found", "problems found"),
            severity_counts(&run.findings)
        );
        let _ = writeln!(o, "{}", wrap(&line, W, "  ", "  "));
    }
    o.push('\n');

    o.push_str("WHAT TO FIX FIRST\n");
    let acts = actions(run);
    if acts.is_empty() {
        let none = "otinv's checks found nothing to fix. That doesn't prove the network is \
                    safe: otinv only sees what was on the wire during the capture.";
        let _ = writeln!(
            o,
            "{}
",
            wrap(none, W, "  ", "  ")
        );
    }
    for (i, a) in acts.iter().take(TOP).enumerate() {
        let first = format!("  {}. ", i + 1);
        let pad = " ".repeat(first.len());
        let _ = writeln!(
            o,
            "{}",
            wrap(
                &format!("[{}] {}", a.severity.label(), a.rule.title),
                W,
                &first,
                &pad
            )
        );
        for f in a.findings.iter().take(2) {
            let _ = writeln!(o, "{}", wrap(&describe(run, f), W, &pad, &pad));
        }
        if a.findings.len() > 2 {
            let more = format!(
                "...and {}.",
                plural(a.findings.len() - 2, "more device", "more devices")
            );
            let _ = writeln!(o, "{}", wrap(&more, W, &pad, &pad));
        }
        let _ = writeln!(
            o,
            "{}",
            wrap(&format!("Do this: {}", a.rule.action), W, &pad, &pad)
        );
        o.push('\n');
    }
    if acts.len() > TOP {
        let n = acts.len() - TOP;
        let rest = if n == 1 {
            "1 more kind of problem is listed in the appendix.".to_string()
        } else {
            format!("{n} more kinds of problem are listed in the appendix.")
        };
        let _ = writeln!(o, "{}\n", wrap(&rest, W, "  ", "  "));
    }

    let foot = "Details and the evidence for every item: appendix.html (or appendix.txt). \
                otinv only listened. It sent nothing to any device, and it can only see \
                devices that talked during the capture.";
    let _ = writeln!(o, "{}", wrap(foot, W, "", ""));
    o
}

/// The volunteer's appendix: everything, with evidence.
pub fn appendix(run: &Run) -> String {
    let mut o = summary(run);
    o.push_str("\n\n");
    o.push_str(&"=".repeat(W));
    o.push_str("\nAPPENDIX\n");
    o.push_str(&"=".repeat(W));
    o.push_str("\n\n");

    o.push_str("FINDINGS\n\n");
    if run.findings.is_empty() {
        o.push_str("  None.\n\n");
    }
    for a in actions(run) {
        let _ = writeln!(
            o,
            "[{}] {} ({})",
            a.severity.label(),
            a.rule.title,
            a.rule.id
        );
        let _ = writeln!(
            o,
            "{}",
            wrap(&format!("Why it matters: {}", a.rule.why), W, "  ", "  ")
        );
        let _ = writeln!(
            o,
            "{}",
            wrap(&format!("Do this: {}", a.rule.action), W, "  ", "  ")
        );
        if !a.rule.cpg.is_empty() {
            let _ = writeln!(
                o,
                "{}",
                wrap(&format!("CISA CPG: {}", a.rule.cpg), W, "  ", "  ")
            );
        }
        for f in &a.findings {
            o.push('\n');
            let _ = writeln!(
                o,
                "{}",
                wrap(
                    &format!("[{}] {}", f.severity.label(), describe(run, f)),
                    W,
                    "  - ",
                    "    "
                )
            );
            let _ = writeln!(
                o,
                "    Evidence ({}{}):",
                plural(f.evidence_total, "log line", "log lines"),
                if f.evidence_total > f.evidence.len() {
                    format!(", first {} shown", f.evidence.len())
                } else {
                    String::new()
                }
            );
            for e in &f.evidence {
                let _ = writeln!(o, "      {}", evidence_line(e));
            }
        }
        o.push('\n');
    }

    o.push_str("ASSET INVENTORY\n\n");
    for a in &run.assets {
        let _ = writeln!(o, "{}", a.describe());
        let mut facts: Vec<String> = Vec::new();
        if let Some(m) = &a.mac {
            facts.push(format!(
                "MAC {m}{}",
                a.vendor
                    .as_ref()
                    .map(|v| format!(" ({v})"))
                    .unwrap_or_default()
            ));
        }
        if !a.hostnames.is_empty() {
            facts.push(format!("host name {}", a.hostnames.join(", ")));
        }
        for (k, v) in &a.identity {
            facts.push(format!("{k}: {v}"));
        }
        if !a.serves.is_empty() {
            facts.push(format!(
                "answers {}",
                english_list(&a.serves.iter().cloned().collect::<Vec<_>>(), 6)
            ));
        }
        if !a.uses.is_empty() {
            facts.push(format!(
                "uses {}",
                english_list(&a.uses.iter().cloned().collect::<Vec<_>>(), 6)
            ));
        }
        facts.push(format!(
            "seen {} to {}",
            timefmt::utc(a.first_seen),
            timefmt::utc(a.last_seen)
        ));
        for f in facts {
            let _ = writeln!(o, "{}", wrap(&f, W, "    ", "      "));
        }
        for r in &a.reasons {
            let peer = r
                .peer
                .as_deref()
                .map(|p| format!(" ({})", who(run, p)))
                .unwrap_or_default();
            let line = format!(
                "{}: {}{peer} [{}:{}]",
                r.role.short(),
                r.what,
                r.evidence.file,
                r.evidence.line
            );
            let _ = writeln!(o, "{}", wrap(&line, W, "    why: ", "      "));
        }
        o.push('\n');
    }

    if !run.externals.is_empty() {
        o.push_str("INTERNET ADDRESSES\n\n");
        for e in &run.externals {
            let peers: Vec<String> = e.peers.iter().map(|p| who(run, p)).collect();
            let protos: Vec<String> = e.protocols.iter().cloned().collect();
            let line = format!(
                "{} - {} with {}",
                e.ip,
                english_list(&protos, 5),
                english_list(&peers, 4)
            );
            let _ = writeln!(o, "{}", wrap(&line, W, "  ", "    "));
        }
        o.push('\n');
    }

    o.push_str("WHO TALKS TO WHOM\n\n");
    for e in &run.edges {
        let line = format!(
            "{} -> {}: {} ({}, {} bytes, {} to {})",
            e.src,
            e.dst,
            e.protocol,
            plural(e.conns as usize, "connection", "connections"),
            e.bytes,
            timefmt::utc(e.first),
            timefmt::utc(e.last)
        );
        let _ = writeln!(o, "{}", wrap(&line, W, "  ", "    "));
    }
    o.push('\n');

    if !run.shared_macs.is_empty() {
        o.push_str("SHARED MAC ADDRESSES\n\n");
        let note =
            "Each of these MACs carried several IP addresses or internet traffic, which almost \
                    always means a router or firewall. Devices behind it can't be identified \
                    by MAC from this capture point.";
        let _ = writeln!(o, "{}\n", wrap(note, W, "  ", "  "));
        for s in &run.shared_macs {
            let line = format!(
                "{}{}: {}",
                s.mac,
                s.vendor
                    .as_ref()
                    .map(|v| format!(" ({v})"))
                    .unwrap_or_default(),
                s.ips.join(", ")
            );
            let _ = writeln!(o, "{}", wrap(&line, W, "  ", "    "));
        }
        o.push('\n');
    }

    o.push_str("HOW THIS WAS MADE\n\n");
    let method = "otinv read the zeek logs listed below and applied fixed rules; the same \
                  logs always give the same report. Roles are inferred from traffic: a device \
                  that answers an industrial protocol is a controller, one that starts those \
                  conversations is an HMI/SCADA, one that programs or configures controllers is \
                  an engineering workstation. Devices that stayed silent during the capture \
                  aren't listed. User names and passwords were removed while the logs were read \
                  and are not in any output.";
    let _ = writeln!(o, "{}\n", wrap(method, W, "  ", "  "));
    for l in &run.logs {
        let _ = writeln!(
            o,
            "  {} ({}, {}{})",
            l.file,
            l.name,
            plural(l.records, "line", "lines"),
            super::skipped_note(l.skipped)
        );
    }
    o
}

pub fn evidence_line(e: &crate::model::Evidence) -> String {
    let mut s = format!("{}:{}", e.file, e.line);
    if let Some(t) = e.ts {
        let _ = write!(s, " {}", timefmt::utc(t));
    }
    match (&e.src, &e.dst) {
        (Some(a), Some(b)) => {
            let _ = write!(s, " {a} -> {b}");
        }
        (Some(a), None) => {
            let _ = write!(s, " {a}");
        }
        _ => {}
    }
    let _ = write!(s, " {}", e.what);
    if let Some(u) = &e.uid {
        let _ = write!(s, " [uid {u}]");
    }
    s
}

/// What changed since the previous run.
pub fn diff(old: &Run, new: &Run, d: &RunDiff) -> String {
    let mut o = String::new();
    header(&mut o, new, "OTINV CHANGES");
    let _ = writeln!(o, "Previous run made: {}", old.generated);
    let _ = writeln!(
        o,
        "{}\n",
        wrap(&format!("Previous traffic: {}", period(old)), W, "", "  ")
    );
    if d.is_empty() {
        o.push_str("Nothing changed: same devices, same conversations, same findings.\n");
        return o;
    }
    let section = |o: &mut String, name: &str, items: Vec<String>| {
        if items.is_empty() {
            return;
        }
        let _ = writeln!(o, "{name} ({})", items.len());
        for i in items {
            let _ = writeln!(o, "{}", wrap(&i, W, "  - ", "    "));
        }
        o.push('\n');
    };
    section(
        &mut o,
        "NEW DEVICES",
        d.new_assets.iter().map(|a| a.describe()).collect(),
    );
    section(
        &mut o,
        "DEVICES NOT SEEN THIS TIME",
        d.gone_assets
            .iter()
            .map(|a| {
                format!(
                    "{} (may just have been quiet during this capture)",
                    a.describe()
                )
            })
            .collect(),
    );
    section(
        &mut o,
        "CHANGED DEVICES",
        d.changed
            .iter()
            .map(|c| format!("{}: {}", who(new, &c.ip), c.what.join("; ")))
            .collect(),
    );
    section(
        &mut o,
        "NEW PROBLEMS",
        d.new_findings.iter().map(|f| describe(new, f)).collect(),
    );
    section(
        &mut o,
        "PROBLEMS NO LONGER SEEN",
        d.resolved_findings
            .iter()
            .map(|f| describe(old, f))
            .collect(),
    );
    section(
        &mut o,
        "NEW CONVERSATIONS",
        d.new_edges
            .iter()
            .map(|e| {
                format!(
                    "{} -> {}: {}",
                    who(new, &e.src),
                    who(new, &e.dst),
                    e.protocol
                )
            })
            .collect(),
    );
    section(
        &mut o,
        "CONVERSATIONS NOT SEEN THIS TIME",
        d.gone_edges
            .iter()
            .map(|e| {
                format!(
                    "{} -> {}: {}",
                    who(old, &e.src),
                    who(old, &e.dst),
                    e.protocol
                )
            })
            .collect(),
    );
    o
}
