// the HTML appendix and diff: one self-contained file each, no scripts, no
// fonts, no network requests, so they open the same on an air-gapped laptop.

use super::{
    actions, describe, device_counts, device_facts, evidence_count, period, severity_counts, title,
    who, SENSITIVE, SHOWN_EVIDENCE,
};
use crate::config::Severity;
use crate::diff::RunDiff;
use crate::model::{Finding, Run};
use crate::timefmt;
use crate::util::{english_list, html, plural};
use std::fmt::Write;

const CSS: &str = r#"
:root { --bg:#ffffff; --fg:#1b1f24; --muted:#5b6470; --line:#d8dde3; --card:#f5f7f9;
  --crit:#b3261e; --high:#c2410c; --med:#a16207; --low:#2563eb; --info:#4b5563;
  --node:#eef2f6; --edge:#8a96a3; --flag:#b3261e; --banner:#fde8e7; }
@media (prefers-color-scheme: dark) { :root { --bg:#14171b; --fg:#e6e9ed; --muted:#9aa4af;
  --line:#2c333b; --card:#1c2127; --crit:#f2867f; --high:#fb923c; --med:#facc15;
  --low:#7aa7ff; --info:#9ca3af; --node:#232a32; --edge:#6b7682; --flag:#f2867f;
  --banner:#3a1d1b; } }
* { box-sizing:border-box; }
body { margin:0; padding:24px 16px 48px; background:var(--bg); color:var(--fg);
  font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { max-width:1100px; margin:0 auto; }
h1 { font-size:1.6rem; margin:.2em 0; } h2 { margin-top:2em; border-bottom:1px solid var(--line);
  padding-bottom:.2em; } h3 { margin-bottom:.3em; }
.banner { background:var(--banner); border:1px solid var(--crit); color:var(--fg);
  padding:8px 12px; border-radius:6px; font-weight:600; }
.meta { color:var(--muted); font-size:.92rem; }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px;
  padding:12px 16px; margin:12px 0; }
.sev { display:inline-block; font-size:.75rem; font-weight:700; letter-spacing:.04em;
  padding:1px 7px; border-radius:4px; color:var(--bg); vertical-align:middle; }
.sev.critical { background:var(--crit); } .sev.high { background:var(--high); }
.sev.medium { background:var(--med); } .sev.low { background:var(--low); }
.sev.info { background:var(--info); }
ol.actions > li { margin-bottom:.9em; } .do { font-weight:600; }
.scroll { overflow-x:auto; }
table { border-collapse:collapse; width:100%; font-size:.88rem; }
th, td { text-align:left; border-bottom:1px solid var(--line); padding:5px 8px; vertical-align:top; }
th { color:var(--muted); font-weight:600; }
code, .mono { font-family:ui-monospace,Consolas,monospace; font-size:.85em; }
details summary { cursor:pointer; color:var(--muted); }
svg.map { width:100%; height:auto; min-width:640px; }
svg.map .node rect { fill:var(--node); stroke:var(--edge); }
svg.map .node.flagged rect { stroke:var(--flag); stroke-width:2.5; }
svg.map text { fill:var(--fg); font-size:12px; font-family:system-ui,sans-serif; }
svg.map .colhead { fill:var(--muted); font-weight:600; }
svg.map .edge { fill:none; stroke:var(--edge); opacity:.8; }
svg.map .arrowhead { fill:var(--edge); }
"#;

fn sev(s: Severity) -> String {
    format!(
        "<span class=\"sev {}\">{}</span>",
        s.label().to_ascii_lowercase(),
        s.label()
    )
}

fn page(title_text: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex\">\
         <title>{}</title><style>{CSS}</style></head><body><main>{body}</main></body></html>\n",
        html(title_text)
    )
}

fn header(o: &mut String, run: &Run, heading: &str) {
    let _ = write!(o, "<p class=\"banner\">{}</p>", html(SENSITIVE));
    let _ = write!(o, "<h1>{}: {}</h1>", html(heading), html(&title(run)));
    let _ = write!(
        o,
        "<p class=\"meta\">Traffic covered: {}<br>Made: {} by otinv {}",
        html(&period(run)),
        html(&run.generated),
        html(&run.tool_version)
    );
    if run.pseudonymized {
        o.push_str("<br>Addresses and names are replaced with aliases (pseudonymized).");
    }
    o.push_str("</p>");
}

fn evidence_table(o: &mut String, f: &Finding) {
    let _ = write!(
        o,
        "<details><summary>Evidence ({})</summary><div class=\"scroll\"><table>\
         <tr><th>Source</th><th>Frame</th><th>Time</th><th>From</th><th>To</th><th>What</th>\
         <th>Zeek uid</th></tr>",
        html(&evidence_count(f))
    );
    for e in f.evidence.iter().take(SHOWN_EVIDENCE) {
        let _ = write!(
            o,
            "<tr><td class=\"mono\">{}:{}</td><td class=\"mono\">{}</td><td>{}</td>\
             <td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td>\
             <td class=\"mono\">{}</td></tr>",
            html(&e.file),
            e.line,
            e.frame.map(|n| n.to_string()).unwrap_or_default(),
            e.ts.map(timefmt::utc).unwrap_or_default(),
            html(e.src.as_deref().unwrap_or("")),
            html(e.dst.as_deref().unwrap_or("")),
            html(&e.what),
            html(e.uid.as_deref().unwrap_or(""))
        );
    }
    o.push_str("</table></div></details>");
}

pub fn appendix(run: &Run) -> String {
    let mut o = String::new();
    header(&mut o, run, "otinv report");

    // the one-pager first, so the HTML stands on its own
    o.push_str("<h2>What is on the network</h2>");
    let _ = write!(
        o,
        "<p>{} seen: {}.",
        plural(run.assets.len(), "device", "devices"),
        if run.assets.is_empty() {
            "none".into()
        } else {
            html(&device_counts(run))
        }
    );
    if !run.externals.is_empty() {
        let _ = write!(
            o,
            " They talked to {} on the internet.",
            plural(run.externals.len(), "address", "addresses")
        );
    }
    if !run.findings.is_empty() {
        let _ = write!(
            o,
            " {} ({}).",
            plural(run.findings.len(), "problem found", "problems found"),
            severity_counts(&run.findings)
        );
    }
    o.push_str("</p>");

    let acts = actions(run);
    o.push_str("<h2>What to fix first</h2>");
    if acts.is_empty() {
        o.push_str(
            "<p>otinv's checks found nothing to fix. That doesn't prove the network is safe: \
             otinv only sees what was on the wire during the capture.</p>",
        );
    } else {
        o.push_str("<ol class=\"actions\">");
        for a in acts.iter().take(5) {
            let lines: Vec<String> = a
                .findings
                .iter()
                .take(3)
                .map(|f| html(&describe(run, f)))
                .collect();
            let more = if a.findings.len() > 3 {
                format!(
                    " &hellip;and {}.",
                    plural(a.findings.len() - 3, "more device", "more devices")
                )
            } else {
                String::new()
            };
            let _ = write!(
                o,
                "<li>{} <strong>{}</strong><br>{}{more}<br><span class=\"do\">Do this:</span> {}</li>",
                sev(a.severity),
                html(&a.rule.title),
                lines.join(" "),
                html(&a.rule.action)
            );
        }
        o.push_str("</ol>");
    }

    o.push_str("<h2>Communication map</h2>");
    o.push_str(
        "<p class=\"meta\">Arrows point from the device that started the conversation. \
         Devices with findings have a red outline. Hover for details. The same map is in \
         comms.dot (Graphviz) and comms.mmd (Mermaid).</p>",
    );
    let _ = write!(o, "<div class=\"scroll\">{}</div>", super::map::svg(run));

    o.push_str("<h2>Findings</h2>");
    if run.findings.is_empty() {
        o.push_str("<p>None.</p>");
    }
    for a in &acts {
        let _ = write!(
            o,
            "<div class=\"card\"><h3>{} {} <span class=\"meta mono\">{}</span></h3>\
             <p><strong>Why it matters:</strong> {}</p><p><span class=\"do\">Do this:</span> {}</p>",
            sev(a.severity),
            html(&a.rule.title),
            html(&a.rule.id),
            html(&a.rule.why),
            html(&a.rule.action)
        );
        if !a.rule.cpg.is_empty() {
            let _ = write!(
                o,
                "<p class=\"meta\">CISA CPG 2.0: {}</p>",
                html(&a.rule.cpg)
            );
        }
        for f in &a.findings {
            let _ = write!(o, "<p>{} {}</p>", sev(f.severity), html(&describe(run, f)));
            evidence_table(&mut o, f);
        }
        o.push_str("</div>");
    }

    o.push_str(
        "<h2>Asset inventory</h2><div class=\"scroll\"><table><tr><th>Address</th><th>Role</th>\
                <th>Name</th><th>MAC / vendor</th><th>Make, model, firmware</th><th>Answers</th>\
                <th>Uses</th><th>Seen</th><th>Why this role</th></tr>",
    );
    for a in &run.assets {
        let ident: Vec<String> = a
            .identity
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .chain(device_facts(run, a))
            .collect();
        let why: Vec<String> = a
            .reasons
            .iter()
            .map(|r| {
                let peer = r
                    .peer
                    .as_deref()
                    .map(|p| format!(" ({})", html(&who(run, p))))
                    .unwrap_or_default();
                format!(
                    "{}: {}{peer} <span class=\"mono\">[{}:{}]</span>",
                    html(r.role.short()),
                    html(&r.what),
                    html(&r.evidence.file),
                    r.evidence.line
                )
            })
            .collect();
        let list = |s: &std::collections::BTreeSet<String>| {
            html(&s.iter().cloned().collect::<Vec<_>>().join(", "))
        };
        let names: Vec<String> = std::iter::once(a.name.clone())
            .chain(a.hostnames.iter().cloned())
            .filter(|n| !n.is_empty())
            .collect();
        let _ = write!(
            o,
            "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}<br>{}</td>\
             <td>{}</td><td>{}</td><td>{}</td><td>{}<br>{}</td><td>{}</td></tr>",
            html(&a.ip),
            html(a.role.label()),
            html(&names.join(", ")),
            html(a.mac.as_deref().unwrap_or("")),
            html(a.vendor.as_deref().unwrap_or("")),
            html(&ident.join("; ")),
            list(&a.serves),
            list(&a.uses),
            timefmt::utc(a.first_seen),
            timefmt::utc(a.last_seen),
            why.join("<br>")
        );
    }
    o.push_str("</table></div>");

    if !run.externals.is_empty() {
        o.push_str(
            "<h2>Internet addresses</h2><div class=\"scroll\"><table><tr><th>Address</th>\
                    <th>Protocols</th><th>Local devices</th></tr>",
        );
        for e in &run.externals {
            let peers: Vec<String> = e.peers.iter().map(|p| who(run, p)).collect();
            let protos: Vec<String> = e.protocols.iter().cloned().collect();
            let _ = write!(
                o,
                "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td></tr>",
                html(&e.ip),
                html(&english_list(&protos, 8)),
                html(&english_list(&peers, 8))
            );
        }
        o.push_str("</table></div>");
    }

    o.push_str("<h2>Who talks to whom</h2><div class=\"scroll\"><table><tr><th>From</th><th>To</th>\
                <th>Protocol</th><th>Connections</th><th>Bytes</th><th>First</th><th>Last</th></tr>");
    for e in &run.edges {
        let _ = write!(
            o,
            "<tr><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td><td>{}</td>\
             <td>{}</td><td>{}</td><td>{}</td></tr>",
            html(&e.src),
            html(&e.dst),
            html(&e.protocol),
            e.conns,
            e.bytes,
            timefmt::utc(e.first),
            timefmt::utc(e.last)
        );
    }
    o.push_str("</table></div>");

    if !run.shared_macs.is_empty() {
        o.push_str(
            "<h2>Shared MAC addresses</h2><p>Each of these MACs carried several IP \
             addresses or internet traffic, which almost always means a router or firewall. Devices behind it \
             can't be identified by MAC from this capture point.</p><ul>",
        );
        for s in &run.shared_macs {
            let _ = write!(
                o,
                "<li><span class=\"mono\">{}</span> {}: <span class=\"mono\">{}</span></li>",
                html(&s.mac),
                html(s.vendor.as_deref().unwrap_or("")),
                html(&s.ips.join(", "))
            );
        }
        o.push_str("</ul>");
    }

    o.push_str(
        "<h2>How this was made</h2><p>otinv read the zeek logs below and applied fixed rules; \
         the same logs always give the same report. Roles are inferred from traffic: a device \
         that answers an industrial protocol is a controller, one that starts those \
         conversations is an HMI/SCADA, one that programs or configures controllers is an \
         engineering workstation. Devices that stayed silent during the capture aren't listed. \
         User names and passwords were removed while the logs were read and are not in any \
         output. otinv only listened: it sent nothing to any device.</p><ul>",
    );
    for l in &run.logs {
        let _ = write!(
            o,
            "<li><span class=\"mono\">{}</span> ({}, {}{})</li>",
            html(&l.file),
            html(&l.name),
            plural(l.records, "line", "lines"),
            super::skipped_note(l.skipped)
        );
    }
    o.push_str("</ul>");
    page(&format!("otinv report: {}", title(run)), &o)
}

pub fn diff(old: &Run, new: &Run, d: &RunDiff) -> String {
    let mut o = String::new();
    header(&mut o, new, "otinv changes");
    let _ = write!(
        o,
        "<p class=\"meta\">Previous run made {}; its traffic covered {}.</p>",
        html(&old.generated),
        html(&period(old))
    );
    if d.is_empty() {
        o.push_str("<p>Nothing changed: same devices, same conversations, same findings.</p>");
        return page("otinv changes", &o);
    }
    let section = |o: &mut String, name: &str, items: Vec<String>| {
        if items.is_empty() {
            return;
        }
        let _ = write!(o, "<h2>{} ({})</h2><ul>", html(name), items.len());
        for i in items {
            let _ = write!(o, "<li>{}</li>", html(&i));
        }
        o.push_str("</ul>");
    };
    section(
        &mut o,
        "New devices",
        d.new_assets.iter().map(|a| a.describe()).collect(),
    );
    section(
        &mut o,
        "Devices not seen this time",
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
        "Changed devices",
        d.changed
            .iter()
            .map(|c| format!("{}: {}", who(new, &c.ip), c.what.join("; ")))
            .collect(),
    );
    section(
        &mut o,
        "New problems",
        d.new_findings.iter().map(|f| describe(new, f)).collect(),
    );
    section(
        &mut o,
        "Problems no longer seen",
        d.resolved_findings
            .iter()
            .map(|f| describe(old, f))
            .collect(),
    );
    section(
        &mut o,
        "New conversations",
        d.new_edges
            .iter()
            .map(|e| {
                format!(
                    "{} \u{2192} {}: {}",
                    who(new, &e.src),
                    who(new, &e.dst),
                    e.protocol
                )
            })
            .collect(),
    );
    section(
        &mut o,
        "Conversations not seen this time",
        d.gone_edges
            .iter()
            .map(|e| {
                format!(
                    "{} \u{2192} {}: {}",
                    who(old, &e.src),
                    who(old, &e.dst),
                    e.protocol
                )
            })
            .collect(),
    );
    page("otinv changes", &o)
}
