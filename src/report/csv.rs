// the asset inventory (FR-14) and the communication list as CSV.
//
// column names follow the language of CISA's asset-inventory guidance (role,
// OT or IT, make/model, firmware, network address, communication) so the file
// can be handed to an inspector or insurer as-is. README explains each column.

use crate::model::{Evidence, Run};
use crate::timefmt;
use crate::util::csv_line;

pub const INVENTORY_COLUMNS: &[&str] = &[
    "ip_address",
    "name",
    "role",
    "ot_or_it",
    "mac_address",
    "mac_vendor",
    "hostname",
    "make_model",
    "firmware_revision",
    "serial_number",
    "device_type",
    "protocols_served",
    "protocols_used",
    "talks_with",
    "first_seen_utc",
    "last_seen_utc",
    "open_findings",
    "role_basis",
    "location",
    "drawings",
    "config_backup",
    "tools",
    "configured_from",
];

pub fn inventory(run: &Run) -> String {
    let mut out = csv_line(INVENTORY_COLUMNS);
    out.push('\n');
    for a in &run.assets {
        let findings: Vec<&str> = run
            .findings
            .iter()
            .filter(|f| f.host == a.ip)
            .map(|f| f.rule.as_str())
            .collect();
        let basis: Vec<String> = a
            .reasons
            .iter()
            .map(|r| format!("{}: {}", r.role.short(), r.what))
            .collect();
        let id = |k: &str| a.identity.get(k).cloned().unwrap_or_default();
        let row = [
            a.ip.clone(),
            a.name.clone(),
            a.role.label().to_string(),
            if a.role.is_ot() { "OT" } else { "IT" }.to_string(),
            a.mac.clone().unwrap_or_default(),
            a.vendor.clone().unwrap_or_default(),
            a.hostnames.join("; "),
            a.make_model(),
            id("firmware"),
            id("serial"),
            id("device type"),
            a.serves.iter().cloned().collect::<Vec<_>>().join("; "),
            a.uses.iter().cloned().collect::<Vec<_>>().join("; "),
            a.peers.to_string(),
            timefmt::utc(a.first_seen),
            timefmt::utc(a.last_seen),
            findings.join("; "),
            basis.join("; "),
            a.details.location.clone(),
            a.details.drawings.clone(),
            a.details.config_backup.clone(),
            a.details.tools.clone(),
            a.configured_from
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        ];
        out.push_str(&csv_line(&row));
        out.push('\n');
    }
    out
}

/// Every log line behind every finding, with a Wireshark filter that finds
/// its packet.
pub fn evidence(run: &Run) -> String {
    let mut out = csv_line(&[
        "finding",
        "severity",
        "device",
        "log_file",
        "log_line",
        "frame",
        "time_utc",
        "from",
        "to",
        "what",
        "zeek_uid",
        "wireshark_filter",
    ]);
    out.push('\n');
    for f in &run.findings {
        for e in &f.evidence {
            let row = [
                f.rule.clone(),
                f.severity.label().to_string(),
                f.host.clone(),
                e.file.clone(),
                e.line.to_string(),
                e.frame.map(|n| n.to_string()).unwrap_or_default(),
                e.ts.map(timefmt::utc).unwrap_or_default(),
                e.src.clone().unwrap_or_default(),
                e.dst.clone().unwrap_or_default(),
                e.what.clone(),
                e.uid.clone().unwrap_or_default(),
                wireshark_filter(e, run.pseudonymized),
            ];
            out.push_str(&csv_line(&row));
            out.push('\n');
        }
    }
    out
}

/// `frame.number == 412` when the packet is known, else the conversation
/// (both addresses and ports) from that time on. Aliases aren't addresses,
/// so a pseudonymized run only gets the frame form.
fn wireshark_filter(e: &Evidence, pseudonymized: bool) -> String {
    if let Some(n) = e.frame {
        return format!("frame.number == {n}");
    }
    let (Some(src), Some(dst), Some((sp, dp)), false) =
        (e.src.as_deref(), e.dst.as_deref(), e.ports, pseudonymized)
    else {
        return String::new();
    };
    let ip = if src.contains(':') { "ipv6" } else { "ip" };
    let mut f = format!(
        "{ip}.addr == {src} && {ip}.addr == {dst} && \
         ((tcp.port == {sp} && tcp.port == {dp}) || (udp.port == {sp} && udp.port == {dp}))"
    );
    if let Some(t) = e.ts {
        // to the microsecond, rounded down: zeek's time is the packet's
        f.push_str(&format!(
            " && frame.time_epoch >= {:.6}",
            (t * 1e6).floor() / 1e6
        ));
    }
    f
}

pub fn comms(run: &Run) -> String {
    let role = |ip: &str| {
        run.asset(ip)
            .map(|a| a.role.short().to_string())
            .unwrap_or_else(|| "Internet".into())
    };
    let mut out = csv_line(&[
        "source",
        "source_role",
        "destination",
        "destination_role",
        "protocol",
        "connections",
        "bytes",
        "first_seen_utc",
        "last_seen_utc",
    ]);
    out.push('\n');
    for e in &run.edges {
        let row = [
            e.src.clone(),
            role(&e.src),
            e.dst.clone(),
            role(&e.dst),
            e.protocol.clone(),
            e.conns.to_string(),
            e.bytes.to_string(),
            timefmt::utc(e.first),
            timefmt::utc(e.last),
        ];
        out.push_str(&csv_line(&row));
        out.push('\n');
    }
    out
}
