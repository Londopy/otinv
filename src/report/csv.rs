// the asset inventory (FR-14) and the communication list as CSV.
//
// column names follow the language of CISA's asset-inventory guidance (role,
// OT or IT, make/model, firmware, network address, communication) so the file
// can be handed to an inspector or insurer as-is. README explains each column.

use crate::model::Run;
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
        ];
        out.push_str(&csv_line(&row));
        out.push('\n');
    }
    out
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
