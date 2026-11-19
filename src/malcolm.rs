// Malcolm exports: what its /mapi/document API returns (a JSON object with a
// `results` array of OpenSearch hits), saved to a file, or the documents one
// per line (NDJSON). Malcolm's Logstash pipeline renames most zeek fields to
// ECS names (id.orig_h -> source.ip, service -> network.protocol, ...); each
// document is mapped back to the zeek record the log reader would have made,
// so everything after this point can't tell the two inputs apart. The
// mapping follows logstash/pipelines/zeek/ in cisagov/Malcolm v26.10.0.

use crate::zeek::{next_line, Format, Log, Record, MAX_LINE};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

/// A .json file is parsed whole, so it gets a tighter cap than NDJSON, which
/// is read a line at a time. One API page is a few MB.
const MAX_JSON_MB: u64 = 64;

/// (zeek field, Malcolm document field) for fields every log shares.
const COMMON: &[(&str, &str)] = &[
    ("uid", "zeek.uid"),
    ("id.orig_h", "source.ip"),
    ("id.orig_p", "source.port"),
    ("id.resp_h", "destination.ip"),
    ("id.resp_p", "destination.port"),
    ("orig_l2_addr", "source.mac"),
    ("resp_l2_addr", "destination.mac"),
    ("proto", "network.transport"),
    ("service", "network.protocol"),
    ("is_orig", "network.is_orig"),
];

/// ICSNPP logs record each packet's own direction (source_h is the sender,
/// is_orig says whether that's the client), and Malcolm keeps that in
/// source.* / destination.* instead of the connection's id.*.
const PACKET_DIRECTION: &[(&str, &str)] = &[
    ("source_h", "source.ip"),
    ("source_p", "source.port"),
    ("destination_h", "destination.ip"),
    ("destination_p", "destination.port"),
];

fn per_log(dataset: &str) -> &'static [(&'static str, &'static str)] {
    match dataset {
        "conn" => &[
            ("duration", "zeek.conn.duration"),
            ("orig_bytes", "zeek.conn.orig_bytes"),
            ("resp_bytes", "zeek.conn.resp_bytes"),
            ("conn_state", "zeek.conn.conn_state"),
            ("history", "zeek.conn.history"),
            ("resp_pkts", "zeek.conn.resp_pkts"),
        ],
        "modbus" => &[
            ("func", "zeek.modbus.func"),
            ("pdu_type", "zeek.modbus.network_direction"),
        ],
        "dnp3" => &[
            ("fc_request", "zeek.dnp3.fc_request"),
            ("fc_reply", "zeek.dnp3.fc_reply"),
        ],
        // Malcolm moves the credentials to related.*; they only become
        // "a login happened" markers, like in a zeek log
        "ftp" => &[("user", "related.user"), ("password", "related.password")],
        "http" => &[
            ("username", "related.user"),
            ("password", "related.password"),
        ],
        "dhcp" => &[
            ("host_name", "zeek.dhcp.host_name"),
            ("client_fqdn", "zeek.dhcp.client_fqdn"),
            ("assigned_addr", "zeek.dhcp.assigned_ip"),
            ("client_addr", "source.ip"),
            ("mac", "zeek.dhcp.mac"),
        ],
        "cip_identity" => &[
            ("socket_address", "zeek.cip_identity.socket_address"),
            ("vendor_id", "zeek.cip_identity.vendor_id"),
            ("vendor_name", "zeek.cip_identity.vendor_name"),
            ("product_name", "zeek.cip_identity.product_name"),
            ("device_type_name", "zeek.cip_identity.device_type_name"),
            ("device_type_id", "zeek.cip_identity.device_type_id"),
            ("product_code", "zeek.cip_identity.product_code"),
            ("revision", "zeek.cip_identity.revision"),
            ("serial_number", "zeek.cip_identity.serial_number"),
        ],
        "modbus_read_device_identification" => &[
            (
                "object_id_code",
                "zeek.modbus_read_device_identification.object_id_code",
            ),
            (
                "object_id",
                "zeek.modbus_read_device_identification.object_id",
            ),
            (
                "object_value",
                "zeek.modbus_read_device_identification.object_value",
            ),
        ],
        _ => &[],
    }
}

/// Looks up "a.b.c" in a document, as nested objects or as a literal dotted key.
fn field<'a>(doc: &'a Value, path: &str) -> Option<&'a Value> {
    if let Some(v) = doc.get(path) {
        return Some(v);
    }
    path.split('.').try_fold(doc, |v, key| v.get(key))
}

fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(if *b { "T" } else { "F" }.to_string()),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().filter_map(as_text).collect();
            (!parts.is_empty()).then(|| parts.join(","))
        }
        _ => None,
    }
}

/// Seconds since the epoch: `timestamp` and `firstPacket` are milliseconds,
/// `@timestamp` is ISO 8601.
fn timestamp(doc: &Value) -> Option<String> {
    for key in ["timestamp", "firstPacket"] {
        if let Some(ms) = field(doc, key).and_then(Value::as_f64) {
            return Some(format!("{:.3}", ms / 1000.0));
        }
    }
    field(doc, "@timestamp").and_then(as_text)
}

/// The zeek log a document came from, or None for anything otinv doesn't
/// read: Arkime sessions, Suricata alerts, and conn_long records (Malcolm
/// files those under conn; the final conn record already counts the
/// connection once).
fn dataset(doc: &Value) -> Option<String> {
    if field(doc, "event.provider").and_then(as_text).as_deref() != Some("zeek") {
        return None;
    }
    let ds = field(doc, "event.dataset").and_then(as_text)?;
    let ds = ds.split(',').next().unwrap_or_default().to_string();
    let long = field(doc, "zeek.conn.long").and_then(as_text);
    if ds == "conn" && matches!(long.as_deref(), Some("true" | "T")) {
        return None;
    }
    crate::zeek::is_used(&ds).then_some(ds)
}

fn record(doc: &Value, dataset: &str, line: usize) -> Record {
    let mut pairs: Vec<(&str, String)> = Vec::new();
    if let Some(ts) = timestamp(doc) {
        pairs.push(("ts", ts));
    }
    let direction: &[(&str, &str)] = if field(doc, "network.is_orig").is_some() {
        PACKET_DIRECTION
    } else {
        &[]
    };
    for (zeek, malcolm) in COMMON.iter().chain(direction).chain(per_log(dataset)) {
        if let Some(mut v) = field(doc, malcolm).and_then(as_text) {
            // Malcolm lowercases zeek's REQ/RESP into request/response
            if *zeek == "pdu_type" {
                v = match v.as_str() {
                    "request" => "REQ".into(),
                    "response" => "RESP".into(),
                    _ => v,
                };
            }
            pairs.push((zeek, v));
        }
    }
    let borrowed: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    Record::from_pairs(line, &borrowed)
}

/// Collects documents from every export file into zeek logs, and keeps track
/// of what a careful reader of the pages would want to know.
#[derive(Default)]
struct Sink {
    logs: BTreeMap<(String, String), Log>,
    seen_ids: BTreeSet<String>,
    duplicates: usize,
    hits: usize,
    total: u64,
    warnings: Vec<String>,
}

impl Sink {
    fn hit(&mut self, file: &str, number: usize, hit: Value) {
        let mut hit = hit;
        if let Some(id) = hit.get("_id").and_then(Value::as_str) {
            if !self.seen_ids.insert(id.to_string()) {
                self.duplicates += 1;
                return;
            }
        }
        self.hits += 1;
        let doc = match hit.get_mut("_source") {
            Some(source) => source.take(),
            None => hit,
        };
        let Some(ds) = dataset(&doc) else { return };
        let rec = record(&doc, &ds, number);
        // keyed by log type first, so pages of one export read in log order
        let log = self
            .logs
            .entry((ds.clone(), file.to_string()))
            .or_insert_with(|| Log {
                name: ds.clone(),
                file: file.to_string(),
                format: Format::Json,
                records: Vec::new(),
                skipped: 0,
            });
        log.records.push(rec);
    }

    /// One /mapi/document response: its hits, plus a warning when the
    /// search behind it didn't finish.
    fn page(&mut self, file: &str, page: Value) {
        let Value::Object(mut page) = page else {
            return;
        };
        if let Some(err) = page.get("error") {
            self.warnings
                .push(format!("{file} is an error response, not documents: {err}"));
        }
        let failed = page
            .get("shards")
            .and_then(|s| s.get("failed"))
            .and_then(Value::as_u64);
        if page.get("timed_out").and_then(Value::as_bool) == Some(true) || failed.unwrap_or(0) > 0 {
            self.warnings.push(format!(
                "{file}: Malcolm's search timed out or failed on some shards, so the page may be incomplete"
            ));
        }
        let total = page
            .get("total")
            .and_then(|t| t.get("value").or(Some(t)))
            .and_then(Value::as_u64);
        self.total = self.total.max(total.unwrap_or(0));
        if let Some(Value::Array(hits)) = page.remove("results") {
            for (i, hit) in hits.into_iter().enumerate() {
                self.hit(file, i + 1, hit);
            }
        }
    }

    fn value(&mut self, file: &str, number: usize, v: Value) {
        match v {
            Value::Object(ref o) if o.contains_key("results") => self.page(file, v),
            Value::Array(items) => {
                for (i, item) in items.into_iter().enumerate() {
                    self.hit(file, i + 1, item);
                }
            }
            other => self.hit(file, number, other),
        }
    }
}

/// Opens an export, refusing UTF-16 (what PowerShell 5's `>` writes) and
/// skipping a UTF-8 byte order mark.
fn open(path: &Path) -> Result<BufReader<std::fs::File>> {
    let file = std::fs::File::open(path).with_context(|| format!("Opening {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let head = reader.fill_buf()?;
    if head.starts_with(&[0xFF, 0xFE]) || head.starts_with(&[0xFE, 0xFF]) {
        bail!(
            "{} is UTF-16; save the export as UTF-8 (in PowerShell: Out-File -Encoding utf8)",
            path.display()
        );
    }
    if head.starts_with(&[0xEF, 0xBB, 0xBF]) {
        reader.consume(3);
    }
    Ok(reader)
}

fn read_file(path: &Path, sink: &mut Sink, max_mb: u64) -> Result<()> {
    let ndjson = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("ndjson"));
    let limit = if ndjson {
        max_mb
    } else {
        max_mb.min(MAX_JSON_MB)
    };
    let mb = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) / (1024 * 1024);
    if mb > limit {
        bail!(
            "{} is {mb} MB, over the {limit} MB limit{}",
            path.display(),
            if ndjson {
                "; raise --max-log-mb if this really is the right export"
            } else {
                ". Save big exports as smaller pages, or as NDJSON (one document per line)"
            }
        );
    }
    let file = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut reader = open(path)?;
    if !ndjson {
        let mut text = String::new();
        reader
            .read_to_string(&mut text)
            .with_context(|| format!("Reading {}", path.display()))?;
        // one JSON value (an API response or an array); otherwise NDJSON
        if let Ok(v) = serde_json::from_str::<Value>(&text) {
            sink.value(&file, 1, v);
            return Ok(());
        }
        return lines(&mut text.as_bytes(), &file, sink)
            .with_context(|| format!("In {}", path.display()));
    }
    lines(&mut reader, &file, sink).with_context(|| format!("In {}", path.display()))
}

/// NDJSON, a line at a time with the log reader's line cap.
fn lines(reader: &mut impl BufRead, file: &str, sink: &mut Sink) -> Result<()> {
    let mut buf = Vec::new();
    let mut number = 0;
    while let Some(fits) = next_line(reader, &mut buf)? {
        number += 1;
        if !fits {
            bail!("line {number} is over {} MB", MAX_LINE / (1024 * 1024));
        }
        if buf.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let v: Value = serde_json::from_slice(&buf)
            .with_context(|| format!("line {number} isn't a JSON document"))?;
        sink.value(file, number, v);
    }
    Ok(())
}

/// Whether a file looks like a Malcolm export: .json or .ndjson, with
/// Malcolm's `event.provider` near the start. A zeek log saved as conn.json
/// has no such field.
pub fn is_export(path: &Path) -> bool {
    let json = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("json") || e.eq_ignore_ascii_case("ndjson"));
    if !json {
        return false;
    }
    let mut head = Vec::new();
    let read = std::fs::File::open(path).and_then(|f| f.take(16 * 1024).read_to_end(&mut head));
    read.is_ok() && head.windows(8).any(|w| w == b"provider")
}

/// Sorts page2 before page10.
fn natural_key(p: &Path) -> Vec<(String, u64)> {
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut key = Vec::new();
    let mut text = String::new();
    let mut digits = String::new();
    for c in name.chars().chain(std::iter::once('\0')) {
        if c.is_ascii_digit() {
            digits.push(c);
        } else {
            if !digits.is_empty() {
                key.push((
                    std::mem::take(&mut text),
                    digits.parse().unwrap_or(u64::MAX),
                ));
                digits.clear();
            }
            text.push(c);
        }
    }
    key.push((text, 0));
    key
}

/// Reads one export file, or every export file in a folder (pages of one
/// export), into zeek logs grouped by log type.
pub fn read(path: &Path, max_mb: u64) -> Result<Vec<Log>> {
    let mut files: Vec<PathBuf> = if path.is_dir() {
        std::fs::read_dir(path)
            .with_context(|| format!("Reading {}", path.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file() && is_export(p))
            .collect()
    } else {
        vec![path.to_path_buf()]
    };
    files.sort_by_key(|p| natural_key(p));
    let mut sink = Sink::default();
    for f in &files {
        read_file(f, &mut sink, max_mb)?;
    }
    for w in &sink.warnings {
        eprintln!("otinv: {w}");
    }
    if sink.duplicates > 0 {
        eprintln!(
            "otinv: skipped {} documents that appear in more than one page",
            sink.duplicates
        );
    }
    if (sink.hits as u64) < sink.total {
        eprintln!(
            "otinv: the export holds {} of the {} documents Malcolm matched; fetch the remaining pages",
            sink.hits, sink.total
        );
    }
    let logs: Vec<Log> = sink.logs.into_values().collect();
    if !logs.iter().any(|l| l.name == "conn") {
        bail!(
            "no zeek conn records in {}: export documents with event.provider \"zeek\" \
             (see the README for the /mapi/document request)",
            path.display()
        );
    }
    Ok(logs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sink_of(text: &str) -> Sink {
        let mut sink = Sink::default();
        lines(&mut text.as_bytes(), "t.ndjson", &mut sink).unwrap();
        sink
    }

    #[test]
    fn maps_a_malcolm_conn_document_back_to_zeek_fields() {
        let doc = json!({
            "@timestamp": "2026-11-01T08:00:00.000Z",
            "timestamp": 1793520000500i64,
            "event": {"provider": "zeek", "dataset": "conn"},
            "zeek": {"uid": "C1", "conn": {"history": "ShADadFf", "conn_state": "SF", "orig_bytes": 10, "resp_pkts": 4}},
            "source": {"ip": "10.0.0.5", "port": 49152, "mac": "00:0c:29:00:00:05"},
            "destination": {"ip": "10.0.0.10", "port": 502},
            "network": {"transport": "tcp", "protocol": ["modbus"]}
        });
        assert_eq!(dataset(&doc).as_deref(), Some("conn"));
        let r = record(&doc, "conn", 3);
        assert_eq!(r.line, 3);
        assert_eq!(r.ts(), Some(1_793_520_000.5));
        assert_eq!(r.get("id.orig_h"), Some("10.0.0.5"));
        assert_eq!(r.get("id.resp_p"), Some("502"));
        assert_eq!(r.get("service"), Some("modbus"));
        assert_eq!(r.get("history"), Some("ShADadFf"));
        // only read when there's no history, so no scenario covers it
        assert_eq!(r.get("resp_pkts"), Some("4"));
        assert_eq!(r.get("orig_l2_addr"), Some("00:0c:29:00:00:05"));
        // no is_orig: no packet direction fields
        assert_eq!(r.get("source_h"), None);
    }

    #[test]
    fn modbus_direction_and_dhcp_address_go_back_to_zeek_names() {
        let modbus = json!({"event": {"provider": "zeek", "dataset": "modbus"},
            "zeek": {"modbus": {"func": "READ_COILS", "network_direction": "request"}}});
        assert_eq!(record(&modbus, "modbus", 1).get("pdu_type"), Some("REQ"));
        let dhcp = json!({"event": {"provider": "zeek", "dataset": "dhcp"},
            "zeek": {"dhcp": {"assigned_ip": "10.0.0.5", "client_fqdn": "pc.lab"}}});
        let r = record(&dhcp, "dhcp", 1);
        assert_eq!(r.get("assigned_addr"), Some("10.0.0.5"));
        assert_eq!(r.get("client_fqdn"), Some("pc.lab"));
    }

    #[test]
    fn icsnpp_replies_keep_the_packet_direction() {
        let reply = json!({"event": {"provider": "zeek", "dataset": "modbus_read_device_identification"},
            "network": {"is_orig": false},
            "source": {"ip": "10.0.0.10", "port": 502},
            "destination": {"ip": "10.0.0.7", "port": 40000}});
        let r = record(&reply, "modbus_read_device_identification", 1);
        let (client, server) = crate::analyze::endpoints(&r).unwrap();
        assert_eq!(
            (client.to_string(), server.to_string()),
            ("10.0.0.7".into(), "10.0.0.10".into())
        );
    }

    #[test]
    fn credentials_become_markers() {
        let doc = json!({
            "event": {"provider": "zeek", "dataset": "ftp"},
            "related": {"user": ["admin"], "password": ["hunter2"]},
            "source": {"ip": "10.0.0.5"}, "destination": {"ip": "10.0.0.11"}
        });
        let r = record(&doc, "ftp", 1);
        assert!(r.had("user") && r.had("password"));
        let dump = format!("{r:?}");
        assert!(
            !dump.contains("hunter2") && !dump.contains("admin"),
            "{dump}"
        );
    }

    #[test]
    fn skips_what_otinv_does_not_read() {
        let long = json!({"event": {"provider": "zeek", "dataset": "conn"}, "zeek": {"conn": {"long": "true"}}});
        assert_eq!(dataset(&long), None);
        assert_eq!(dataset(&json!({"event": {"provider": "arkime"}})), None);
        assert_eq!(
            dataset(&json!({"event": {"provider": "zeek", "dataset": "dns"}})),
            None
        );
    }

    #[test]
    fn pages_ndjson_duplicates_and_incomplete_searches() {
        let conn = json!({"event": {"provider": "zeek", "dataset": "conn"}});
        let page = json!({"results": [{"_id": "a", "_source": conn}, {"_id": "b", "_source": conn}],
                          "total": {"value": 5}, "timed_out": true});
        let mut sink = Sink::default();
        sink.value("p1.json", 1, page.clone());
        sink.value("p2.json", 1, page);
        assert_eq!(sink.hits, 2);
        assert_eq!(sink.duplicates, 2);
        assert_eq!(sink.total, 5);
        assert_eq!(sink.warnings.len(), 2);

        // NDJSON: evidence numbers are line numbers, blank lines included
        let sink = sink_of(&format!("{conn}\n\n{conn}\n"));
        let log = sink.logs.values().next().unwrap();
        assert_eq!(
            log.records.iter().map(|r| r.line).collect::<Vec<_>>(),
            [1, 3]
        );
        let mut sink = Sink::default();
        assert!(lines(&mut "{not json\n".as_bytes(), "t", &mut sink).is_err());
    }

    #[test]
    fn dotted_keys_work_too() {
        let doc =
            json!({"source.ip": "10.0.0.5", "event.provider": "zeek", "event.dataset": "conn"});
        assert_eq!(
            field(&doc, "source.ip").and_then(as_text).as_deref(),
            Some("10.0.0.5")
        );
        assert_eq!(dataset(&doc).as_deref(), Some("conn"));
    }

    #[test]
    fn natural_page_order() {
        let mut v = vec![
            PathBuf::from("page10.json"),
            PathBuf::from("page2.json"),
            PathBuf::from("page1.json"),
        ];
        v.sort_by_key(|p| natural_key(p));
        assert_eq!(
            v,
            [
                PathBuf::from("page1.json"),
                PathBuf::from("page2.json"),
                PathBuf::from("page10.json")
            ]
        );
    }
}
