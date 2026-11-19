// reading zeek logs: the default tab-separated format and JSON lines.
//
// credentials never get past this file. only the logs otinv uses are read,
// and of those only the fields on the allow-list below are kept; everything
// else (URLs, cookies, SNMP communities, FTP reply text...) is dropped as each
// line is parsed. user name and password fields leave only a
// `<field>__present` marker saying a value was there. so even a debugger or a
// crash dump can't show what was typed on the wire.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

/// Logs otinv reads. Anything else in the folder is never opened.
const USED_LOGS: &[&str] = &[
    "conn",
    "modbus",
    "dnp3",
    "ftp",
    "http",
    "dhcp",
    "enip_list_identity",
];
const USED_LOG_PREFIXES: &[&str] = &["cip_identity", "modbus_read_device_identification"];

pub fn is_used(name: &str) -> bool {
    USED_LOGS.contains(&name) || USED_LOG_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// The only fields kept. Add a field here when code starts reading it.
const KEPT: &[&str] = &[
    // every log
    "ts",
    "uid",
    "_path",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    // conn
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "history",
    "resp_pkts",
    "orig_l2_addr",
    "resp_l2_addr",
    // modbus, dnp3, and the ICSNPP direction fields
    "func",
    "pdu_type",
    "is_orig",
    "source_h",
    "source_p",
    "destination_h",
    "destination_p",
    "fc_request",
    "fc_reply",
    // dhcp
    "assigned_addr",
    "client_addr",
    "mac",
    "host_name",
    "client_fqdn",
    // ICSNPP identity replies
    "socket_address",
    "vendor_id",
    "vendor_name",
    "product_name",
    "device_type_name",
    "device_type_id",
    "product_code",
    "revision",
    "serial_number",
    "object_id",
    "object_id_code",
    "object_name",
    "object_value",
    "value",
];

/// Credential fields: only "a value was there" is kept. Matching is on the
/// last dotted part of the name, case-insensitive, so `auth.password` counts.
const CREDENTIALS: &[&str] = &["user", "username", "password", "passwd", "pass"];

/// Values zeek uses for "no user given"; these don't count as a login.
const NOT_A_VALUE: &[&str] = &["", "-", "(empty)", "<unknown>"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Tsv,
    Json,
}

/// One log line. Unset fields are simply absent.
#[derive(Debug, Clone, Default)]
pub struct Record {
    /// 1-based line number in the file, for evidence.
    pub line: usize,
    fields: BTreeMap<String, String>,
}

impl Record {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    /// The first of several possible field names that is set. ICSNPP and
    /// stock zeek don't always agree on names.
    pub fn get_any(&self, keys: &[&str]) -> Option<&str> {
        keys.iter().find_map(|k| self.get(k))
    }

    pub fn f64(&self, key: &str) -> Option<f64> {
        self.get(key).and_then(crate::timefmt::parse)
    }

    pub fn u64(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(|v| v.parse().ok())
    }

    pub fn is_true(&self, key: &str) -> bool {
        matches!(self.get(key), Some("T" | "true"))
    }

    /// True when a redacted field had a real value (a user name was sent).
    pub fn had(&self, key: &str) -> bool {
        self.is_true(&format!("{key}__present"))
    }

    pub fn ts(&self) -> Option<f64> {
        self.f64("ts")
    }

    pub fn uid(&self) -> Option<&str> {
        self.get("uid")
    }

    #[cfg(test)]
    pub fn from_pairs(line: usize, pairs: &[(&str, &str)]) -> Self {
        let mut r = Record {
            line,
            ..Default::default()
        };
        for (k, v) in pairs {
            r.set(k, v);
        }
        r
    }

    // the one way in, so redaction can't be skipped
    fn set(&mut self, key: &str, value: &str) {
        let last = key.rsplit('.').next().unwrap_or(key).to_ascii_lowercase();
        if CREDENTIALS.contains(&last.as_str()) {
            if !NOT_A_VALUE.contains(&value) {
                self.fields.insert(format!("{last}__present"), "T".into());
            }
            return;
        }
        if KEPT.contains(&key) {
            self.fields.insert(key.to_string(), value.to_string());
        }
    }
}

#[derive(Debug, Clone)]
pub struct Log {
    /// Log type, e.g. "conn", "modbus", "cip_identity".
    pub name: String,
    /// File name as it appears in evidence.
    pub file: String,
    pub format: Format,
    pub records: Vec<Record>,
    /// Lines that couldn't be used: cut off mid-write, or not valid JSON.
    pub skipped: usize,
}

/// Default for `--max-log-mb`: a month of a small utility's conn.log is far
/// below this; anything bigger is probably the wrong folder.
pub const DEFAULT_MAX_LOG_MB: u64 = 4096;

/// Longest line kept. No zeek log line comes close; a longer one is skipped
/// (and counted) without ever being held in memory.
const MAX_LINE: usize = 1 << 20;

/// Reads the zeek logs otinv uses from a directory (not recursive). Other
/// logs are never opened; compressed ones are skipped with a warning; a file
/// over `max_mb` megabytes is refused.
pub fn read_dir(dir: &Path, max_mb: u64) -> Result<Vec<Log>> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("Reading {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    paths.sort();
    let mut logs = Vec::new();
    for p in paths {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let stem = name.split('.').next().unwrap_or_default();
        if !is_used(stem) && !peek_path(&p).is_some_and(|n| is_used(&n)) {
            continue;
        }
        if name.ends_with(".gz") {
            eprintln!("otinv: skipping {name}: compressed logs aren't read; unzip it first");
            continue;
        }
        if name.ends_with(".log") || name.ends_with(".json") {
            let mb = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0) / (1024 * 1024);
            if mb > max_mb {
                bail!(
                    "{name} is {mb} MB, over the {max_mb} MB limit; raise --max-log-mb if \
                     this really is the right log"
                );
            }
            logs.push(read_file(&p)?);
        }
    }
    if !logs.iter().any(|l| l.name == "conn") {
        bail!(
            "no conn.log in {}; otinv needs zeek's conn.log (plus modbus.log, dnp3.log, \
             dhcp.log and the ICSNPP logs when they exist)",
            dir.display()
        );
    }
    Ok(logs)
}

/// The log type a file declares in its first lines (`#path conn` in TSV,
/// `"_path":"conn"` in JSON), for files not named after their type, like
/// `2026-11-01-conn.log`. Reads at most 8 KiB.
fn peek_path(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut head = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(8192)
        .read_to_end(&mut head)
        .ok()?;
    let text = String::from_utf8_lossy(&head);
    for line in text.lines().take(20) {
        if let Some(rest) = line.strip_prefix("#path") {
            return Some(rest.trim().to_string());
        }
        if line.starts_with('{') {
            let i = line.find("\"_path\"")?;
            let rest = line[i + 7..].trim_start().strip_prefix(':')?.trim_start();
            let rest = rest.strip_prefix('"')?;
            return Some(rest.split('"').next()?.to_string());
        }
    }
    None
}

pub fn read_file(path: &Path) -> Result<Log> {
    let file = std::fs::File::open(path).with_context(|| format!("Opening {}", path.display()))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("log")
        .to_string();
    parse(&name, BufReader::new(file)).with_context(|| format!("Parsing {}", path.display()))
}

/// Reads one line (without the newline) into `buf`, holding at most
/// MAX_LINE bytes. Some(true): a line; Some(false): a line too long, skipped;
/// None: end of input.
fn next_line(r: &mut impl BufRead, buf: &mut Vec<u8>) -> std::io::Result<Option<bool>> {
    buf.clear();
    let mut too_long = false;
    let mut any = false;
    loop {
        let avail = r.fill_buf()?;
        if avail.is_empty() {
            return Ok(any.then_some(!too_long));
        }
        any = true;
        let newline = avail.iter().position(|&b| b == b'\n');
        let chunk = &avail[..newline.unwrap_or(avail.len())];
        if !too_long {
            if buf.len() + chunk.len() > MAX_LINE {
                too_long = true;
                buf.clear();
            } else {
                buf.extend_from_slice(chunk);
            }
        }
        let used = newline.map_or(avail.len(), |i| i + 1);
        r.consume(used);
        if newline.is_some() {
            return Ok(Some(!too_long));
        }
    }
}

/// Parses one log. The format is sniffed from the first non-blank line.
pub fn parse(file_name: &str, mut reader: impl BufRead) -> Result<Log> {
    // "conn.log", "conn.08:00:00-09:00:00.log" and "conn.json" are all "conn"
    let mut name = file_name.split('.').next().unwrap_or(file_name).to_string();
    let mut format = None;
    let mut records = Vec::new();
    let mut skipped = 0;

    let mut sep = "\t".to_string();
    let mut set_sep = ",".to_string();
    let mut unset = "-".to_string();
    let mut empty = "(empty)".to_string();
    let mut fields: Vec<String> = Vec::new();

    let mut raw = Vec::new();
    let mut next_index = 0usize;
    while let Some(fits) = next_line(&mut reader, &mut raw)? {
        // 0-based line index; evidence shows i + 1
        let i = next_index;
        next_index += 1;
        if !fits {
            skipped += 1;
            continue;
        }
        let text = String::from_utf8_lossy(&raw);
        let text = text.trim_end_matches('\r');
        if text.trim().is_empty() {
            continue;
        }
        let fmt = *format.get_or_insert(if text.starts_with('{') {
            Format::Json
        } else {
            Format::Tsv
        });
        match fmt {
            Format::Json => {
                let value: serde_json::Value = match serde_json::from_str(text) {
                    Ok(v) => v,
                    // a truncated last line (log still being written) is skipped
                    Err(_) => {
                        skipped += 1;
                        continue;
                    }
                };
                let mut rec = Record {
                    line: i + 1,
                    ..Default::default()
                };
                if let serde_json::Value::Object(map) = value {
                    for (k, v) in map {
                        flatten_json(&mut rec, &k, &v);
                    }
                }
                if let Some(p) = rec.get("_path") {
                    name = p.to_string();
                }
                records.push(rec);
            }
            Format::Tsv => {
                if let Some(h) = text.strip_prefix('#') {
                    let (key, val) = h.split_once(sep.as_str()).unwrap_or((h, ""));
                    let key = key.trim();
                    match key {
                        // "#separator \x09" uses a space, before the separator is known
                        _ if h.starts_with("separator") => {
                            sep = unescape(h.trim_start_matches("separator").trim());
                        }
                        "set_separator" => set_sep = unescape(val),
                        "unset_field" => unset = unescape(val),
                        "empty_field" => empty = unescape(val),
                        "path" => name = val.to_string(),
                        "fields" => fields = val.split(sep.as_str()).map(String::from).collect(),
                        _ => {}
                    }
                    continue;
                }
                if fields.is_empty() {
                    bail!("line {} has data before the #fields header", i + 1);
                }
                let values: Vec<&str> = text.split(sep.as_str()).collect();
                // a row cut off mid-write would land in the wrong fields
                // (an address read as "10.10.1.1" instead of "10.10.1.10")
                if values.len() != fields.len() {
                    skipped += 1;
                    continue;
                }
                let mut rec = Record {
                    line: i + 1,
                    ..Default::default()
                };
                for (k, v) in fields.iter().zip(values) {
                    if v == unset {
                        continue;
                    }
                    let v = if v == empty {
                        String::new()
                    } else {
                        unescape(v)
                    };
                    // sets/vectors become comma-joined, like JSON arrays below
                    let v = if set_sep != "," {
                        v.replace(&set_sep, ",")
                    } else {
                        v
                    };
                    rec.set(k, &v);
                }
                records.push(rec);
            }
        }
    }
    Ok(Log {
        name,
        file: file_name.to_string(),
        format: format.unwrap_or(Format::Tsv),
        records,
        skipped,
    })
}

fn flatten_json(rec: &mut Record, key: &str, v: &serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::Null => {}
        Value::Bool(b) => rec.set(key, if *b { "T" } else { "F" }),
        Value::Number(n) => rec.set(key, &n.to_string()),
        Value::String(s) => rec.set(key, s),
        Value::Array(items) => {
            let joined: Vec<String> = items
                .iter()
                .map(|i| match i {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect();
            rec.set(key, &joined.join(","));
        }
        Value::Object(map) => {
            for (k, v) in map {
                flatten_json(rec, &format!("{key}.{k}"), v);
            }
        }
    }
}

/// Undoes zeek's `\xNN` escapes.
fn unescape(s: &str) -> String {
    if !s.contains("\\x") {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 4 <= bytes.len() && bytes.get(i + 1) == Some(&b'x') {
            if let Some(b) = std::str::from_utf8(&bytes[i + 2..i + 4])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(b);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TSV: &str = "#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tftp
#fields\tts\tuid\tid.orig_h\tuser\tpassword\tcommand\targ\treply_msg\tservice
#types\ttime\tstring\taddr\tstring\tstring\tstring\tstring\tstring\tset[string]
1793520000.5\tCa1\t10.0.0.5\toperator\thunter2\tPASS\thunter2\tPassword required for operator\ta,b
1793520001.0\tCa2\t10.0.0.6\t<unknown>\t-\tSYST\t-\t-\t(empty)
1793520002.0\tCa3\t10.0.0.
#close\t2026-11-01-09-00-00
";

    #[test]
    fn reads_tsv_and_keeps_only_allowed_fields() {
        let log = parse("ftp.log", TSV.as_bytes()).unwrap();
        assert_eq!(log.name, "ftp");
        assert_eq!(log.format, Format::Tsv);
        // the row cut off mid-write is skipped, not read into the wrong fields
        assert_eq!(log.records.len(), 2);
        assert_eq!(log.skipped, 1);
        let r = &log.records[0];
        assert_eq!(r.line, 8);
        assert_eq!(r.get("id.orig_h"), Some("10.0.0.5"));
        assert_eq!(r.ts(), Some(1_793_520_000.5));
        assert_eq!(r.get("service"), Some("a,b"));
        // credentials leave only a marker; other fields not on the list are gone
        for gone in ["user", "password", "arg", "reply_msg", "command"] {
            assert_eq!(r.get(gone), None, "{gone}");
        }
        assert!(r.had("user") && r.had("password"));
        let dump = format!("{:?}", log.records);
        assert!(
            !dump.contains("hunter2") && !dump.contains("operator"),
            "{dump}"
        );
        // "<unknown>" and unset are not logins
        assert!(!log.records[1].had("user") && !log.records[1].had("password"));
        assert_eq!(log.records[1].get("service"), Some(""));
    }

    #[test]
    fn reads_json_lines_and_flattens() {
        let text = r#"{"_path":"http","ts":"2026-11-01T08:00:00Z","uid":"Ch1","id.orig_h":"10.0.0.5","id":{"resp_h":"10.0.1.10"},"username":"admin","password":"pw","service":["x","y"],"orig_bytes":1,"is_orig":true,"community":"public","uri":"/login?token=abc"}
{"ts":1793520001.0,"uid":"Ch2"
"#;
        let log = parse("weird-name.log", text.as_bytes()).unwrap();
        assert_eq!(log.name, "http");
        assert_eq!(log.format, Format::Json);
        // the truncated second line is skipped
        assert_eq!(log.records.len(), 1);
        assert_eq!(log.skipped, 1);
        let r = &log.records[0];
        assert_eq!(r.ts(), Some(1_793_520_000.0));
        assert_eq!(r.get("id.resp_h"), Some("10.0.1.10"));
        assert_eq!(r.get("service"), Some("x,y"));
        assert_eq!(r.get("orig_bytes"), Some("1"));
        assert!(r.is_true("is_orig"));
        assert!(r.had("username") && r.had("password"));
        let dump = format!("{r:?}");
        for secret in ["admin", "public", "token=abc"] {
            assert!(!dump.contains(secret), "{secret} in {dump}");
        }
    }

    #[test]
    fn rotated_names_and_escapes() {
        let text = "#separator \\x09\n#fields\tts\tservice\n1\ta\\x2cb\n";
        let log = parse("conn.08:00:00-09:00:00.log", text.as_bytes()).unwrap();
        assert_eq!(log.name, "conn");
        assert_eq!(log.records[0].get("service"), Some("a,b"));
    }

    #[test]
    fn overlong_lines_are_skipped_not_buffered() {
        let long = "x".repeat(MAX_LINE + 10);
        let text = format!("#separator \\x09\n#fields\tts\tuid\n1\tC1\n{long}\n2\tC2");
        let log = parse("conn.log", text.as_bytes()).unwrap();
        assert_eq!(log.records.len(), 2);
        assert_eq!(log.skipped, 1);
        // line numbers still count the skipped line
        assert_eq!(log.records[1].line, 5);
        assert_eq!(log.records[1].uid(), Some("C2"));
    }

    #[test]
    fn data_without_header_is_an_error() {
        assert!(parse("conn.log", "1\t2\n".as_bytes()).is_err());
    }

    #[test]
    fn only_used_logs_are_read() {
        let d = std::env::temp_dir().join(format!("otinv-zeek-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let conn = "#separator \\x09\n#fields\tts\tuid\n1\tC1\n";
        std::fs::write(d.join("conn.log"), conn).unwrap();
        // not a log otinv uses: never opened, so its junk can't fail the run
        std::fs::write(d.join("snmp.log"), "garbage without a header\n").unwrap();
        std::fs::write(d.join("modbus.log.gz"), [0x1f, 0x8b]).unwrap();
        let logs = read_dir(&d, DEFAULT_MAX_LOG_MB).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].name, "conn");
        std::fs::remove_file(d.join("conn.log")).unwrap();
        assert!(read_dir(&d, DEFAULT_MAX_LOG_MB)
            .unwrap_err()
            .to_string()
            .contains("no conn.log"));
        // named by date, but the header says what it is
        std::fs::write(
            d.join("2026-11-01-conn.log"),
            "#separator \\x09\n#path\tconn\n#fields\tts\tuid\n1\tC1\n",
        )
        .unwrap();
        std::fs::write(
            d.join("dhcp-export.json"),
            "{\"_path\": \"dhcp\", \"ts\": 1}\n",
        )
        .unwrap();
        let mut names: Vec<String> = read_dir(&d, DEFAULT_MAX_LOG_MB)
            .unwrap()
            .into_iter()
            .map(|l| l.name)
            .collect();
        names.sort();
        assert_eq!(names, ["conn", "dhcp"]);
        let _ = std::fs::remove_dir_all(&d);
    }
}
