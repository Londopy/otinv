// small, targeted cases: each pins down a rule the lab fixtures don't
// exercise on their own (found by mutating one line at a time and seeing
// which mutations the suite missed).

use otinv::config::{Rules, Site};
use otinv::model::{Role, Run};
use otinv::oui::Oui;
use otinv::{pipeline, pseudo, zeek};
use std::path::PathBuf;

const CONN_FIELDS: &str = "ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\thistory\torig_bytes\tresp_bytes\torig_l2_addr\tresp_l2_addr";
const MODBUS_FIELDS: &str = "ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tfunc\tpdu_type";

fn tsv(fields: &str, rows: &[String]) -> String {
    let mut s = format!("#separator \\x09\n#fields\t{fields}\n");
    for r in rows {
        s.push_str(r);
        s.push('\n');
    }
    s
}

/// One conn.log row. `history` "ShADadFf" is a real conversation, "ShAR" a
/// handshake-only scan.
#[allow(clippy::too_many_arguments)]
fn conn(
    ts: u32,
    orig: &str,
    resp: &str,
    port: u16,
    history: &str,
    resp_bytes: &str,
    l2: (&str, &str),
) -> String {
    format!(
        "{ts}.0\tC{ts}\t{orig}\t49152\t{resp}\t{port}\ttcp\t-\t{history}\t100\t{resp_bytes}\t{}\t{}",
        l2.0, l2.1
    )
}

fn data(ts: u32, orig: &str, resp: &str, port: u16) -> String {
    conn(ts, orig, resp, port, "ShADadFf", "300", ("-", "-"))
}

fn modbus(ts: u32, orig: &str, resp: &str, func: &str, pdu: &str) -> String {
    format!("{ts}.0\tM{ts}\t{orig}\t49152\t{resp}\t502\t{func}\t{pdu}")
}

fn run(tag: &str, files: &[(&str, String)]) -> Run {
    let d = std::env::temp_dir().join(format!("otinv-edge-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    for (name, body) in files {
        std::fs::write(d.join(name), body).unwrap();
    }
    let logs = zeek::read_dir(&d, zeek::DEFAULT_MAX_LOG_MB).unwrap();
    let rules = Rules::builtin();
    let r = pipeline::analyze(&pipeline::Inputs {
        logs: &logs,
        rules: &rules,
        site: &Site::default(),
        oui: &Oui::builtin(),
        previous: None,
        source: tag.into(),
        generated: "2026-11-02T00:00:00Z".into(),
    });
    let _ = std::fs::remove_dir_all(PathBuf::from(&d));
    r
}

fn role(r: &Run, ip: &str) -> Role {
    r.asset(ip).unwrap_or_else(|| panic!("{ip} missing")).role
}

#[test]
fn a_handshake_only_scan_gives_the_scanner_no_role() {
    let r = run(
        "scan",
        &[(
            "conn.log",
            tsv(
                CONN_FIELDS,
                &[
                    data(1, "10.0.0.5", "10.0.0.10", 502),
                    conn(2, "10.0.0.66", "10.0.0.10", 502, "ShAR", "0", ("-", "-")),
                    conn(3, "10.0.0.66", "10.0.0.10", 80, "ShAR", "0", ("-", "-")),
                    // the same web page with data really is configuration
                    data(4, "10.0.0.7", "10.0.0.10", 80),
                ],
            ),
        )],
    );
    assert_eq!(role(&r, "10.0.0.10"), Role::Controller);
    assert_eq!(role(&r, "10.0.0.5"), Role::Hmi);
    assert_eq!(role(&r, "10.0.0.66"), Role::ItHost);
    assert_eq!(role(&r, "10.0.0.7"), Role::EngineeringWorkstation);
}

#[test]
fn trimmed_conn_logs_fall_back_to_answered() {
    let fields = "ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state";
    let r = run(
        "trimmed",
        &[(
            "conn.log",
            tsv(
                fields,
                &["1.0\tC1\t10.0.0.5\t49152\t10.0.0.10\t502\ttcp\tSF".into()],
            ),
        )],
    );
    assert_eq!(role(&r, "10.0.0.5"), Role::Hmi);
}

#[test]
fn a_mac_carrying_internet_traffic_is_a_routers() {
    let router = "00:11:22:33:44:01";
    let routed = conn(
        1,
        "10.0.5.5",
        "10.0.0.10",
        502,
        "ShADadFf",
        "300",
        (router, "00:1d:9c:00:00:10"),
    );
    // without internet traffic the lone routed device would get the router's MAC
    let alone = run(
        "mac-alone",
        &[("conn.log", tsv(CONN_FIELDS, std::slice::from_ref(&routed)))],
    );
    assert_eq!(
        alone.asset("10.0.5.5").unwrap().mac.as_deref(),
        Some(router)
    );
    let internet = conn(
        2,
        "10.0.0.5",
        "8.8.8.8",
        443,
        "ShADadFf",
        "300",
        ("00:0c:29:00:00:05", router),
    );
    let r = run(
        "mac-router",
        &[("conn.log", tsv(CONN_FIELDS, &[routed, internet]))],
    );
    assert_eq!(r.asset("10.0.5.5").unwrap().mac, None);
    assert!(r.shared_macs.iter().any(|s| s.mac == router));
    assert_eq!(
        r.asset("10.0.0.10").unwrap().mac.as_deref(),
        Some("00:1d:9c:00:00:10")
    );
}

#[test]
fn first_traffic_is_the_earliest_line_not_the_first_in_the_file() {
    // conn.log is written when connections end, so a later line can start earlier
    let r = run(
        "order",
        &[(
            "conn.log",
            tsv(
                CONN_FIELDS,
                &[
                    data(200, "10.0.0.5", "10.0.0.10", 502),
                    data(100, "10.0.0.5", "10.0.0.10", 502),
                ],
            ),
        )],
    );
    let a = r.asset("10.0.0.5").unwrap();
    assert_eq!(a.first_seen, 100.0);
    assert_eq!(a.first_evidence.line, 4, "{:?}", a.first_evidence);
}

#[test]
fn edge_byte_counts_saturate() {
    let max = u64::MAX.to_string();
    let row = |ts| {
        conn(
            ts,
            "10.0.0.5",
            "10.0.0.10",
            502,
            "ShADadFf",
            &max,
            ("-", "-"),
        )
    };
    let r = run(
        "bytes",
        &[("conn.log", tsv(CONN_FIELDS, &[row(1), row(2)]))],
    );
    assert_eq!(r.edges[0].bytes, u64::MAX);
}

fn writer_case(tag: &str, polls: u32) -> Run {
    let mut mb = Vec::new();
    for i in 0..polls {
        // REQ and RESP lines: only the REQ counts as a poll
        mb.push(modbus(10 + i, "10.0.0.5", "10.0.0.10", "READ_COILS", "REQ"));
        mb.push(modbus(
            10 + i,
            "10.0.0.5",
            "10.0.0.10",
            "READ_COILS",
            "RESP",
        ));
    }
    mb.push(modbus(
        100,
        "10.0.0.5",
        "10.0.0.10",
        "WRITE_SINGLE_COIL",
        "REQ",
    ));
    run(
        tag,
        &[
            (
                "conn.log",
                tsv(CONN_FIELDS, &[data(1, "10.0.0.5", "10.0.0.10", 502)]),
            ),
            ("modbus.log", tsv(MODBUS_FIELDS, &mb)),
        ],
    )
}

#[test]
fn min_polls_is_counted_in_transactions() {
    let flagged = |r: &Run| r.findings.iter().any(|f| f.rule == "UNEXPECTED-WRITE");
    let nine = writer_case("polls9", 9);
    assert!(flagged(&nine));
    assert_eq!(role(&nine, "10.0.0.5"), Role::ItHost);
    let ten = writer_case("polls10", 10);
    assert!(!flagged(&ten));
    assert_eq!(role(&ten, "10.0.0.5"), Role::Hmi);
}

#[test]
fn a_refused_write_without_pdu_type_still_counts() {
    // older logs: one line per transaction, no pdu_type, refused ones suffixed
    let fields = "ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tfunc";
    let r = run(
        "exception",
        &[
            (
                "conn.log",
                tsv(CONN_FIELDS, &[data(1, "10.0.0.66", "10.0.0.10", 502)]),
            ),
            (
                "modbus.log",
                tsv(
                    fields,
                    &[
                        "5.0\tM5\t10.0.0.66\t49152\t10.0.0.10\t502\tWRITE_SINGLE_COIL_EXCEPTION"
                            .into(),
                    ],
                ),
            ),
        ],
    );
    let f = r
        .findings
        .iter()
        .find(|f| f.rule == "UNEXPECTED-WRITE")
        .unwrap();
    assert_eq!(f.evidence[0].what, "Modbus WRITE_SINGLE_COIL");
}

fn named(tag: &str, hostname: &str) -> Run {
    let dhcp = format!("#separator \\x09\n#fields\tts\tassigned_addr\tmac\thost_name\n1.0\t10.0.0.5\t00:0c:29:00:00:05\t{hostname}\n");
    run(
        tag,
        &[
            (
                "conn.log",
                tsv(CONN_FIELDS, &[data(1, "10.0.0.5", "10.0.0.10", 502)]),
            ),
            ("dhcp.log", dhcp),
        ],
    )
}

#[test]
fn aliases_never_collide_with_real_values() {
    let r = named("collide", "host-01");
    let map = pseudo::Map::build(&[&r]);
    let aliases: Vec<&String> = map.pairs().map(|(_, a)| a).collect();
    assert!(!aliases.iter().any(|a| *a == "host-01"), "{aliases:?}");
    assert!(map.leaks(&map.apply(&r)).is_empty());
}

#[test]
fn leak_check_finds_escaped_values() {
    let real = "WELL\"5\\X";
    let r = named("escaped", real);
    let map = pseudo::Map::build(&[&r]);
    let mut p = map.apply(&r);
    assert!(map.leaks(&p).is_empty());
    // simulate a gap in apply(): the real host name slips through
    p.assets[0].hostnames.push(real.to_string());
    assert_eq!(map.leaks(&p), [real]);
}

#[test]
fn aliases_stay_the_same_from_month_to_month() {
    let october = named("oct", "PUMP-HMI");
    let first = pseudo::Map::build(&[&october]);
    // november: the same devices plus a new one
    let november = run(
        "nov",
        &[(
            "conn.log",
            tsv(
                CONN_FIELDS,
                &[
                    data(1, "10.0.0.5", "10.0.0.10", 502),
                    data(2, "10.0.0.3", "10.0.0.10", 502),
                ],
            ),
        )],
    );
    let saved = first.to_csv();
    let reloaded = pseudo::Map::from_csv(&saved).unwrap();
    let second = pseudo::Map::extend(&reloaded, &[&november]);
    let alias = |m: &pseudo::Map, real: &str| {
        m.pairs()
            .find(|(r, _)| *r == real)
            .map(|(_, a)| a.clone())
            .unwrap()
    };
    for real in ["10.0.0.5", "10.0.0.10", "PUMP-HMI"] {
        assert_eq!(alias(&first, real), alias(&second, real), "{real}");
    }
    // the new device gets a fresh number, not one already handed out
    let new = alias(&second, "10.0.0.3");
    assert!(first.pairs().all(|(_, a)| *a != new), "{new}");
    assert!(second.leaks(&second.apply(&november)).is_empty());
}

#[test]
fn pseudonym_map_files_roundtrip_formula_values() {
    let r = named("formula", "=cmd|' /C calc'!A0");
    let m = pseudo::Map::build(&[&r]);
    let back = pseudo::Map::from_csv(&m.to_csv()).unwrap();
    let a: Vec<_> = m.pairs().collect();
    let b: Vec<_> = back.pairs().collect();
    assert_eq!(a, b);
    assert!(pseudo::Map::from_csv("real,alias\nx,host-01\ny,host-01\n").is_err());
}

#[test]
fn modbus_device_identification_as_icsnpp_logs_it() {
    // columns and values as ICSNPP-Modbus writes them (from the capture test)
    let fields = "ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tis_orig\tsource_h\tsource_p\tdestination_h\tdestination_p\tfunc\tobject_id_code\tobject_id\tobject_value";
    let row = |is_orig: &str, code: &str, name: &str, value: &str| {
        let (s, d) = if is_orig == "T" {
            ("10.0.0.7", "10.0.0.10")
        } else {
            ("10.0.0.10", "10.0.0.7")
        };
        format!("1.0\tM1\t10.0.0.7\t40000\t10.0.0.10\t502\t{is_orig}\t{s}\t40000\t{d}\t502\tENCAP_INTERFACE_TRANSPORT\t{code}\t{name}\t{value}")
    };
    let r = run(
        "modbus-ident",
        &[
            (
                "conn.log",
                tsv(CONN_FIELDS, &[data(1, "10.0.0.7", "10.0.0.10", 502)]),
            ),
            (
                "modbus_read_device_identification.log",
                tsv(
                    fields,
                    &[
                        row("T", "0x00", "Basic Device Identification", "-"),
                        row("F", "0x00", "VendorName", "AutomationDirect"),
                        row("F", "0x01", "ProductCode", "C0-12DD1E-D"),
                        row("F", "0x02", "MajorMinorVersion", "3.41"),
                    ],
                ),
            ),
        ],
    );
    let plc = r.asset("10.0.0.10").unwrap();
    assert_eq!(
        plc.identity.get("vendor").map(String::as_str),
        Some("AutomationDirect")
    );
    assert_eq!(
        plc.identity.get("product code").map(String::as_str),
        Some("C0-12DD1E-D")
    );
    assert_eq!(
        plc.identity.get("firmware").map(String::as_str),
        Some("3.41")
    );
    assert!(r.asset("10.0.0.7").unwrap().identity.is_empty());
}
