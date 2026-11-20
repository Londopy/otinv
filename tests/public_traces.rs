// otinv on public ICS captures it didn't make: CISA's ICSNPP test captures
// and zeek's own, listed with their hashes in tests/public-traces.txt. These
// cover protocols the lab capture doesn't (BACnet, S7comm, OPC UA, Omron
// FINS, ROC Plus, C37.118, HART-IP, C12.22) and capture formats it doesn't
// (pcapng, raw IP, BSD loopback).
//
// needs the otinv-zeek:local image and the captures, so a plain `cargo test`
// ignores it. the capture workflow runs:
//   python scripts/fetch_public_traces.py target/public-traces
//   OTINV_PUBLIC_TRACES=target/public-traces cargo test --test public_traces -- --ignored
//
// the expected values below were read from zeek's own logs of each capture.

use otinv::model::{Role, Run};
use otinv::pipeline;
use std::path::{Path, PathBuf};
use std::process::Command;

fn traces() -> PathBuf {
    let dir = std::env::var("OTINV_PUBLIC_TRACES").expect("OTINV_PUBLIC_TRACES");
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(dir)
}

fn analyze(trace: &str, site: Option<&str>) -> Run {
    let pcap = traces().join(trace);
    assert!(
        pcap.is_file(),
        "{} missing; run fetch_public_traces.py",
        pcap.display()
    );
    let out = std::env::temp_dir().join(format!("otinv-public-{trace}"));
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_otinv"));
    cmd.args([
        "analyze",
        &pcap.to_string_lossy(),
        "-o",
        &out.to_string_lossy(),
    ])
    .args(["--runner", "docker", "--pseudonymize"]);
    if let Some(s) = site {
        let p = out.join("site.toml");
        std::fs::write(&p, s).unwrap();
        cmd.arg("--site").arg(&p);
    }
    let o = cmd.output().unwrap();
    assert!(
        o.status.success(),
        "{trace}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let run = pipeline::load_run(&out.join("run.londopy")).unwrap();
    every_packet_found(trace, &run, &out);
    run
}

/// Every evidence line about a tcp/udp connection names its packet, so the
/// capture reader handled this file's format and link type.
fn every_packet_found(trace: &str, run: &Run, out: &Path) {
    for f in &run.findings {
        for e in &f.evidence {
            if e.ports.is_some() {
                assert!(e.frame.is_some(), "{trace}: no frame for {e:?}");
            }
        }
    }
    let first = run.assets.iter().map(|a| &a.first_evidence);
    for e in first.filter(|e| e.ports.is_some()) {
        assert!(e.frame.is_some(), "{trace}: no frame for {e:?}");
    }
    assert!(out.join("evidence.csv").is_file());
}

fn id<'a>(run: &'a Run, ip: &str, key: &str) -> Option<&'a str> {
    run.asset(ip)?.identity.get(key).map(String::as_str)
}

fn role(run: &Run, ip: &str) -> Option<Role> {
    run.asset(ip).map(|a| a.role)
}

fn findings(run: &Run) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = run
        .findings
        .iter()
        .map(|f| (f.rule.clone(), f.host.clone()))
        .collect();
    v.sort();
    v
}

#[test]
#[ignore = "needs the zeek image and the public captures"]
fn bacnet_devices_describe_themselves() {
    let run = analyze("bacnet-example.pcap", None);
    let ip = "172.20.32.100";
    assert_eq!(role(&run, ip), Some(Role::Controller));
    assert_eq!(id(&run, ip, "model"), Some("GHU-026"));
    assert_eq!(id(&run, ip, "firmware"), Some("5.6.1"));
    assert_eq!(id(&run, ip, "location"), Some("bay_3257"));
    assert_eq!(id(&run, ip, "device name"), Some("PLC_93"));
    // from its I-Am broadcast
    assert_eq!(
        id(&run, "172.20.32.108", "vendor"),
        Some("Cornell University")
    );
    assert_eq!(id(&run, "172.20.32.108", "BACnet device"), Some("721"));
    assert!(run.findings.is_empty());
    // names and places typed into the devices stay out of the shared copy
    let share = shared_text("bacnet-example.pcap");
    for typed in ["bay_3257", "PLC_93"] {
        assert!(!share.contains(typed), "{typed} in share/");
    }
    assert!(share.contains("GHU-026"), "the model is kept");

    // 192.168.0.24 sends I-Am for many devices: a router for the devices
    // behind it. Only its own device object's properties describe it.
    let run = analyze("bacnet-services.pcap", None);
    let ip = "192.168.0.24";
    assert_eq!(id(&run, ip, "vendor"), Some("Lithonia Lighting, Inc."));
    assert_eq!(id(&run, ip, "model"), Some("SYSC MLX"));
    assert_eq!(id(&run, ip, "firmware"), Some("2.62"));
    assert_eq!(id(&run, ip, "BACnet device"), None);
}

fn shared_text(trace: &str) -> String {
    let share = std::env::temp_dir()
        .join(format!("otinv-public-{trace}"))
        .join("share");
    let mut s = String::new();
    for e in std::fs::read_dir(&share).unwrap() {
        s.push_str(&std::fs::read_to_string(e.unwrap().path()).unwrap_or_default());
    }
    s
}

#[test]
#[ignore = "needs the zeek image and the public captures"]
fn s7_opcua_fins_roc_and_pmu_identity() {
    let run = analyze("s7ident.pcap", None);
    assert_eq!(role(&run, "172.17.0.2"), Some(Role::Controller));
    assert_eq!(id(&run, "172.17.0.2", "model"), Some("CPU 315-2 PN/DP"));
    assert_eq!(id(&run, "172.17.0.2", "serial"), Some("S C-C2UR28922012"));

    let run = analyze("opcua-open62541.pcap", None);
    assert_eq!(id(&run, "::1", "product URI"), Some("http://open62541.org"));
    assert_eq!(
        id(&run, "::1", "application"),
        Some("open62541-based OPC UA Application")
    );

    // the test generator fills the model and version with placeholder letters
    let run = analyze("omron-fins.pcap", None);
    assert_eq!(role(&run, "192.168.0.1"), Some(Role::Controller));
    assert_eq!(
        id(&run, "192.168.0.1", "model"),
        Some("AAAAAAAAAAAAAAAAAAAA")
    );
    assert_eq!(
        id(&run, "192.168.0.1", "firmware"),
        Some("BBBBBBBBBBBBBBBBBBBB")
    );

    let run = analyze("roc-plus.pcap", None);
    assert_eq!(role(&run, "192.168.1.200"), Some(Role::Controller));
    assert_eq!(id(&run, "192.168.1.200", "model"), Some("ROC800 (809/827)"));

    let run = analyze("synchrophasor.pcap", None);
    assert_eq!(role(&run, "192.168.0.241"), Some(Role::Controller));
    assert_eq!(id(&run, "192.168.0.241", "PMU"), Some("Blue PMU (ID 241)"));
    let share = shared_text("synchrophasor.pcap");
    assert!(!share.contains("Blue PMU"), "station name in share/");
}

#[test]
#[ignore = "needs the zeek image and the public captures"]
fn enip_and_modbus_identity() {
    let run = analyze("enip-cip.pcap", None);
    let ip = "10.1.1.164";
    assert_eq!(id(&run, ip, "model"), Some("1756-ENBT/A"));
    assert_eq!(id(&run, ip, "serial"), Some("0x00524d8e"));
    assert_eq!(id(&run, ip, "firmware"), Some("4.3"));

    let run = analyze("modbus-icsnpp.pcap", None);
    assert_eq!(id(&run, "127.0.0.1", "vendor"), Some("Zeek Modbus Test"));
    assert_eq!(id(&run, "127.0.0.1", "firmware"), Some("1.2.3.6"));
    // the capture also has a Modbus session with an internet address
    assert_eq!(
        findings(&run),
        [("OT-INTERNET".to_string(), "192.168.1.6".to_string())]
    );

    let run = analyze("modbus-eit.pcap", None);
    assert!(run.assets.iter().any(|a| a.role == Role::Controller));
}

#[test]
#[ignore = "needs the zeek image and the public captures"]
fn writes_from_computers_that_dont_poll() {
    // 4SICS lab: a read/write of registers from a host that never polls
    let run = analyze("modbus-4sics.pcap", None);
    assert_eq!(role(&run, "192.168.88.95"), Some(Role::Controller));
    assert_eq!(
        findings(&run),
        [("UNEXPECTED-WRITE".to_string(), "192.168.2.166".to_string())]
    );

    // public addresses used inside a plant: only counted with local_networks
    let trace = "dnp3-select-operate.pcap";
    assert!(analyze(trace, None).assets.is_empty());
    let run = analyze(trace, Some("local_networks = [\"130.126.0.0/16\"]\n"));
    assert_eq!(role(&run, "130.126.140.229"), Some(Role::Controller));
    let w = run
        .findings
        .iter()
        .find(|f| f.rule == "UNEXPECTED-WRITE")
        .unwrap();
    let what: Vec<&str> = w.evidence.iter().map(|e| e.what.as_str()).collect();
    assert_eq!(what, ["DNP3 SELECT", "DNP3 OPERATE"]);
}

#[test]
#[ignore = "needs the zeek image and the public captures"]
fn other_protocols_find_their_controllers() {
    for (trace, controller, label) in [
        ("hart-ip.pcap", "192.168.0.10", "HART-IP"),
        ("c1222-ident.pcap", "192.168.1.101", "ANSI C12.22"),
        ("dnp3-icsnpp.pcap", "10.10.20.8", "DNP3"),
    ] {
        let run = analyze(trace, None);
        let a = run.asset(controller).unwrap_or_else(|| panic!("{trace}"));
        assert_eq!(a.role, Role::Controller, "{trace}");
        assert!(a.serves.contains(label), "{trace}: {:?}", a.serves);
    }
}
