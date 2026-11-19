// end to end through a real zeek: tests/fixtures/make_lab_pcap.py writes the
// lab's bad hour as packets, otinv runs zeek + ICSNPP on it (docker runner)
// and must find the same problems the log fixtures produce.
//
// needs docker and the otinv-zeek:local image, so it only runs when
// OTINV_CAPTURE_TEST=1 (the capture workflow sets it). elsewhere it passes
// without doing anything.

use otinv::model::{Role, Run};
use otinv::pipeline;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const SECRET: &str = "Sup3rSecretLabPw";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn all_text(dir: &Path) -> String {
    let mut s = String::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_file() && p.extension().is_some_and(|x| x != "londopy") {
            s.push_str(&std::fs::read_to_string(&p).unwrap_or_default());
        }
    }
    s
}

#[test]
fn capture_through_real_zeek() {
    if std::env::var("OTINV_CAPTURE_TEST").as_deref() != Ok("1") {
        eprintln!("skipped: set OTINV_CAPTURE_TEST=1 (needs docker and otinv-zeek:local)");
        return;
    }
    let work = std::env::temp_dir().join("otinv-capture-test");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    let pcap = work.join("lab.pcap");
    let gen = Command::new("python3")
        .arg(root().join("tests/fixtures/make_lab_pcap.py"))
        .arg(&pcap)
        .status()
        .or_else(|_| {
            Command::new("python")
                .arg(root().join("tests/fixtures/make_lab_pcap.py"))
                .arg(&pcap)
                .status()
        })
        .expect("python to write the capture");
    assert!(gen.success());

    let out = work.join("report");
    let o = Command::new(env!("CARGO_BIN_EXE_otinv"))
        .args([
            "analyze",
            &pcap.to_string_lossy(),
            "-o",
            &out.to_string_lossy(),
        ])
        .args(["--runner", "docker", "--keep-logs", "--pseudonymize"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&o.stderr);
    eprintln!("{}\n{stderr}", String::from_utf8_lossy(&o.stdout));
    assert!(o.status.success(), "otinv failed");
    assert!(
        stderr.contains("--network none"),
        "docker must run without a network"
    );

    // zeek wrote the logs otinv needs, ICSNPP included
    let logs: BTreeSet<String> = std::fs::read_dir(out.join("zeek-logs"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    eprintln!("zeek logs: {logs:?}");
    for need in [
        "conn.log",
        "modbus.log",
        "dnp3.log",
        "ftp.log",
        "http.log",
        "dhcp.log",
        "modbus_read_device_identification.log",
    ] {
        assert!(logs.contains(need), "zeek didn't write {need}");
    }
    assert!(
        logs.iter()
            .any(|l| l.starts_with("cip_identity") || l.starts_with("enip")),
        "no ICSNPP EtherNet/IP log"
    );

    let run: Run = pipeline::load_run(&out.join("run.londopy")).unwrap();
    let roles: Vec<(String, Role)> = run.assets.iter().map(|a| (a.ip.clone(), a.role)).collect();
    eprintln!("roles: {roles:?}");
    let role = |ip: &str| run.asset(ip).map(|a| a.role);
    assert_eq!(role("10.10.1.10"), Some(Role::Controller));
    assert_eq!(role("10.10.1.11"), Some(Role::Controller));
    assert_eq!(role("10.10.1.12"), Some(Role::Controller));
    assert_eq!(role("10.10.1.20"), Some(Role::Controller));
    assert_eq!(role("10.10.2.20"), Some(Role::Hmi));
    assert_eq!(role("10.10.2.30"), Some(Role::EngineeringWorkstation));
    assert_eq!(role("10.10.0.1"), Some(Role::NetworkService));
    assert_eq!(role("10.10.3.5"), Some(Role::ItHost));

    let office = run.asset("10.10.3.5").unwrap();
    assert_eq!(office.hostnames, ["OFFICE-PC1"], "DHCP host name");
    let plc3 = run.asset("10.10.1.12").unwrap();
    eprintln!("plc3 identity: {:?}", plc3.identity);
    assert!(
        plc3.identity
            .get("model")
            .is_some_and(|m| m.contains("1769-L33ER")),
        "EtherNet/IP identity"
    );
    let plc2 = run.asset("10.10.1.11").unwrap();
    eprintln!("plc2 identity: {:?}", plc2.identity);
    assert_eq!(
        plc2.identity.get("vendor").map(String::as_str),
        Some("AutomationDirect"),
        "Modbus identity"
    );
    assert_eq!(
        plc2.identity.get("firmware").map(String::as_str),
        Some("3.41")
    );

    let got: BTreeSet<(String, String)> = run
        .findings
        .iter()
        .map(|f| (f.rule.clone(), f.host.clone()))
        .collect();
    for f in &run.findings {
        let what: Vec<String> = f
            .evidence
            .iter()
            .map(|e| format!("{}:{} {}", e.file, e.line, e.what))
            .collect();
        eprintln!("finding {} on {}: {what:?}", f.rule, f.host);
    }
    let want: BTreeSet<(String, String)> = [
        ("OT-INTERNET", "10.10.1.10"),
        ("REMOTE-ACCESS", "10.10.2.20"),
        ("REMOTE-ACCESS", "10.10.1.11"),
        ("REMOTE-ACCESS", "10.10.2.30"),
        ("CLEARTEXT-LOGIN", "10.10.1.10"),
        ("CLEARTEXT-LOGIN", "10.10.1.11"),
        ("UNEXPECTED-WRITE", "10.10.3.5"),
        ("IT-OT-MIXING", "10.10.2.20"),
    ]
    .iter()
    .map(|(a, b)| (a.to_string(), b.to_string()))
    .collect();
    assert_eq!(got, want);

    // the rogue's write and refused write, each counted once
    let w = run
        .findings
        .iter()
        .find(|f| f.rule == "UNEXPECTED-WRITE")
        .unwrap();
    assert_eq!(w.evidence_total, 2, "{:?}", w.evidence);

    // credentials are in zeek's raw logs (kept here on purpose), never in otinv's
    for dir in [out.clone(), out.join("share")] {
        assert!(
            !all_text(&dir).contains(SECRET),
            "secret in {}",
            dir.display()
        );
    }
    assert!(
        otinv::pseudo::addresses_in(&all_text(&out.join("share")), &BTreeSet::new()).is_empty()
    );
}
