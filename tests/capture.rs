// end to end through a real zeek: tests/fixtures/make_lab_pcap.py writes the
// lab's bad hour as packets, otinv runs zeek on it and must find the same
// problems the log fixtures produce.
//
// needs a zeek, so it's ignored by a plain `cargo test`. the capture
// workflow runs it with `cargo test --test capture -- --ignored` three ways,
// picked by OTINV_CAPTURE_RUNNER:
//   docker  the otinv-zeek:local image, zeek + ICSNPP (the default)
//   native  zeek on PATH, without ICSNPP
//   wsl     zeek inside WSL on Windows, without ICSNPP
// without ICSNPP there are no identity logs, so those checks only run on docker.

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

/// Packet `n` (from 1) of the little-endian classic pcap the generator writes.
fn packet(pcap: &[u8], n: u64) -> &[u8] {
    let mut i = 24;
    for k in 1.. {
        let len = u32::from_le_bytes(pcap[i + 8..i + 12].try_into().unwrap()) as usize;
        if k == n {
            return &pcap[i + 16..i + 16 + len];
        }
        i += 16 + len;
    }
    unreachable!()
}

#[test]
#[ignore = "needs zeek; the capture workflow runs it"]
fn capture_through_real_zeek() {
    let runner = std::env::var("OTINV_CAPTURE_RUNNER").unwrap_or_else(|_| "docker".into());
    let icsnpp = runner == "docker";
    let work = std::env::temp_dir().join("otinv-capture-test");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    let pcap = work.join("lab.pcap");
    // on Windows `python3` can be the store's stub, which runs and fails
    let wrote = ["python3", "python"].iter().any(|py| {
        Command::new(py)
            .arg(root().join("tests/fixtures/make_lab_pcap.py"))
            .arg(&pcap)
            .status()
            .is_ok_and(|s| s.success())
    });
    assert!(wrote, "python couldn't write the capture");

    let out = work.join("report");
    let o = Command::new(env!("CARGO_BIN_EXE_otinv"))
        .args([
            "analyze",
            &pcap.to_string_lossy(),
            "-o",
            &out.to_string_lossy(),
        ])
        .args(["--runner", &runner, "--keep-logs", "--pseudonymize"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&o.stderr);
    eprintln!("{}\n{stderr}", String::from_utf8_lossy(&o.stdout));
    assert!(o.status.success(), "otinv failed");
    if runner == "docker" {
        assert!(
            stderr.contains("--network none"),
            "docker must run without a network"
        );
    }

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
    ] {
        assert!(logs.contains(need), "zeek didn't write {need}");
    }
    if icsnpp {
        assert!(logs.contains("modbus_read_device_identification.log"));
        assert!(
            logs.iter()
                .any(|l| l.starts_with("cip_identity") || l.starts_with("enip")),
            "no ICSNPP EtherNet/IP log"
        );
    }

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
    if icsnpp {
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
    }

    let got: BTreeSet<(String, String)> = run
        .findings
        .iter()
        .map(|f| (f.rule.clone(), f.host.clone()))
        .collect();
    for f in &run.findings {
        let what: Vec<String> = f
            .evidence
            .iter()
            .map(|e| format!("{}:{} {:?} {}", e.file, e.line, e.frame, e.what))
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

    // every tcp/udp evidence line names its packet
    for f in &run.findings {
        for e in &f.evidence {
            if e.ports.is_some() {
                assert!(e.frame.is_some(), "{} has no frame: {e:?}", f.key);
            }
        }
    }

    // the rogue's write and refused write, each counted once, and the cited
    // packet really is the write: Modbus/TCP to port 502, function 5
    let w = run
        .findings
        .iter()
        .find(|f| f.rule == "UNEXPECTED-WRITE")
        .unwrap();
    assert_eq!(w.evidence_total, 2, "{:?}", w.evidence);
    let coil = w
        .evidence
        .iter()
        .find(|e| e.what.contains("WRITE_SINGLE_COIL"))
        .unwrap();
    let bytes = std::fs::read(&pcap).unwrap();
    let p = packet(&bytes, coil.frame.unwrap());
    assert_eq!(&p[26..30], &[10, 10, 3, 5], "source address");
    assert_eq!(u16::from_be_bytes([p[36], p[37]]), 502, "destination port");
    let tcp_len = usize::from(p[46] >> 4) * 4;
    assert_eq!(p[34 + tcp_len + 7], 5, "Modbus function code");

    let evidence = std::fs::read_to_string(out.join("evidence.csv")).unwrap();
    assert!(evidence.contains(&format!("frame.number == {}", coil.frame.unwrap())));

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
