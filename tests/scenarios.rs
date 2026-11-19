// end-to-end checks against the lab fixtures (tests/fixtures/make_fixtures.py).
// the spec's success metric for lab captures: every asset inventoried, every
// scripted bad scenario flagged with evidence, and nothing extra.

use otinv::config::{Rules, Site};
use otinv::model::{Role, Run};
use otinv::oui::Oui;
use otinv::{diff, pipeline, pseudo, report, zeek};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const SECRET: &str = "Sup3rSecretLabPw";
const GENERATED: &str = "2026-11-02T00:00:00Z";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("otinv-it-{tag}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run_on(name: &str, site: &Site, previous: Option<&Run>) -> Run {
    let logs = zeek::read_dir(&fixture(name), zeek::DEFAULT_MAX_LOG_MB).unwrap();
    let rules = Rules::builtin();
    pipeline::analyze(&pipeline::Inputs {
        logs: &logs,
        rules: &rules,
        site,
        oui: &Oui::builtin(),
        previous,
        source: name.into(),
        generated: GENERATED.into(),
    })
}

fn baseline() -> Run {
    run_on("lab-baseline", &Site::default(), None)
}

fn bad(previous: &Run) -> Run {
    run_on("lab-bad", &Site::default(), Some(previous))
}

fn role(run: &Run, ip: &str) -> Role {
    run.asset(ip).unwrap_or_else(|| panic!("{ip} missing")).role
}

fn findings(run: &Run) -> BTreeSet<(String, String)> {
    run.findings
        .iter()
        .map(|f| (f.rule.clone(), f.host.clone()))
        .collect()
}

fn all_text(dir: &Path) -> String {
    let mut s = String::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x != "londopy") {
            s.push_str(&std::fs::read_to_string(&p).unwrap());
        }
    }
    s
}

#[test]
fn baseline_inventory_is_complete_and_quiet() {
    let run = baseline();
    let ips: Vec<&str> = run.assets.iter().map(|a| a.ip.as_str()).collect();
    assert_eq!(
        ips,
        [
            "10.10.0.1",
            "10.10.1.10",
            "10.10.1.11",
            "10.10.1.12",
            "10.10.1.20",
            "10.10.2.20",
            "10.10.2.30",
            "10.10.3.5"
        ]
    );
    assert_eq!(role(&run, "10.10.1.10"), Role::Controller);
    assert_eq!(role(&run, "10.10.1.11"), Role::Controller);
    assert_eq!(role(&run, "10.10.1.12"), Role::Controller);
    assert_eq!(role(&run, "10.10.1.20"), Role::Controller);
    assert_eq!(role(&run, "10.10.2.20"), Role::Hmi);
    assert_eq!(role(&run, "10.10.2.30"), Role::EngineeringWorkstation);
    assert_eq!(role(&run, "10.10.0.1"), Role::NetworkService);
    assert_eq!(role(&run, "10.10.3.5"), Role::ItHost);
    assert!(run.findings.is_empty(), "{:#?}", run.findings);

    // the probe to an empty address didn't invent a device
    assert!(run.asset("10.10.1.99").is_none());

    // MACs: own MACs on the wire, the router's MAC is shared and trusted for
    // nobody, the routed office PC gets its real MAC from DHCP
    let plc1 = run.asset("10.10.1.10").unwrap();
    assert_eq!(plc1.mac.as_deref(), Some("b8:27:eb:00:00:10"));
    assert_eq!(plc1.vendor.as_deref(), Some("Raspberry Pi Foundation"));
    assert_eq!(run.asset("10.10.0.1").unwrap().mac, None);
    let office = run.asset("10.10.3.5").unwrap();
    assert_eq!(office.mac.as_deref(), Some("3c:52:82:00:00:05"));
    assert_eq!(office.hostnames, ["OFFICE-PC1"]);
    assert_eq!(run.shared_macs.len(), 1);
    assert_eq!(run.shared_macs[0].ips, ["10.10.0.1", "10.10.3.5"]);

    // identity from the EtherNet/IP reply (a JSON log)
    let plc3 = run.asset("10.10.1.12").unwrap();
    assert_eq!(plc3.identity["firmware"], "30.11");
    assert_eq!(plc3.identity["model"], "1769-L33ER/A LOGIX5333ER");

    // every role has a reason that points at a log line
    for a in &run.assets {
        for r in &a.reasons {
            assert!(r.evidence.line > 0 && !r.evidence.file.is_empty());
        }
        assert!(
            a.role == Role::ItHost || !a.reasons.is_empty(),
            "{} has no reason",
            a.ip
        );
    }
}

#[test]
fn every_scripted_bad_scenario_is_flagged_with_evidence() {
    let base = baseline();
    let run = bad(&base);
    let got = findings(&run);
    let want: BTreeSet<(String, String)> = [
        ("OT-INTERNET", "10.10.1.10"),     // Modbus answered from the internet
        ("REMOTE-ACCESS", "10.10.2.20"),   // VNC on the HMI
        ("REMOTE-ACCESS", "10.10.1.11"),   // telnet on a PLC
        ("REMOTE-ACCESS", "10.10.2.30"),   // TeamViewer dialing out from the laptop
        ("CLEARTEXT-LOGIN", "10.10.1.10"), // basic-auth web login
        ("CLEARTEXT-LOGIN", "10.10.1.11"), // FTP and telnet logins
        ("UNEXPECTED-WRITE", "10.10.3.5"), // rogue write from the office PC
        ("NEW-DEVICE", "10.10.1.50"),      // the Moxa gateway
        ("IT-OT-MIXING", "10.10.2.20"),    // HMI browsing the internet
    ]
    .iter()
    .map(|(a, b)| (a.to_string(), b.to_string()))
    .collect();
    assert_eq!(got, want);

    for f in &run.findings {
        assert!(!f.evidence.is_empty(), "{} has no evidence", f.key);
        assert_eq!(f.evidence_total.max(f.evidence.len()), f.evidence_total);
        for e in &f.evidence {
            assert!(e.line > 0 && e.file.ends_with(".log"), "{e:?}");
        }
    }

    let vnc = run
        .findings
        .iter()
        .find(|f| f.key == "REMOTE-ACCESS:10.10.2.20")
        .unwrap();
    assert!(vnc.from_internet);
    assert_eq!(vnc.severity, otinv::config::Severity::Critical);
    let telnet = run
        .findings
        .iter()
        .find(|f| f.key == "REMOTE-ACCESS:10.10.1.11")
        .unwrap();
    assert_eq!(telnet.severity, otinv::config::Severity::High);

    let tv = run
        .findings
        .iter()
        .find(|f| f.key == "REMOTE-ACCESS:10.10.2.30")
        .unwrap();
    assert!(tv.outbound && !tv.inbound);
    assert_eq!(tv.severity, otinv::config::Severity::Critical);
    // not counted a second time as plain internet use
    assert!(!run
        .findings
        .iter()
        .any(|f| f.key == "IT-OT-MIXING:10.10.2.30"));

    // a host that writes after a few reads is not promoted to HMI, and each
    // write transaction (REQ + RESP lines, one refused) is one piece of evidence
    assert_eq!(role(&run, "10.10.3.5"), Role::ItHost);
    let w = run
        .findings
        .iter()
        .find(|f| f.key == "UNEXPECTED-WRITE:10.10.3.5")
        .unwrap();
    assert_eq!(w.evidence_total, 2);
    let what: Vec<&str> = w.evidence.iter().map(|e| e.what.as_str()).collect();
    assert_eq!(
        what,
        [
            "Modbus WRITE_SINGLE_COIL",
            "Modbus WRITE_MULTIPLE_REGISTERS"
        ]
    );

    // DNP3: the RTU restart marks the laptop as engineering; the HMI's
    // DIRECT_OPERATE is expected (it polls the RTU), and the RTU's own
    // unsolicited report isn't a poll by anyone
    let ews = run.asset("10.10.2.30").unwrap();
    assert!(ews
        .reasons
        .iter()
        .any(|r| r.what == "sends DNP3 COLD_RESTART"));

    // ranked actions put the critical ones first
    let acts = report::actions(&run);
    assert_eq!(acts[0].severity, otinv::config::Severity::Critical);
    assert_eq!(acts[1].severity, otinv::config::Severity::Critical);
}

#[test]
fn credentials_never_reach_any_output() {
    let base = baseline();
    let run = bad(&base);
    let json = serde_json::to_string(&run).unwrap();
    for bad in [SECRET, "\"admin\"", "token=", "Password required"] {
        assert!(!json.contains(bad), "{bad}");
    }

    let out = tmp("secret");
    let d = diff::diff(&base, &run);
    report::write_all(&run, Some((&base, &d)), &out, false).unwrap();
    pipeline::save_run(&run, &out.join("run.londopy")).unwrap();
    let text = all_text(&out);
    assert!(!text.contains(SECRET));
    let saved = pipeline::load_run(&out.join("run.londopy")).unwrap();
    assert!(!serde_json::to_string(&saved).unwrap().contains(SECRET));
    // the findings are still there, just without the secrets
    assert!(text.contains("FTP login (user name and password not kept)"));
    assert!(text.contains("Web (HTTP) login (user name and password not kept)"));
}

#[test]
fn run_files_roundtrip_and_analysis_is_deterministic() {
    let a = baseline();
    let b = baseline();
    assert_eq!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );

    let out = tmp("roundtrip");
    let p = out.join("run.londopy");
    pipeline::save_run(&a, &p).unwrap();
    assert_eq!(pipeline::load_run(&p).unwrap(), a);
}

#[test]
fn diff_reports_new_changed_and_new_problems() {
    let base = baseline();
    let run = bad(&base);
    let d = diff::diff(&base, &run);
    assert_eq!(d.new_assets.len(), 1);
    assert_eq!(d.new_assets[0].ip, "10.10.1.50");
    assert!(d.gone_assets.is_empty());
    let plc3 = d.changed.iter().find(|c| c.ip == "10.10.1.12").unwrap();
    assert!(plc3
        .what
        .iter()
        .any(|w| w.contains("firmware changed 30.11 -> 33.11")));
    assert_eq!(d.new_findings.len(), run.findings.len());
    assert!(d.resolved_findings.is_empty());

    // and back the other way: problems resolve, the new device is gone
    let back = diff::diff(&run, &base);
    assert_eq!(back.gone_assets.len(), 1);
    assert!(back
        .resolved_findings
        .iter()
        .all(|f| f.rule != "NEW-DEVICE"));
    assert_eq!(back.resolved_findings.len(), run.findings.len() - 1);
}

#[test]
fn pseudonymized_reports_hold_no_real_addresses() {
    let base = baseline();
    let run = bad(&base);
    let map = pseudo::Map::build(&[&run, &base]);
    let (p_run, p_base) = (map.apply(&run), map.apply(&base));
    assert!(map.leaks(&p_run).is_empty(), "{:?}", map.leaks(&p_run));
    assert!(map.leaks(&p_base).is_empty());

    let out = tmp("pseudo");
    let d = diff::diff(&p_base, &p_run);
    report::write_all(&p_run, Some((&p_base, &d)), &out, true).unwrap();
    let text = all_text(&out);
    for real in [
        "10.10.",
        "198.51.100.",
        "203.0.113.",
        "b8:27:eb",
        "OFFICE-PC1",
        "0x60a1b2c3",
    ] {
        assert!(!text.contains(real), "{real} leaked");
    }
    // same aliases across both runs, and the findings survive
    assert_eq!(p_run.findings.len(), run.findings.len());
    assert!(text.contains("host-"));
    assert!(text.contains("ext-"));
    let alias = map
        .pairs()
        .find(|(real, _)| *real == "10.10.1.10")
        .unwrap()
        .1
        .clone();
    assert!(p_base.asset(&alias).is_some() && p_run.asset(&alias).is_some());
}

#[test]
fn site_file_names_devices_and_allows_writers() {
    let site = Site::parse(
        r#"
name = "Lab"
expected_writers = ["10.10.2.20", "10.10.3.5"]
[names]
"10.10.1.10" = "Well 2 PLC"
"#,
    )
    .unwrap();
    let base = run_on("lab-baseline", &site, None);
    let run = run_on("lab-bad", &site, Some(&base));
    assert!(!findings(&run).iter().any(|(r, _)| r == "UNEXPECTED-WRITE"));
    let text = report::text::summary(&run);
    assert!(text.contains("\"Well 2 PLC\" (10.10.1.10)"), "{text}");
    assert!(text.contains("OTINV REPORT: Lab"));
}

#[test]
fn reports_render_for_an_empty_capture() {
    let dir = tmp("empty");
    std::fs::write(
        dir.join("conn.log"),
        "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.resp_h\n",
    )
    .unwrap();
    let logs = zeek::read_dir(&dir, zeek::DEFAULT_MAX_LOG_MB).unwrap();
    let rules = Rules::builtin();
    let run = pipeline::analyze(&pipeline::Inputs {
        logs: &logs,
        rules: &rules,
        site: &Site::default(),
        oui: &Oui::builtin(),
        previous: None,
        source: "empty".into(),
        generated: GENERATED.into(),
    });
    assert!(run.assets.is_empty());
    let out = dir.join("out");
    report::write_all(&run, None, &out, false).unwrap();
    let s = std::fs::read_to_string(out.join("summary.txt")).unwrap();
    assert!(s.contains("0 devices seen: none."));
    assert!(s.contains("unknown (the logs had no time stamps)"));
}

fn otinv(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_otinv"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn cli_share_folder_is_clean_and_reruns_clear_stale_files() {
    let dir = tmp("cli");
    let (base, bad_out) = (dir.join("base"), dir.join("bad"));
    let s = |p: &Path| p.to_string_lossy().into_owned();
    let o = otinv(&["analyze", &s(&fixture("lab-baseline")), "-o", &s(&base)]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let prev = base.join("run.londopy");
    let o = otinv(&[
        "analyze",
        &s(&fixture("lab-bad")),
        "-o",
        &s(&bad_out),
        "--previous",
        &s(&prev),
        "--pseudonymize",
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));

    // the real reports and the keys stay outside share/
    let share = bad_out.join("share");
    assert!(bad_out.join("run.londopy").is_file());
    assert!(bad_out.join("pseudonym-map.csv").is_file());
    assert!(bad_out.join("summary.txt").is_file());
    let mut names: Vec<String> = std::fs::read_dir(&share)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "README-SHARED.txt",
            "appendix.html",
            "appendix.txt",
            "comms.csv",
            "comms.dot",
            "comms.mmd",
            "diff.html",
            "diff.txt",
            "inventory.csv",
            "summary.txt"
        ]
    );
    let text = all_text(&share);
    assert!(pseudo::addresses_in(&text, &BTreeSet::new()).is_empty());
    for real in [
        "OFFICE-PC1",
        "0x60a1b2c3",
        "lab-bad",
        "base/run.londopy",
        SECRET,
        "10.10.",
        "198.51.100.",
        "203.0.113.",
    ] {
        assert!(!text.contains(real), "{real} leaked into share/");
    }

    // a plain re-run into the same folder leaves no stale share/ or diff
    let o = otinv(&["analyze", &s(&fixture("lab-bad")), "-o", &s(&bad_out)]);
    assert!(o.status.success());
    assert!(!share.exists());
    assert!(!bad_out.join("diff.txt").exists());
    assert!(!bad_out.join("pseudonym-map.csv").exists());
}

#[test]
fn hostile_strings_are_neutralized_in_csv_and_html() {
    let dir = tmp("hostile");
    let logs = dir.join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(
        logs.join("conn.log"),
        "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\thistory\n\
         1793520000.0\tC1\t10.0.0.5\t49152\t10.0.0.10\t502\ttcp\tmodbus\tShADadFf\n",
    )
    .unwrap();
    std::fs::write(
        logs.join("dhcp.log"),
        "#separator \\x09\n#fields\tts\tassigned_addr\tmac\thost_name\n\
         1793520000.0\t10.0.0.5\t00:11:22:33:44:55\t=HYPERLINK(\"http://evil.example/\",\"x\")\n",
    )
    .unwrap();
    let site = Site::parse("[names]\n\"10.0.0.5\" = \"Well <script>alert(1)</script>\"\n").unwrap();
    let logs = zeek::read_dir(&logs, zeek::DEFAULT_MAX_LOG_MB).unwrap();
    let rules = Rules::builtin();
    let run = pipeline::analyze(&pipeline::Inputs {
        logs: &logs,
        rules: &rules,
        site: &site,
        oui: &Oui::builtin(),
        previous: None,
        source: "hostile".into(),
        generated: GENERATED.into(),
    });
    let csv = report::csv::inventory(&run);
    assert!(csv.contains("\"'=HYPERLINK("), "{csv}");
    let html = report::html::appendix(&run);
    assert!(!html.contains("<script>alert"), "unescaped name in HTML");
    assert!(html.contains("&lt;script&gt;"));
}
