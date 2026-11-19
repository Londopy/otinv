// running zeek on a capture (FR-1). otinv doesn't bundle zeek: it uses a zeek
// it can find, in this order of preference when --runner is auto:
//   native  `zeek` on PATH (or --zeek <path>), the normal case on Linux
//   wsl     zeek inside WSL, the easy case on Windows
//   docker  a local image (default otinv-zeek:local, built from
//           docker/zeek-icsnpp/Dockerfile), started with --network none
// otinv never pulls an image or installs anything; that stays the user's call.
//
// zeek runs with its default scripts plus the zkg packages (ICSNPP) and
// MAC logging, but never site/local.zeek: that file can load log writers or
// mail settings that send data off the machine, and otinv only listens.
// zkg packages still load, so a zeek install with, say, a Kafka writer
// package installed would run it; use a dedicated install or the docker image.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const DEFAULT_IMAGE: &str = "otinv-zeek:local";

/// Zeek scripts for every capture: zkg packages (where ICSNPP lives) when
/// zeek has any, and mac-logging, which adds MAC addresses to conn.log.
fn scripts(packages: bool) -> Vec<String> {
    let mut v = Vec::new();
    if packages {
        v.push("packages".to_string());
    }
    v.push("policy/protocols/conn/mac-logging".to_string());
    v
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum RunnerChoice {
    Auto,
    Native,
    Wsl,
    Docker,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Runner {
    /// zeek binary, and whether it has zkg packages to load
    Native(PathBuf, bool),
    /// whether WSL's zeek has zkg packages to load
    Wsl(bool),
    /// image name; the otinv image always has ICSNPP
    Docker(String),
}

/// The exact command that will run, so it can be shown and tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
}

impl Plan {
    pub fn display(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn works(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn detect(choice: RunnerChoice, zeek: Option<&Path>, image: &str) -> Result<Runner> {
    let native = || -> Option<Runner> {
        let exe = zeek
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("zeek"));
        let name = exe.to_string_lossy().into_owned();
        // -a only parses scripts: does `packages` exist on this install?
        works(&name, &["--version"]).then(|| Runner::Native(exe, works(&name, &["-a", "packages"])))
    };
    let wsl = || -> Option<Runner> {
        (cfg!(windows) && works("wsl", &["-e", "zeek", "--version"]))
            .then(|| Runner::Wsl(works("wsl", &["-e", "zeek", "-a", "packages"])))
    };
    let docker = || works("docker", &["image", "inspect", image]);
    let found = match choice {
        RunnerChoice::Native => native(),
        RunnerChoice::Wsl => wsl(),
        RunnerChoice::Docker => docker().then(|| Runner::Docker(image.to_string())),
        RunnerChoice::Auto => native()
            .or_else(wsl)
            .or_else(|| docker().then(|| Runner::Docker(image.to_string()))),
    };
    if let Some(Runner::Native(_, false) | Runner::Wsl(false)) = &found {
        eprintln!(
            "otinv: this zeek has no zkg packages, so the CISA ICSNPP parsers won't run; Modbus and DNP3 still work, EtherNet/IP identity and others won't"
        );
    }
    match found {
        Some(r) => Ok(r),
        None => bail!(
            "couldn't find zeek ({choice:?}). Options:\n  \
             - install zeek and the CISA ICSNPP packages (`zkg install icsnpp-modbus ...`), or\n  \
             - on Windows, install them inside WSL, or\n  \
             - build the image: docker build -t {image} docker/zeek-icsnpp\n\
             Or run zeek yourself and pass the log folder to otinv instead of the capture."
        ),
    }
}

/// `C:\cap\a.pcap` -> `/mnt/c/cap/a.pcap`
pub fn wsl_path(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    let b = s.as_bytes();
    if b.len() >= 2 && b[1] == b':' {
        format!("/mnt/{}{}", s[..1].to_ascii_lowercase(), &s[2..])
    } else {
        s
    }
}

pub fn plan(runner: &Runner, pcap: &Path, logs: &Path) -> Result<Plan> {
    let pcap = std::path::absolute(pcap).context("Resolving the capture path")?;
    let logs = std::path::absolute(logs).context("Resolving the log folder")?;
    let file = pcap
        .file_name()
        .and_then(|n| n.to_str())
        .context("capture has no file name")?
        .to_string();
    // -C: SPAN ports and NIC offload often leave bad checksums; analyze anyway
    let mut zeek_args: Vec<String> = vec!["-C".into(), "-r".into()];
    let plan = match runner {
        Runner::Native(exe, packages) => {
            zeek_args.push(pcap.to_string_lossy().into_owned());
            zeek_args.extend(scripts(*packages));
            Plan {
                program: exe.to_string_lossy().into_owned(),
                args: zeek_args,
                cwd: logs,
            }
        }
        Runner::Wsl(packages) => {
            zeek_args.push(wsl_path(&pcap));
            zeek_args.extend(scripts(*packages));
            let mut args: Vec<String> =
                vec!["--cd".into(), wsl_path(&logs), "-e".into(), "zeek".into()];
            args.extend(zeek_args);
            Plan {
                program: "wsl".into(),
                args,
                cwd: logs,
            }
        }
        Runner::Docker(image) => {
            let dir = pcap.parent().context("capture has no folder")?;
            zeek_args.push(format!("/in/{file}"));
            zeek_args.extend(scripts(true));
            let mut args: Vec<String> = vec![
                "run".into(),
                "--rm".into(),
                // the capture never needs a network, and a utility's data stays put
                "--network".into(),
                "none".into(),
                "-v".into(),
                format!("{}:/in:ro", dir.display()),
                "-v".into(),
                format!("{}:/out", logs.display()),
                "-w".into(),
                "/out".into(),
                image.clone(),
                "zeek".into(),
            ];
            args.extend(zeek_args);
            Plan {
                program: "docker".into(),
                args,
                cwd: logs,
            }
        }
    };
    Ok(plan)
}

pub fn run(runner: &Runner, pcap: &Path, logs: &Path) -> Result<()> {
    std::fs::create_dir_all(logs).with_context(|| format!("Creating {}", logs.display()))?;
    // logs from an earlier capture would otherwise be read as part of this one
    for entry in std::fs::read_dir(logs)?.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "log") {
            std::fs::remove_file(&path).with_context(|| format!("Removing {}", path.display()))?;
        }
    }
    let p = plan(runner, pcap, logs)?;
    eprintln!("running: {}", p.display());
    let out = Command::new(&p.program)
        .args(&p.args)
        .current_dir(&p.cwd)
        .output()
        .with_context(|| format!("Starting {}", p.program))?;
    if !out.status.success() {
        bail!(
            "zeek failed ({}):\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wsl_paths() {
        assert_eq!(wsl_path(Path::new("C:\\cap\\a.pcap")), "/mnt/c/cap/a.pcap");
        assert_eq!(wsl_path(Path::new("/home/x/a.pcap")), "/home/x/a.pcap");
    }

    #[test]
    fn docker_plan_is_offline_and_read_only() {
        let p = plan(
            &Runner::Docker(DEFAULT_IMAGE.into()),
            Path::new("caps/lab.pcap"),
            Path::new("out/zeek-logs"),
        )
        .unwrap();
        assert_eq!(p.program, "docker");
        let s = p.args.join(" ");
        assert!(s.contains("--network none"), "{s}");
        assert!(s.contains(":/in:ro"), "{s}");
        assert!(
            s.contains("zeek -C -r /in/lab.pcap packages policy/protocols/conn/mac-logging"),
            "{s}"
        );
    }

    #[test]
    fn native_plan_runs_in_the_log_folder() {
        let p = plan(
            &Runner::Native("zeek".into(), false),
            Path::new("a.pcap"),
            Path::new("logs"),
        )
        .unwrap();
        assert_eq!(p.program, "zeek");
        assert_eq!(p.args[0..2], ["-C", "-r"]);
        assert!(p.cwd.ends_with("logs"));
        // never the user's local.zeek, and no packages when zeek has none
        assert!(
            !p.args.iter().any(|a| a == "local" || a == "packages"),
            "{:?}",
            p.args
        );
    }
}
