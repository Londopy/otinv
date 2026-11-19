use crate::analyze;
use crate::checks;
use crate::config::{Rules, Site};
use crate::londopy;
use crate::model::{LogSummary, Run, RUN_SCHEMA};
use crate::oui::Oui;
use crate::zeek::Log;
use anyhow::{bail, Context, Result};
use std::path::Path;

/// What one `.londopy` run file may hold at most (zip-bomb guard). Months of
/// a small utility's inventory is a few megabytes.
const MAX_RUN_BYTES: u64 = 256 * 1024 * 1024;
const RUN_ENTRY: &str = "run.json";
pub const RUN_KIND: &str = "run";

pub struct Inputs<'a> {
    pub logs: &'a [Log],
    pub rules: &'a Rules,
    pub site: &'a Site,
    pub oui: &'a Oui,
    pub previous: Option<&'a Run>,
    /// Name of what was analyzed (no full path: reports get shared).
    pub source: String,
    /// RFC 3339 time stamp for the report.
    pub generated: String,
}

pub fn analyze(i: &Inputs) -> Run {
    let conns = analyze::conns(i.logs, i.rules);
    let inv = analyze::inventory(i.logs, &conns, i.rules, i.site, i.oui);
    let findings = checks::run(i.logs, &conns, &inv, i.rules, i.site, i.previous);
    Run {
        schema: RUN_SCHEMA,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        generated: i.generated.clone(),
        site: i.site.name.clone(),
        source: i.source.clone(),
        first_ts: inv.first_ts,
        last_ts: inv.last_ts,
        logs: i
            .logs
            .iter()
            .map(|l| LogSummary {
                file: l.file.clone(),
                name: l.name.clone(),
                records: l.records.len(),
                skipped: l.skipped,
            })
            .collect(),
        assets: inv.assets,
        externals: inv.externals,
        edges: inv.edges,
        findings,
        rules: i.rules.rule.clone(),
        shared_macs: inv.shared_macs,
        pseudonymized: false,
        compared_to: None,
    }
}

pub fn save_run(run: &Run, path: &Path) -> Result<()> {
    let title = if run.site.is_empty() {
        run.source.clone()
    } else {
        run.site.clone()
    };
    let manifest = londopy::Manifest::new(RUN_KIND, &title, &run.generated);
    let json = serde_json::to_vec_pretty(run)?;
    londopy::write(path, &manifest, &[(RUN_ENTRY, &json)])
}

pub fn load_run(path: &Path) -> Result<Run> {
    let mut f = londopy::LondopyFile::open(path)?;
    if f.manifest.app != londopy::APP_ID || f.manifest.kind != RUN_KIND {
        bail!(
            "{} is a '{}' file from {}, not an otinv run",
            path.display(),
            f.manifest.kind,
            f.manifest.app
        );
    }
    let raw = f.read_entry(RUN_ENTRY, MAX_RUN_BYTES)?;
    let run: Run =
        serde_json::from_slice(&raw).with_context(|| format!("Reading {}", path.display()))?;
    if run.schema > RUN_SCHEMA {
        bail!(
            "{} was written by a newer otinv (run schema {}); update otinv",
            path.display(),
            run.schema
        );
    }
    Ok(run)
}
