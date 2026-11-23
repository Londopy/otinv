// `otinv update`: the one command that uses the network, and only when you
// run it. it asks GitHub for the latest release and, once you say yes,
// downloads this platform's binary, checks it against the release's
// SHA256SUMS.txt and swaps it in for the running exe. no background checks,
// no update notices: nothing here runs on its own.
//
// the swap: the new binary is written next to the exe as <exe>.new, the
// running exe is renamed to <exe>.old (windows lets you rename a running exe,
// not delete it), and <exe>.new takes its name. if that fails, <exe>.old is
// renamed back. the next start of otinv deletes the leftover <exe>.old.
//
// the asset names come from .github/workflows/release.yml; change them
// together. a test below fails when they drift apart.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const LATEST_RELEASE: &str = "https://api.github.com/repos/Londopy/otinv/releases/latest";
const DOWNLOADS: &str = "https://github.com/Londopy/otinv/releases/download";
const RELEASES: &str = "https://github.com/Londopy/otinv/releases";
const SUMS: &str = "SHA256SUMS.txt";

// connecting, getting an answer, and every read of a download: a stalled
// connection fails after this long
const TIMEOUT: Duration = Duration::from_secs(30);
// the binary as a whole may take longer on a slow link, as long as each read
// still makes progress within TIMEOUT
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10 * 60);
// caps on what comes back: the release JSON, SHA256SUMS.txt, the binary
const MAX_JSON: u64 = 10 * 1024 * 1024;
const MAX_SUMS: u64 = 1024 * 1024;
const MAX_BINARY: u64 = 256 * 1024 * 1024;

// the parts of GitHub's release JSON otinv reads
#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
}

/// The programs a release ships. Each updates itself and its sibling, so the
/// CLI and the GUI never end up on different versions.
pub const PROGRAMS: [&str; 2] = ["otinv", "otinv-gui"];

/// What GitHub says about the latest release, compared to this build.
pub enum Check {
    /// This build is the latest, or newer; the sentence says which.
    Current(String),
    Available(Offer),
}

/// A newer release, and what installing it here would mean.
pub struct Offer {
    tag: String,
    /// "1.2.3"
    pub version: String,
    /// The release page.
    pub page: String,
    assets: Vec<String>,
}

/// Asks GitHub for the latest release. Only call this when the person asked.
pub fn check() -> Result<Check> {
    let current = env!("CARGO_PKG_VERSION");
    let release: Release =
        serde_json::from_slice(&get(&agent(), LATEST_RELEASE, MAX_JSON, TIMEOUT)?)
            .context("Reading GitHub's answer about the latest release")?;
    let tag = release.tag_name.trim().to_string();
    let latest = Version::parse(&tag)
        .with_context(|| format!("the latest release has a tag otinv can't read: {tag:?}"))?;
    let this = Version::parse(current).context("Reading this build's own version")?;
    let version = tag.trim_start_matches(['v', 'V']).to_string();
    Ok(match latest.cmp(&this) {
        Ordering::Less => Check::Current(format!(
            "otinv {current} is newer than the latest release ({version})."
        )),
        Ordering::Equal => Check::Current(format!("otinv {current} is up to date.")),
        Ordering::Greater => Check::Available(Offer {
            page: format!("{RELEASES}/tag/{tag}"),
            tag,
            version,
            assets: release.assets.into_iter().map(|a| a.name).collect(),
        }),
    })
}

/// The exes to replace: the running one (as `program`), and its sibling
/// program if it sits in the same folder.
fn targets(exe: &Path, program: &str) -> Vec<(&'static str, PathBuf)> {
    let dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
    PROGRAMS
        .iter()
        .filter_map(|p| {
            if *p == program {
                Some((*p, exe.to_path_buf()))
            } else {
                let sibling = dir.join(format!("{p}{}", std::env::consts::EXE_SUFFIX));
                // a renamed exe can carry its sibling's name; it's still itself
                (sibling.is_file() && sibling != exe).then_some((*p, sibling))
            }
        })
        .collect()
}

impl Offer {
    /// Downloads, checks and swaps in the new version of `program` (the
    /// running exe) and of its sibling next to it. `say` gets a line per step.
    pub fn install(&self, program: &str, say: &mut dyn FnMut(String)) -> Result<()> {
        let (tag, new, page) = (&self.tag, &self.version, &self.page);
        let exe = std::env::current_exe().context("Finding otinv's own exe")?;
        let dir = exe.parent().context("otinv's exe has no folder")?;
        let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
        let has = |n: &str| self.assets.iter().any(|a| a == n);
        if !can_replace_in(dir) {
            let manual = manual_asset(program, tag, os, arch, installed_by(dir))
                .filter(|n| has(n))
                .map(|n| format!("\n  {}", download_url(tag, &n)))
                .unwrap_or_default();
            bail!(
                "otinv can't update itself in {}, which is read-only or an all-users install. \
                 Get {new} here:{manual}\n  {page}",
                dir.display()
            );
        }
        let mut downloads = Vec::new();
        for (p, path) in targets(&exe, program) {
            let Some(asset) = binary_asset(p, tag, os, arch) else {
                bail!(
                    "otinv releases have no build for {os}/{arch}; build {new} from source \
                     (see the README)"
                );
            };
            if !has(&asset) {
                bail!("release {tag} has no {asset}; get {new} from {page}");
            }
            downloads.push((asset, path));
        }
        if !has(SUMS) {
            bail!(
                "release {tag} has no {SUMS}, so the download couldn't be checked; nothing was \
                 installed"
            );
        }
        let agent = agent();
        let sums = String::from_utf8(get(&agent, &download_url(tag, SUMS), MAX_SUMS, TIMEOUT)?)
            .with_context(|| format!("Reading {SUMS}"))?;
        // everything is downloaded and checked before anything is replaced
        let mut checked = Vec::new();
        for (asset, path) in downloads {
            let expected = expected_hash(&sums, &asset)?;
            say(format!("Downloading {asset} ..."));
            let bytes = get(
                &agent,
                &download_url(tag, &asset),
                MAX_BINARY,
                DOWNLOAD_TIMEOUT,
            )?;
            let actual = sha256_hex(&bytes);
            if actual != expected {
                bail!(
                    "{asset} doesn't match {SUMS} (expected SHA-256 {expected}, got {actual}); \
                     nothing was installed"
                );
            }
            say("SHA-256 verified.".to_string());
            checked.push((path, bytes));
        }
        let mut swapped: Vec<PathBuf> = Vec::new();
        for (path, bytes) in checked {
            if let Err(e) = replace_exe(&path, &bytes) {
                // both programs stay on one version: undo the ones already swapped
                for done in &swapped {
                    if let Err(undo) = restore(done) {
                        say(format!(
                            "Couldn't put back the old {}: {undo:#}",
                            done.display()
                        ));
                    }
                }
                return Err(e);
            }
            swapped.push(path);
        }
        for path in swapped {
            say(format!("Updated {} to {new}.", path.display()));
        }
        Ok(())
    }
}

/// Puts the `<exe>.old` an update left back in place of `exe`.
fn restore(exe: &Path) -> Result<()> {
    let aside = new_path(exe);
    let _ = std::fs::remove_file(&aside);
    rename(exe, &aside).with_context(|| format!("Moving {} aside", exe.display()))?;
    rename(&old_path(exe), exe).with_context(|| format!("Restoring {}", exe.display()))?;
    // a running exe can't be deleted yet; the next start sweeps it up
    let _ = std::fs::remove_file(&aside);
    Ok(())
}

/// `otinv update`: the terminal version of check, ask, install.
pub fn run(check_only: bool, yes: bool) -> Result<()> {
    let offer = match check()? {
        Check::Current(msg) => {
            println!("{msg}");
            return Ok(());
        }
        Check::Available(o) => o,
    };
    println!(
        "otinv {} is installed; {} is available: {}",
        env!("CARGO_PKG_VERSION"),
        offer.version,
        offer.page
    );
    if check_only {
        println!("Run `otinv update` to install it.");
        return Ok(());
    }
    if !confirm(&offer.version, yes)? {
        println!("Nothing changed.");
        return Ok(());
    }
    offer.install("otinv", &mut |line| println!("{line}"))
}
/// Deletes the `<exe>.old` an earlier `otinv update` left next to the exe.
/// Runs first thing on every start; best effort and silent.
pub fn remove_leftover() {
    if let Ok(exe) = std::env::current_exe() {
        remove_old(&exe);
        // the sibling program's too: an update from the GUI swaps otinv.exe
        // as well, and the command line may never be started again
        let dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
        for p in PROGRAMS {
            remove_old(&dir.join(format!("{p}{}", std::env::consts::EXE_SUFFIX)));
        }
    }
}

fn remove_old(exe: &Path) {
    let _ = std::fs::remove_file(old_path(exe));
    let _ = std::fs::remove_file(new_path(exe));
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .user_agent(format!("otinv/{}", env!("CARGO_PKG_VERSION")))
        // downloads redirect to GitHub's CDN; never follow one to plain http
        .https_only(true)
        // get() turns statuses into messages
        .http_status_as_error(false)
        .timeout_connect(Some(TIMEOUT))
        .timeout_recv_response(Some(TIMEOUT))
        .timeout_per_read(Some(TIMEOUT))
        .build()
        .into()
}

/// GETs `url` and returns the body: at most `limit` bytes, all of it within
/// `timeout`.
fn get(agent: &ureq::Agent, url: &str, limit: u64, timeout: Duration) -> Result<Vec<u8>> {
    let mut request = agent
        .get(url)
        .config()
        .timeout_global(Some(timeout))
        .build();
    if url == LATEST_RELEASE {
        request = request.header("Accept", "application/vnd.github+json");
    }
    let host = url.split('/').nth(2).unwrap_or(url);
    let mut response = request.call().with_context(|| format!("Reaching {host}"))?;
    match response.status().as_u16() {
        200 => {}
        404 if url == LATEST_RELEASE => bail!("otinv has no published release yet; see {RELEASES}"),
        s @ (403 | 429) => bail!(
            "GitHub turned the request down (HTTP {s}). Without a login it allows 60 requests \
             an hour from one address; try again later"
        ),
        s => bail!("GitHub answered HTTP {s} for {url}"),
    }
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .with_context(|| format!("Downloading {url}"))
}

fn download_url(tag: &str, name: &str) -> String {
    format!("{DOWNLOADS}/{tag}/{name}")
}

/// Asks "Install vX? [y/N]" on the terminal. `--yes` skips the question;
/// without a terminal to ask in, otinv refuses rather than guess.
fn confirm(version: &str, yes: bool) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        bail!(
            "not installing {version} without asking, and there's no terminal to ask in. \
             Run `otinv update --yes` to install it anyway"
        );
    }
    // on stderr, so the question shows even when stdout goes to a file
    eprint!("Install v{version}? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("Reading the answer")?;
    Ok(is_yes(&answer))
}

fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// A release version: major.minor.patch with an optional prerelease suffix.
/// Hand-written; this is all the comparing otinv does.
#[derive(Debug, Clone)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    // "rc.1" in 1.2.0-rc.1, empty for a release
    pre: String,
}

impl Version {
    /// "1.2.3", "v1.2.3" or "1.2.3-rc.1". Build metadata ("+abc") is checked,
    /// then ignored, as semver says.
    fn parse(s: &str) -> Option<Version> {
        let s = s.trim();
        let s = s.strip_prefix(['v', 'V']).unwrap_or(s);
        let (s, build) = match s.split_once('+') {
            Some((s, build)) => (s, Some(build)),
            None => (s, None),
        };
        let (core, pre) = match s.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (s, None),
        };
        if !pre.into_iter().chain(build).all(identifiers) {
            return None;
        }
        let mut parts = core.split('.');
        let version = Version {
            major: number(parts.next()?)?,
            minor: number(parts.next()?)?,
            patch: number(parts.next()?)?,
            pre: pre.unwrap_or_default().to_string(),
        };
        parts.next().is_none().then_some(version)
    }
}

// a run of ASCII digits; no sign, no spaces
fn number(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

// semver's dot-separated identifiers: [0-9A-Za-z-], none empty
fn identifiers(s: &str) -> bool {
    s.split('.')
        .all(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| cmp_prerelease(&self.pre, &other.pre))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

/// Semver's prerelease order: no suffix sorts above any suffix (1.0.0-rc.1 <
/// 1.0.0). Otherwise the dot-separated parts compare left to right: numbers
/// as numbers, numbers below words, words as text, fewer parts first.
fn cmp_prerelease(a: &str, b: &str) -> Ordering {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        (false, false) => {}
    }
    let (mut a, mut b) = (a.split('.'), b.split('.'));
    loop {
        let (x, y) = match (a.next(), b.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => (x, y),
        };
        let order = match (number(x), number(y)) {
            (Some(m), Some(n)) => m.cmp(&n),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => x.cmp(y),
        };
        if order != Ordering::Equal {
            return order;
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest.iter() {
        hex.push(char::from(DIGITS[usize::from(b >> 4)]));
        hex.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    hex
}

/// The entries of a sha256sum-style file: "<64 hex>  <name>" (text mode) or
/// "<64 hex> *<name>" (binary mode), hashes lowercased. Other lines are
/// skipped.
fn parse_sums(text: &str) -> Vec<(&str, String)> {
    text.trim_start_matches('\u{feff}')
        .lines()
        .filter_map(|line| {
            let line = line.trim_end_matches('\r');
            let hash = line.get(..64)?;
            if !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            let rest = line.get(64..)?;
            let name = rest
                .strip_prefix("  ")
                .or_else(|| rest.strip_prefix(" *"))?;
            Some((name, hash.to_ascii_lowercase()))
        })
        .collect()
}

/// The SHA-256 `sums` lists for `name`. No entry is an error, and so are two
/// entries that disagree: either way nothing gets installed.
fn expected_hash(sums: &str, name: &str) -> Result<String> {
    let mut found: Option<String> = None;
    for (entry, hash) in parse_sums(sums) {
        if entry != name {
            continue;
        }
        if found.as_ref().is_some_and(|f| *f != hash) {
            bail!("{SUMS} lists {name} twice with different hashes; nothing was installed");
        }
        found = Some(hash);
    }
    found.with_context(|| {
        format!("{SUMS} has no entry for {name}, so it can't be checked; nothing was installed")
    })
}

// the windows architecture names in asset file names
fn windows_arch(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("x64"),
        "x86" => Some("x86"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

/// The standalone binary the release workflow publishes for `os`/`arch`
/// (`std::env::consts` names) and program: otinv-v1.2.3-x64-portable.exe (or
/// x86, arm64, and otinv-gui-...) on Windows, otinv-v1.2.3-linux-x86_64 on Linux. Linux gets the bare binary
/// rather than the tar.gz so that otinv needs no tar or gzip code.
fn binary_asset(program: &str, tag: &str, os: &str, arch: &str) -> Option<String> {
    match (os, arch) {
        ("windows", _) => Some(format!(
            "{program}-{tag}-{}-portable.exe",
            windows_arch(arch)?
        )),
        ("linux", "x86_64") => Some(format!("{program}-{tag}-linux-x86_64")),
        _ => None,
    }
}

/// How the copy next to an exe was installed, from what installers leave
/// beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Installed {
    // install.ini with source=msi, written by the MSI
    Msi,
    // unins000.exe, Inno Setup's uninstaller
    Setup,
    // portable exe, zip, tar.gz, or something else
    Other,
}

fn installed_by(dir: &Path) -> Installed {
    let ini = std::fs::read_to_string(dir.join("install.ini")).unwrap_or_default();
    if ini_says_msi(&ini) {
        Installed::Msi
    } else if dir.join("unins000.exe").is_file() {
        Installed::Setup
    } else {
        Installed::Other
    }
}

// the MSI writes install.ini ([install] source=msi) next to the exe
fn ini_says_msi(ini: &str) -> bool {
    ini.lines()
        .map(|l| l.trim().to_ascii_lowercase().replace(' ', ""))
        .any(|l| l == "source=msi")
}

/// What to download by hand when otinv can't replace itself: the installer
/// that put it there (the MSI for its architecture, or the setup.exe), the
/// portable exe for any other Windows copy, the tar.gz on Linux.
fn manual_asset(
    program: &str,
    tag: &str,
    os: &str,
    arch: &str,
    installed: Installed,
) -> Option<String> {
    let version = tag.trim_start_matches(['v', 'V']);
    match os {
        "windows" => {
            let arch = windows_arch(arch)?;
            Some(match installed {
                Installed::Msi => format!("otinv-{version}-{arch}.msi"),
                // the setup.exe is x64 only
                Installed::Setup => format!("otinv-{version}-setup-x64.exe"),
                Installed::Other => format!("{program}-{tag}-{arch}-portable.exe"),
            })
        }
        "linux" if arch == "x86_64" => Some(format!("otinv-{tag}-linux-x86_64.tar.gz")),
        _ => None,
    }
}

/// Whether otinv may swap its exe in `dir`: the folder has to take a test
/// write, and not be under Program Files. There a 32-bit otinv (no UAC
/// manifest) can have its writes quietly redirected to the VirtualStore, and
/// an all-users install should be updated with its installer anyway.
fn can_replace_in(dir: &Path) -> bool {
    !under_any(dir, &program_files()) && dir_is_writable(dir)
}

fn program_files() -> Vec<PathBuf> {
    if !cfg!(windows) {
        return Vec::new();
    }
    ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
        .into_iter()
        .filter_map(std::env::var_os)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Whether `dir` is inside one of `roots`, ignoring case and a `\\?\` prefix
/// (windows paths).
fn under_any(dir: &Path, roots: &[PathBuf]) -> bool {
    fn plain(p: &Path) -> PathBuf {
        let s = p.to_string_lossy().to_lowercase();
        PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s))
    }
    let dir = plain(dir);
    roots.iter().any(|root| dir.starts_with(plain(root)))
}

// actually tries a write: permission bits don't tell the whole story on windows
fn dir_is_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".otinv-write-test-{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(file) => {
            drop(file);
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn with_suffix(exe: &Path, suffix: &str) -> PathBuf {
    let mut s = exe.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

fn old_path(exe: &Path) -> PathBuf {
    with_suffix(exe, ".old")
}

fn new_path(exe: &Path) -> PathBuf {
    with_suffix(exe, ".new")
}

/// Writes `bytes` to `<exe>.new` and swaps it in for `exe`. When anything
/// fails, `exe` is the old version again and `<exe>.new` is gone.
fn replace_exe(exe: &Path, bytes: &[u8]) -> Result<()> {
    let staged = new_path(exe);
    let result = write_staged(exe, &staged, bytes).and_then(|()| swap_in(exe, &staged));
    if result.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    result
}

fn write_staged(exe: &Path, staged: &Path, bytes: &[u8]) -> Result<()> {
    let mut file =
        std::fs::File::create(staged).with_context(|| format!("Creating {}", staged.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("Writing {}", staged.display()))?;
    drop(file);
    copy_permissions(exe, staged)
}

// keeps the exe's mode, so the new binary is executable too
#[cfg(unix)]
fn copy_permissions(from: &Path, to: &Path) -> Result<()> {
    let permissions = std::fs::metadata(from)
        .with_context(|| format!("Reading {}", from.display()))?
        .permissions();
    std::fs::set_permissions(to, permissions)
        .with_context(|| format!("Setting the permissions of {}", to.display()))
}

#[cfg(not(unix))]
fn copy_permissions(_from: &Path, _to: &Path) -> Result<()> {
    Ok(())
}

/// Renames `exe` to `<exe>.old`, then `staged` to `exe`. If the second rename
/// fails the first is undone, so `exe` is always a working otinv.
fn swap_in(exe: &Path, staged: &Path) -> Result<()> {
    let old = old_path(exe);
    // left by an earlier update whose cleanup at start didn't get to it
    if old.exists() {
        std::fs::remove_file(&old).with_context(|| {
            format!(
                "Removing {}, left over from an earlier update",
                old.display()
            )
        })?;
    }
    rename(exe, &old)
        .with_context(|| format!("Renaming {} to {}", exe.display(), old.display()))?;
    if let Err(e) = rename(staged, exe) {
        return match rename(&old, exe) {
            Ok(()) => Err(e).with_context(|| {
                format!(
                    "Moving the new version to {}; the old version is back in place",
                    exe.display()
                )
            }),
            Err(back) => Err(e).with_context(|| {
                format!(
                    "Moving the new version to {} failed, and so did putting the old one back \
                     ({back}). Rename {} to {} to restore it",
                    exe.display(),
                    old.display(),
                    exe.display()
                )
            }),
        };
    }
    Ok(())
}

// on windows a virus scanner often holds a just-written exe open for a moment,
// so a rename gets a few short retries there
fn rename(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut tries = 0;
    loop {
        match std::fs::rename(from, to) {
            Err(e) if cfg!(windows) && e.kind() != std::io::ErrorKind::NotFound && tries < 5 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(200));
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|| panic!("{s} should parse"))
    }

    // a fresh folder under the temp dir, removed when dropped
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("otinv-update-test-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        // an "exe" holding `content`
        fn exe(&self, content: &str) -> PathBuf {
            let exe = self.0.join("otinv.exe");
            std::fs::write(&exe, content).unwrap();
            exe
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn versions_parse() {
        let x = v("v1.2.3");
        assert_eq!((x.major, x.minor, x.patch, x.pre.as_str()), (1, 2, 3, ""));
        assert_eq!(v("V0.10.0-rc.1").pre, "rc.1");
        assert_eq!(v(" 1.2.3+build.5 ").pre, "");
        assert_eq!(v("1.2.3-rc-1+sha.0a1b").pre, "rc-1");
        for bad in [
            "",
            "v",
            "1.2",
            "1.2.3.4",
            "1.x.3",
            "+1.2.3",
            "1.2.3-",
            "1.2.3-rc..1",
            "1.2.3+",
            "1.2.3-rc/1",
            "1.2.3 beta",
            "-1.2.3",
        ] {
            assert!(Version::parse(bad).is_none(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn versions_compare_like_semver() {
        // semver.org's own example order, then plain releases
        let order = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.2.0",
            "1.10.0",
            "2.0.0",
        ];
        for pair in order.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
            assert!(v(pair[1]) > v(pair[0]), "{} > {}", pair[1], pair[0]);
        }
        // numbers, not text: 0.10.0 is newer than 0.9.0
        assert!(v("0.10.0") > v("0.9.0"));
        // a prerelease sorts below its release, above the one before
        assert!(v("0.2.0-rc1") < v("0.2.0"));
        assert!(v("0.2.0-rc1") > v("0.1.9"));
        assert!(v("0.2.0-rc1") < v("0.2.0-rc2"));
        assert_eq!(v("v0.2.0"), v("0.2.0"));
        assert_eq!(v("1.0.0+build.1"), v("1.0.0+build.2"));
        // this build's own version always parses
        assert!(Version::parse(env!("CARGO_PKG_VERSION")).is_some());
    }

    #[test]
    fn sha256_hex_is_lowercase_hex() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sums_parse_text_and_binary_mode_lines() {
        let (a, b, c) = ("a".repeat(64), "B".repeat(64), "c".repeat(64));
        let sums = format!(
            "\u{feff}{a}  otinv-v1.2.3-x64-portable.exe\r\n\
             {b} *otinv-v1.2.3-linux-x86_64\n\
             not a checksum line\n\
             abc123  short-hash.exe\n\
             {c}  otinv-v1.2.3-x64-portable.exe.torrent\n\
             {a}  name with spaces.zip\n"
        );
        assert_eq!(
            expected_hash(&sums, "otinv-v1.2.3-x64-portable.exe").unwrap(),
            a
        );
        // "hash *name" works too, and hashes come back lowercase
        assert_eq!(
            expected_hash(&sums, "otinv-v1.2.3-linux-x86_64").unwrap(),
            "b".repeat(64)
        );
        assert_eq!(expected_hash(&sums, "name with spaces.zip").unwrap(), a);
        let entries = parse_sums(&sums);
        assert_eq!(entries.len(), 4);
        assert!(entries.iter().all(|(name, _)| *name != "short-hash.exe"));
    }

    #[test]
    fn a_missing_or_ambiguous_sum_is_an_error() {
        let (a, b) = ("a".repeat(64), "b".repeat(64));
        let sums = format!("{a}  otinv-v1.2.3-x64-portable.exe\n");
        let err = expected_hash(&sums, "otinv-v1.2.3-arm64-portable.exe").unwrap_err();
        assert!(err.to_string().contains("no entry"), "{err}");
        // a prefix of a listed name is not a match
        assert!(expected_hash(&sums, "otinv-v1.2.3-x64-portable").is_err());
        let twice = format!("{a}  otinv.exe\n{b}  otinv.exe\n");
        assert!(expected_hash(&twice, "otinv.exe").is_err());
        let same_twice = format!("{a}  otinv.exe\n{a} *otinv.exe\n");
        assert_eq!(expected_hash(&same_twice, "otinv.exe").unwrap(), a);
        assert!(expected_hash("", "otinv.exe").is_err());
    }

    #[test]
    fn the_binary_matches_the_os_and_architecture() {
        let tag = "v1.2.3";
        let asset = |os, arch| binary_asset("otinv", tag, os, arch);
        assert_eq!(
            asset("windows", "x86_64").as_deref(),
            Some("otinv-v1.2.3-x64-portable.exe")
        );
        assert_eq!(
            asset("windows", "x86").as_deref(),
            Some("otinv-v1.2.3-x86-portable.exe")
        );
        assert_eq!(
            asset("windows", "aarch64").as_deref(),
            Some("otinv-v1.2.3-arm64-portable.exe")
        );
        assert_eq!(
            asset("linux", "x86_64").as_deref(),
            Some("otinv-v1.2.3-linux-x86_64")
        );
        // no release builds for these
        assert_eq!(asset("linux", "aarch64"), None);
        assert_eq!(asset("macos", "aarch64"), None);
        assert_eq!(asset("windows", "riscv64"), None);
    }

    #[test]
    fn read_only_copies_point_at_their_installer() {
        use Installed::*;
        let tag = "v1.2.3";
        let manual = |os, arch, how| manual_asset("otinv", tag, os, arch, how);
        assert_eq!(
            manual("windows", "x86_64", Msi).as_deref(),
            Some("otinv-1.2.3-x64.msi")
        );
        assert_eq!(
            manual("windows", "aarch64", Msi).as_deref(),
            Some("otinv-1.2.3-arm64.msi")
        );
        assert_eq!(
            manual("windows", "x86_64", Setup).as_deref(),
            Some("otinv-1.2.3-setup-x64.exe")
        );
        assert_eq!(
            manual("windows", "x86", Other).as_deref(),
            Some("otinv-v1.2.3-x86-portable.exe")
        );
        assert_eq!(
            manual("linux", "x86_64", Other).as_deref(),
            Some("otinv-v1.2.3-linux-x86_64.tar.gz")
        );
        assert_eq!(manual("macos", "aarch64", Other), None);
    }

    #[test]
    fn install_markers_are_read() {
        assert!(ini_says_msi("[install]\r\nsource=msi\r\n"));
        assert!(ini_says_msi("[install]\nSource = MSI\n"));
        assert!(!ini_says_msi("[install]\nsource=inno\n"));
        assert!(!ini_says_msi(""));
        let d = Scratch::new("markers");
        assert_eq!(installed_by(&d.0), Installed::Other);
        std::fs::write(d.0.join("unins000.exe"), "").unwrap();
        assert_eq!(installed_by(&d.0), Installed::Setup);
        std::fs::write(d.0.join("install.ini"), "[install]\r\nsource=msi\r\n").unwrap();
        assert_eq!(installed_by(&d.0), Installed::Msi);
    }

    #[test]
    fn program_files_is_matched_by_folder_and_any_case() {
        let base = std::env::temp_dir();
        let pf = base.join("Program Files");
        let pf86 = base.join("Program Files (x86)");
        let roots = [pf.clone()];
        assert!(under_any(&pf.join("otinv"), &roots));
        let shouting = PathBuf::from(pf.join("otinv").to_string_lossy().to_uppercase());
        assert!(under_any(&shouting, &roots));
        // a sibling whose name starts the same is not inside it
        assert!(!under_any(&pf86.join("otinv"), &roots));
        assert!(under_any(&pf86.join("otinv"), &[pf.clone(), pf86.clone()]));
        assert!(!under_any(
            &base.join("Programs").join("otinv"),
            &[pf, pf86]
        ));
        assert!(!under_any(&base, &[]));
    }

    #[cfg(windows)]
    #[test]
    fn program_files_is_matched_through_a_verbatim_prefix() {
        let roots = [PathBuf::from(r"C:\Program Files")];
        assert!(under_any(Path::new(r"\\?\C:\Program Files\otinv"), &roots));
        assert!(!under_any(
            Path::new(r"C:\Users\x\AppData\Local\Programs\otinv"),
            &roots
        ));
    }

    #[test]
    fn the_write_probe_cleans_up_after_itself() {
        let d = Scratch::new("probe");
        assert!(dir_is_writable(&d.0));
        assert_eq!(std::fs::read_dir(&d.0).unwrap().count(), 0);
        assert!(!dir_is_writable(&d.0.join("missing")));
    }

    #[test]
    fn the_new_exe_takes_the_old_ones_place() {
        let d = Scratch::new("swap");
        let exe = d.exe("old build");
        replace_exe(&exe, b"new build").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new build");
        assert_eq!(std::fs::read(old_path(&exe)).unwrap(), b"old build");
        assert!(!new_path(&exe).exists());
        // what the next start does
        remove_old(&exe);
        assert!(!old_path(&exe).exists());
        assert_eq!(std::fs::read(&exe).unwrap(), b"new build");
        // and when there's nothing to clean up, nothing happens
        remove_old(&exe);
        assert_eq!(std::fs::read(&exe).unwrap(), b"new build");
    }

    #[test]
    fn a_leftover_old_from_an_earlier_update_is_replaced() {
        let d = Scratch::new("stale");
        let exe = d.exe("build 2");
        std::fs::write(old_path(&exe), "build 1").unwrap();
        replace_exe(&exe, b"build 3").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"build 3");
        assert_eq!(std::fs::read(old_path(&exe)).unwrap(), b"build 2");
    }

    #[test]
    fn a_failed_swap_puts_the_old_exe_back() {
        let d = Scratch::new("rollback");
        let exe = d.exe("old build");
        // nothing staged: renaming the exe away works, moving the new one in fails
        let err = swap_in(&exe, &new_path(&exe)).unwrap_err();
        assert!(format!("{err:#}").contains("back in place"), "{err:#}");
        assert_eq!(std::fs::read(&exe).unwrap(), b"old build");
        assert!(!old_path(&exe).exists());
    }

    #[test]
    fn a_failed_download_write_changes_nothing() {
        let d = Scratch::new("stage-fails");
        let exe = d.exe("old build");
        // a folder where <exe>.new should go: writing the new version fails
        std::fs::create_dir(new_path(&exe)).unwrap();
        assert!(replace_exe(&exe, b"new build").is_err());
        assert_eq!(std::fs::read(&exe).unwrap(), b"old build");
        assert!(!old_path(&exe).exists());
    }

    #[test]
    fn a_missing_exe_is_an_error_and_leaves_no_staged_file() {
        let d = Scratch::new("no-exe");
        let exe = d.0.join("otinv.exe");
        assert!(replace_exe(&exe, b"new build").is_err());
        assert!(!exe.exists());
        assert!(!new_path(&exe).exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_new_exe_keeps_the_old_ones_mode() {
        use std::os::unix::fs::PermissionsExt;
        let d = Scratch::new("mode");
        let exe = d.exe("old build");
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        replace_exe(&exe, b"new build").unwrap();
        let mode = std::fs::metadata(&exe).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[test]
    fn only_yes_means_yes() {
        for answer in ["y", "Y", "yes", " YES \r\n", "y\n"] {
            assert!(is_yes(answer), "{answer:?}");
        }
        for answer in ["", "\n", "n", "no", "yep", "y es", "1"] {
            assert!(!is_yes(answer), "{answer:?}");
        }
    }

    #[test]
    fn download_urls_point_at_the_release() {
        assert_eq!(
            download_url("v1.2.3", SUMS),
            "https://github.com/Londopy/otinv/releases/download/v1.2.3/SHA256SUMS.txt"
        );
    }

    // the names above are what the release workflow and installers produce;
    // if one side changes, this fails until the other does too
    #[test]
    fn names_match_the_release_workflow() {
        let workflow = include_str!("../.github/workflows/release.yml");
        let inno = include_str!("../installer/otinv.iss");
        let notes = include_str!("../scripts/release_notes.py");
        let tag = "v1.2.3";
        for (arch, label) in [("x86_64", "x64"), ("x86", "x86"), ("aarch64", "arm64")] {
            let portable = "otinv-$tag-$arch-portable.exe";
            assert!(workflow.contains(portable), "{portable}");
            assert_eq!(
                binary_asset("otinv", tag, "windows", arch).unwrap(),
                portable.replace("$tag", tag).replace("$arch", label)
            );
            let msi = "otinv-$ver-${{ matrix.label }}.msi";
            assert!(workflow.contains(msi), "{msi}");
            assert_eq!(
                manual_asset("otinv", tag, "windows", arch, Installed::Msi).unwrap(),
                msi.replace("$ver", "1.2.3")
                    .replace("${{ matrix.label }}", label)
            );
        }
        let linux = "otinv-${TAG}-linux-x86_64";
        assert!(workflow.contains(linux), "{linux}");
        assert_eq!(
            binary_asset("otinv", tag, "linux", "x86_64").unwrap(),
            linux.replace("${TAG}", tag)
        );
        assert!(workflow.contains(r#"tar -C pkg -czf "out/$name.tar.gz""#));
        assert_eq!(
            manual_asset("otinv", tag, "linux", "x86_64", Installed::Other).unwrap(),
            format!("{}.tar.gz", linux.replace("${TAG}", tag))
        );
        let setup = "OutputBaseFilename=otinv-{#AppVersion}-setup-x64";
        assert!(inno.contains(setup), "{setup}");
        assert_eq!(
            manual_asset("otinv", tag, "windows", "x86_64", Installed::Setup).unwrap(),
            "otinv-1.2.3-setup-x64.exe"
        );
        assert!(notes.contains(&format!("\"{SUMS}\"")));

        // the GUI's own downloads, which it and its sibling update to
        for (arch, label) in [("x86_64", "x64"), ("x86", "x86"), ("aarch64", "arm64")] {
            let portable = "otinv-gui-$tag-$arch-portable.exe";
            assert!(workflow.contains(portable), "{portable}");
            assert_eq!(
                binary_asset("otinv-gui", tag, "windows", arch).unwrap(),
                portable.replace("$tag", tag).replace("$arch", label)
            );
        }
        let gui_linux = "otinv-gui-${TAG}-linux-x86_64";
        assert!(workflow.contains(gui_linux), "{gui_linux}");
        assert_eq!(
            binary_asset("otinv-gui", tag, "linux", "x86_64").unwrap(),
            gui_linux.replace("${TAG}", tag)
        );
        assert!(inno.contains("#define GuiExeName   \"otinv-gui.exe\""));
    }

    #[test]
    fn a_swapped_exe_can_be_put_back() {
        let t = Scratch::new("restore");
        let exe = t.exe("old version");
        replace_exe(&exe, b"new version").unwrap();
        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "new version");
        restore(&exe).unwrap();
        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "old version");
        assert!(!old_path(&exe).exists() && !new_path(&exe).exists());
    }

    #[test]
    fn updates_the_sibling_program_too() {
        let t = Scratch::new("sibling");
        let cli = t.exe("cli");
        let sibling = cli.with_file_name(format!("otinv-gui{}", std::env::consts::EXE_SUFFIX));
        // no GUI next to it: only the running exe
        let only: Vec<&str> = targets(&cli, "otinv").iter().map(|(p, _)| *p).collect();
        assert_eq!(only, ["otinv"]);
        std::fs::write(&sibling, "gui").unwrap();
        let both: Vec<(&str, PathBuf)> = targets(&cli, "otinv");
        assert_eq!(both, [("otinv", cli.clone()), ("otinv-gui", sibling)]);
        // the running exe keeps its own name, however it was renamed
        let from_gui: Vec<&str> = targets(&cli, "otinv-gui").iter().map(|(p, _)| *p).collect();
        assert_eq!(from_gui, ["otinv-gui"]);
    }
}
