// londopy.rs
// .londopy files: the file format every Londopy app shares, like osu!'s .osz.
// a .londopy is a zip with a londopy.toml manifest that says which app it belongs
// to. otinv saves each analysis run as one (kind "run") so diff mode can compare
// two runs later.
//
// this is the container half of the shared londopy.rs. the Explorer half
// (registry, dispatch, inbox) comes with the Windows installer; a CLI that is
// never installed has nothing to register.
//
// format: londopy-files.md in the londopy-style skill.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::Path;

pub const APP_ID: &str = "otinv";
pub const APP_NAME: &str = "otinv";
pub const HOMEPAGE: &str = "https://github.com/Londopy/otinv";

pub const EXTENSION: &str = "londopy";
pub const MANIFEST_NAME: &str = "londopy.toml";
// newest container version this code understands
pub const FORMAT_VERSION: u32 = 1;
// a manifest is a few hundred bytes; anything huge is not a real .londopy
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

// londopy.toml
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    // container version (FORMAT_VERSION when written)
    pub format: u32,
    // app id that opens this file: lowercase repo slug, e.g. "clipvault"
    pub app: String,
    // what's inside; each app defines its own kinds ("profile", "theme", ...)
    pub kind: String,
    #[serde(default)]
    pub title: String,
    // version of the app that wrote it
    #[serde(default)]
    pub app_version: String,
    // RFC 3339 UTC, e.g. "2026-10-07T22:15:00Z"
    #[serde(default)]
    pub created: String,
    // where to get the app, shown when it isn't installed
    #[serde(default)]
    pub homepage: String,
}

impl Manifest {
    // a manifest for a file this app writes
    pub fn new(kind: &str, title: &str, created: &str) -> Self {
        Self {
            format: FORMAT_VERSION,
            app: APP_ID.into(),
            kind: kind.into(),
            title: title.into(),
            app_version: env!("CARGO_PKG_VERSION").into(),
            created: created.into(),
            homepage: HOMEPAGE.into(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.format == 0 {
            bail!("londopy.toml has no valid format number");
        }
        if self.format > FORMAT_VERSION {
            bail!(
                "this .londopy file uses format {} but this app understands up to {}; update the app",
                self.format,
                FORMAT_VERSION
            );
        }
        if !valid_app_id(&self.app) {
            bail!("londopy.toml has an invalid app id '{}'", self.app);
        }
        if self.kind.trim().is_empty() {
            bail!("londopy.toml has no kind");
        }
        Ok(())
    }
}

// lowercase letters, digits and hyphens, like a repo slug
pub fn valid_app_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

// entry names stay relative and inside the archive: no "..", no drive letters,
// no leading slash, and londopy.toml is reserved
fn safe_entry_name(name: &str) -> bool {
    !name.is_empty()
        && name != MANIFEST_NAME
        && !name.starts_with('/')
        && !name.starts_with('\\')
        && !name.contains(':')
        && name
            .split(['/', '\\'])
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

pub fn is_londopy_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case(EXTENSION))
}

// writes a .londopy: manifest first and uncompressed (cheap to sniff), then
// the payload entries, compressed. goes to a temp file first so a crash
// never leaves half a file behind.
pub fn write(path: &Path, manifest: &Manifest, entries: &[(&str, &[u8])]) -> Result<()> {
    manifest.validate()?;
    for (name, _) in entries {
        if !safe_entry_name(name) {
            bail!("bad entry name '{name}' for a .londopy file");
        }
    }
    let tmp = path.with_extension("londopy.tmp");
    {
        let file =
            std::fs::File::create(&tmp).with_context(|| format!("Creating {}", tmp.display()))?;
        let mut zip = zip::ZipWriter::new(file);
        let stored = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        let deflated = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file(MANIFEST_NAME, stored)?;
        zip.write_all(toml::to_string(manifest)?.as_bytes())?;
        for (name, data) in entries {
            zip.start_file(name.replace('\\', "/"), deflated)?;
            zip.write_all(data)?;
        }
        zip.finish()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("Saving {}", path.display()))?;
    Ok(())
}

// an opened .londopy; read entries on demand with a size cap
pub struct LondopyFile {
    pub manifest: Manifest,
    archive: zip::ZipArchive<std::fs::File>,
}

impl LondopyFile {
    pub fn open(path: &Path) -> Result<Self> {
        let file =
            std::fs::File::open(path).with_context(|| format!("Opening {}", path.display()))?;
        let mut archive = zip::ZipArchive::new(file)
            .with_context(|| format!("{} is not a .londopy file (not a zip)", path.display()))?;
        let raw = read_capped(&mut archive, MANIFEST_NAME, MAX_MANIFEST_BYTES)
            .with_context(|| format!("{} has no readable londopy.toml", path.display()))?;
        let text = String::from_utf8(raw).context("londopy.toml is not UTF-8")?;
        let manifest: Manifest = toml::from_str(&text).context("Parsing londopy.toml")?;
        manifest.validate()?;
        Ok(Self { manifest, archive })
    }

    // payload entry names (londopy.toml and folders left out)
    pub fn entry_names(&self) -> Vec<String> {
        self.archive
            .file_names()
            // zip 9 hands back a Result per name; a name it can't decode is skipped
            .filter_map(|n| n.ok().map(|n| n.into_owned()))
            .filter(|n| n != MANIFEST_NAME && !n.ends_with('/'))
            .collect()
    }

    // reads one entry, refusing anything bigger than max_bytes (zip bombs)
    pub fn read_entry(&mut self, name: &str, max_bytes: u64) -> Result<Vec<u8>> {
        if !safe_entry_name(name) {
            bail!("bad entry name '{name}'");
        }
        read_capped(&mut self.archive, name, max_bytes)
    }
}

fn read_capped<R: Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    name: &str,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    let entry = archive
        .by_name(name)
        .with_context(|| format!("No '{name}' inside"))?;
    if entry.size() > max_bytes {
        bail!(
            "'{name}' is {} bytes, over the {max_bytes} byte limit",
            entry.size()
        );
    }
    // the header size can lie; cap the actual read too
    let mut out = Vec::new();
    entry.take(max_bytes + 1).read_to_end(&mut out)?;
    if out.len() as u64 > max_bytes {
        bail!("'{name}' is over the {max_bytes} byte limit");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("londopy-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn sample() -> Manifest {
        Manifest::new("profile", "Work setup", "2026-10-07T22:15:00Z")
    }

    #[test]
    fn write_then_read_roundtrip() {
        let d = tmpdir("rt");
        let p = d.join("work.londopy");
        write(
            &p,
            &sample(),
            &[("profile.toml", b"x = 1\n"), ("img/icon.png", &[1, 2, 3])],
        )
        .unwrap();
        let mut f = LondopyFile::open(&p).unwrap();
        assert_eq!(f.manifest, sample());
        let mut names = f.entry_names();
        names.sort();
        assert_eq!(names, vec!["img/icon.png", "profile.toml"]);
        assert_eq!(f.read_entry("profile.toml", 1024).unwrap(), b"x = 1\n");
        assert!(!d.join("work.londopy.tmp").exists());
    }

    #[test]
    fn manifest_is_first_and_uncompressed() {
        let d = tmpdir("first");
        let p = d.join("a.londopy");
        write(&p, &sample(), &[("data.bin", &[0u8; 4096])]).unwrap();
        let mut z = zip::ZipArchive::new(std::fs::File::open(&p).unwrap()).unwrap();
        let first = z.by_index(0).unwrap();
        assert_eq!(first.name().unwrap(), MANIFEST_NAME);
        assert_eq!(first.compression(), zip::CompressionMethod::Stored);
    }

    #[test]
    fn rejects_unsafe_entry_names() {
        for bad in [
            "../evil",
            "/abs",
            "C:\\x",
            "a/../b",
            "londopy.toml",
            "",
            "a//b",
        ] {
            assert!(!safe_entry_name(bad), "{bad} should be rejected");
        }
        for good in ["profile.toml", "img/icon.png", "a\\b.txt"] {
            assert!(safe_entry_name(good), "{good} should be allowed");
        }
        let d = tmpdir("unsafe");
        assert!(write(&d.join("x.londopy"), &sample(), &[("../x", b"")]).is_err());
    }

    #[test]
    fn enforces_entry_size_cap() {
        let d = tmpdir("cap");
        let p = d.join("big.londopy");
        write(&p, &sample(), &[("big.bin", &vec![0u8; 100_000])]).unwrap();
        let mut f = LondopyFile::open(&p).unwrap();
        assert!(f.read_entry("big.bin", 1000).is_err());
        assert_eq!(f.read_entry("big.bin", 100_000).unwrap().len(), 100_000);
    }

    #[test]
    fn refuses_newer_format_and_bad_ids() {
        let mut m = sample();
        m.format = FORMAT_VERSION + 1;
        assert!(m
            .validate()
            .unwrap_err()
            .to_string()
            .contains("update the app"));
        let mut m = sample();
        m.app = "Bad App".into();
        assert!(m.validate().is_err());
        assert!(valid_app_id("clip-vault2"));
        assert!(!valid_app_id("ClipVault"));
    }

    #[test]
    fn not_a_zip_is_a_clear_error() {
        let d = tmpdir("nozip");
        let p = d.join("x.londopy");
        std::fs::write(&p, b"hello").unwrap();
        let err = LondopyFile::open(&p).err().unwrap().to_string();
        assert!(err.contains("not a .londopy file"), "{err}");
    }
}
