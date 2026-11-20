// MAC vendor lookup (the first three bytes of a MAC are the maker's OUI, or
// more for the smaller MA-M and MA-S blocks).
//
// the whole IEEE registry is built in (data/oui.tsv, refreshed with
// scripts/update_oui.py), so lookups work offline. the short list below
// gives friendlier names for vendors common on control networks; every
// entry was checked against the IEEE registry on 2026-11-19. --oui reads a
// newer IEEE CSV on top.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

const REGISTRY: &str = include_str!("../data/oui.tsv");

const FRIENDLY: &[(&str, &str)] = &[
    ("B827EB", "Raspberry Pi Foundation"),
    ("DCA632", "Raspberry Pi Trading"),
    ("E45F01", "Raspberry Pi Trading"),
    ("D83ADD", "Raspberry Pi Trading"),
    ("2CCF67", "Raspberry Pi (Trading)"),
    ("0000BC", "Rockwell Automation"),
    ("001D9C", "Rockwell Automation"),
    ("5C8816", "Rockwell Automation"),
    ("F45433", "Rockwell Automation"),
    ("000E8C", "Siemens"),
    ("001B1B", "Siemens"),
    ("286336", "Siemens"),
    ("000054", "Schneider Electric"),
    ("0080F4", "Telemecanique (Schneider Electric)"),
    ("00D07C", "JTEKT Electronics (Koyo)"),
    ("0090E8", "Moxa"),
    ("00A045", "Phoenix Contact"),
    ("0030DE", "WAGO"),
    ("000105", "Beckhoff Automation"),
    ("008063", "Hirschmann Automation and Control"),
    ("005056", "VMware"),
    ("000C29", "VMware"),
    ("080027", "PCS Systemtechnik (VirtualBox)"),
];

/// Assignment lengths in hex digits, longest first: MA-S, MA-M, MA-L.
const PREFIXES: [usize; 3] = [9, 7, 6];

pub struct Oui {
    table: HashMap<String, String>,
}

impl Oui {
    pub fn builtin() -> Self {
        let mut table: HashMap<String, String> = REGISTRY
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once('\t'))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        for (k, v) in FRIENDLY {
            table.insert(k.to_string(), v.to_string());
        }
        Self { table }
    }

    /// Built-in table plus an IEEE CSV (oui.csv, mam.csv or oui36.csv:
    /// "Registry,Assignment,Organization Name,Organization Address"). The
    /// file's names win where both have one.
    pub fn with_ieee_csv(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("Reading {}", path.display()))?;
        let mut oui = Self::builtin();
        let mut added = 0;
        for line in text.lines().skip(1) {
            let f = crate::util::parse_csv_line(line);
            if let (Some(a), Some(n)) = (f.get(1), f.get(2)) {
                // IEEE's name on blocks it splits up says nothing about a device
                if n.trim() == "IEEE Registration Authority" {
                    continue;
                }
                if PREFIXES.contains(&a.len()) && a.chars().all(|c| c.is_ascii_hexdigit()) {
                    oui.table
                        .insert(a.to_ascii_uppercase(), n.trim().to_string());
                    added += 1;
                }
            }
        }
        anyhow::ensure!(
            added > 0,
            "{} has no OUI entries; expected IEEE oui.csv",
            path.display()
        );
        Ok(oui)
    }

    pub fn vendor(&self, mac: &str) -> Option<String> {
        let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() != 12 {
            return None;
        }
        let first = u8::from_str_radix(&hex[..2], 16).ok()?;
        // locally administered: phones, VMs and containers make these up
        if first & 0x02 != 0 {
            return Some("(randomized or locally assigned MAC)".into());
        }
        let hex = hex.to_ascii_uppercase();
        PREFIXES
            .iter()
            .find_map(|n| self.table.get(&hex[..*n]))
            .cloned()
    }
}

/// Lowercase colon form: "00:1d:9c:aa:bb:cc".
pub fn normalize_mac(mac: &str) -> Option<String> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 || hex.chars().all(|c| c == '0') || hex.eq_ignore_ascii_case("ffffffffffff")
    {
        return None;
    }
    let lower = hex.to_ascii_lowercase();
    Some(
        (0..6)
            .map(|i| &lower[i * 2..i * 2 + 2])
            .collect::<Vec<_>>()
            .join(":"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_vendors() {
        let o = Oui::builtin();
        assert_eq!(
            o.vendor("00:1D:9C:01:02:03").as_deref(),
            Some("Rockwell Automation")
        );
        assert_eq!(
            o.vendor("b8-27-eb-00-00-01").as_deref(),
            Some("Raspberry Pi Foundation")
        );
        assert!(o
            .vendor("02:00:00:00:00:01")
            .unwrap()
            .contains("randomized"));
        // the whole registry is built in, MA-M blocks inside IEEE's own too
        assert!(o.vendor("00:11:22:33:44:55").is_some());
        assert!(o
            .vendor("c8:5c:e2:70:00:01")
            .is_some_and(|v| v != "IEEE Registration Authority"));
        assert_eq!(o.vendor("nonsense"), None);
    }

    #[test]
    fn normalizes_macs() {
        assert_eq!(
            normalize_mac("00-1D-9C-AA-BB-CC").as_deref(),
            Some("00:1d:9c:aa:bb:cc")
        );
        assert_eq!(normalize_mac("ff:ff:ff:ff:ff:ff"), None);
        assert_eq!(normalize_mac("00:00:00:00:00:00"), None);
    }

    #[test]
    fn reads_ieee_csv() {
        let d = std::env::temp_dir().join(format!("otinv-oui-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("oui.csv");
        std::fs::write(
            &p,
            "Registry,Assignment,Organization Name,Organization Address\n\
             MA-L,001122,\"Example, Inc.\",Somewhere\n\
             MA-L,0C1B2C,IEEE Registration Authority,Piscataway\n\
             MA-M,0C1B2C3,Medium Block Co,Somewhere\n\
             MA-S,0C1B2C4D5,Small Block Co,Somewhere\n",
        )
        .unwrap();
        let o = Oui::with_ieee_csv(&p).unwrap();
        assert_eq!(
            o.vendor("00:11:22:00:00:01").as_deref(),
            Some("Example, Inc.")
        );
        // longest assignment wins; IEEE's own umbrella name is never a vendor
        assert_eq!(
            o.vendor("0c:1b:2c:30:00:01").as_deref(),
            Some("Medium Block Co")
        );
        assert_eq!(
            o.vendor("0c:1b:2c:4d:50:01").as_deref(),
            Some("Small Block Co")
        );
        assert_ne!(
            o.vendor("0c:1b:2c:ff:00:01").as_deref(),
            Some("IEEE Registration Authority")
        );
        // the short names for common control-network vendors beat the registry's
        assert_eq!(o.vendor("00:0e:8c:00:00:01").as_deref(), Some("Siemens"));
        std::fs::write(&p, "nothing useful\n").unwrap();
        assert!(Oui::with_ieee_csv(&p).is_err());
    }
}
