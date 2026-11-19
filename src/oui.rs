// MAC vendor lookup (the first three bytes of a MAC are the maker's OUI).
//
// the built-in table is a small seed of vendors common on utility control
// networks, so reports say something useful offline. for full coverage,
// download the IEEE registry once (https://standards-oui.ieee.org/oui/oui.csv)
// and pass it with --oui.
// every entry was checked against the IEEE registry on 2026-11-19.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

const BUILTIN: &[(&str, &str)] = &[
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

pub struct Oui {
    table: HashMap<String, String>,
}

impl Oui {
    pub fn builtin() -> Self {
        Self {
            table: BUILTIN
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    /// Built-in table plus the IEEE MA-L CSV ("Registry,Assignment,Organization
    /// Name,Organization Address"). IEEE names win where both have one.
    pub fn with_ieee_csv(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("Reading {}", path.display()))?;
        let mut oui = Self::builtin();
        let mut added = 0;
        for line in text.lines().skip(1) {
            let f = crate::util::parse_csv_line(line);
            if let (Some(a), Some(n)) = (f.get(1), f.get(2)) {
                if a.len() == 6 && a.chars().all(|c| c.is_ascii_hexdigit()) {
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
        self.table.get(&hex[..6].to_ascii_uppercase()).cloned()
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
        assert_eq!(o.vendor("00:11:22:33:44:55"), None);
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
             MA-L,001122,\"Example, Inc.\",Somewhere\n",
        )
        .unwrap();
        let o = Oui::with_ieee_csv(&p).unwrap();
        assert_eq!(
            o.vendor("00:11:22:00:00:01").as_deref(),
            Some("Example, Inc.")
        );
        assert!(o.vendor("00:1d:9c:00:00:01").is_some());
        std::fs::write(&p, "nothing useful\n").unwrap();
        assert!(Oui::with_ieee_csv(&p).is_err());
    }
}
