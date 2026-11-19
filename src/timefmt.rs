// timestamps: zeek writes epoch seconds (TSV) or epoch/ISO 8601 (JSON).
// everything inside otinv is epoch seconds as f64; this turns them into
// readable UTC and back without pulling in a date crate.

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (year, month, day) to days since 1970-01-01.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Epoch seconds to "2026-11-01 08:00:00 UTC".
pub fn utc(ts: f64) -> String {
    let secs = ts.floor() as i64;
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// Epoch seconds to RFC 3339 ("2026-11-01T08:00:00Z").
pub fn rfc3339(ts: f64) -> String {
    // "YYYY-MM-DD HH:MM:SS UTC" -> "YYYY-MM-DDTHH:MM:SSZ"
    let u = utc(ts);
    format!("{}T{}Z", &u[..10], &u[11..19])
}

/// Parses epoch seconds ("1762000000.123") or ISO 8601 / RFC 3339 in UTC
/// ("2026-11-01T08:00:00.123456Z"), the two forms zeek JSON can use.
pub fn parse(s: &str) -> Option<f64> {
    let s = s.trim();
    if let Ok(v) = s.parse::<f64>() {
        return v.is_finite().then_some(v);
    }
    let s = s.strip_suffix('Z').unwrap_or(s);
    let (date, time) = s.split_once(['T', ' '])?;
    let mut dp = date.split('-');
    let y: i64 = dp.next()?.parse().ok()?;
    let m: u32 = dp.next()?.parse().ok()?;
    let d: u32 = dp.next()?.parse().ok()?;
    // the year bound also keeps the day arithmetic far from overflow
    if !(1..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // zeek only writes UTC; refuse offsets rather than guess
    if time.contains('+') || time.get(1..).is_some_and(|t| t.contains('-')) {
        return None;
    }
    let mut tp = time.split(':');
    let h: f64 = tp.next()?.parse().ok()?;
    let mi: f64 = tp.next()?.parse().ok()?;
    let sec: f64 = tp.next().unwrap_or("0").parse().ok()?;
    // "inf" and "1e308" parse as f64; a clock reading can't be either
    if !((0.0..24.0).contains(&h) && (0.0..60.0).contains(&mi) && (0.0..61.0).contains(&sec)) {
        return None;
    }
    Some(days_from_civil(y, m, d) as f64 * 86_400.0 + h * 3600.0 + mi * 60.0 + sec)
}

/// Seconds now, from the system clock.
pub fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// "3 h 20 min", "45 min", "12 s".
pub fn duration(secs: f64) -> String {
    let s = secs.max(0.0).round() as u64;
    match s {
        0..=59 => format!("{s} s"),
        60..=3599 => format!("{} min", s / 60),
        3600..=86_399 => format!("{} h {} min", s / 3600, (s % 3600) / 60),
        _ => format!("{} days {} h", s / 86_400, (s % 86_400) / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(utc(0.0), "1970-01-01 00:00:00 UTC");
        // 2026-11-01T08:00:00Z
        assert_eq!(utc(1_793_520_000.0), "2026-11-01 08:00:00 UTC");
        assert_eq!(rfc3339(1_793_520_000.5), "2026-11-01T08:00:00Z");
        assert_eq!(utc(951_782_400.0), "2000-02-29 00:00:00 UTC");
    }

    #[test]
    fn parses_both_forms() {
        assert_eq!(parse("1793520000.25"), Some(1_793_520_000.25));
        assert_eq!(parse("2026-11-01T08:00:00Z"), Some(1_793_520_000.0));
        assert_eq!(parse("2026-11-01T08:00:01.5Z"), Some(1_793_520_001.5));
        assert_eq!(parse("2026-11-01T08:00:00+02:00"), None);
        assert_eq!(parse("nonsense"), None);
    }

    #[test]
    fn hostile_timestamps_dont_panic() {
        for bad in [
            "2026-11-01T",
            "2026-11-01Té",
            "2026-11-01T\u{e9}:00",
            "9223372036854775807-01-01T00:00:00Z",
            "-5-01-01T00:00:00Z",
            "inf",
            "NaN",
            "2026-11-01Tinf:00:00Z",
            "2026-11-01T1e308:00:00Z",
            "2026-11-01T25:00:00Z",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
        // far-off epochs still format instead of panicking
        let _ = utc(f64::MAX);
        let _ = utc(-1e300);
    }

    #[test]
    fn durations() {
        assert_eq!(duration(12.0), "12 s");
        assert_eq!(duration(3600.0 * 3.0 + 1200.0), "3 h 20 min");
    }
}
