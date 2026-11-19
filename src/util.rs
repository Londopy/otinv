// small text helpers shared by the readers and the report writers.
// hand-written on purpose: each is a few lines and saves a dependency.

/// Quotes one CSV field when it needs it (RFC 4180). Any device on the
/// mirrored network chooses its own host name and model string, so a value
/// starting like a spreadsheet formula gets a leading `'` and opens as text.
pub fn csv_field(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

/// Joins fields into one CSV line, without the line ending.
pub fn csv_line<S: AsRef<str>>(fields: &[S]) -> String {
    fields
        .iter()
        .map(|f| csv_field(f.as_ref()))
        .collect::<Vec<_>>()
        .join(",")
}

/// Splits one CSV line into fields. Handles quotes and doubled quotes; a field
/// can't span lines, which is fine for the files otinv reads (IEEE oui.csv).
pub fn parse_csv_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            ('"', true) => quoted = false,
            ('"', false) if cur.is_empty() => quoted = true,
            (',', false) => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// Escapes text for HTML element content and attribute values.
pub fn html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Word-wraps `text` to `width` columns. Every line gets `indent`, except the
/// first, which gets `first` (so numbered lists hang nicely).
pub fn wrap(text: &str, width: usize, first: &str, indent: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut line = first.to_string();
    let mut empty = true;
    for word in text.split_whitespace() {
        let need = if empty { word.len() } else { word.len() + 1 };
        if !empty && line.chars().count() + need > width {
            lines.push(std::mem::replace(&mut line, indent.to_string()));
            empty = true;
        }
        if !empty {
            line.push(' ');
        }
        line.push_str(word);
        empty = false;
    }
    lines.push(line);
    lines.join("\n")
}

/// "1 controller" / "3 controllers".
pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Joins a list as plain English: "a", "a and b", "a, b and c". Long lists
/// are cut after `max` items with "and N more".
pub fn english_list(items: &[String], max: usize) -> String {
    let shown: Vec<&String> = items.iter().take(max).collect();
    let extra = items.len().saturating_sub(max);
    let mut parts: Vec<String> = shown.iter().map(|s| s.to_string()).collect();
    if extra > 0 {
        parts.push(format!("{extra} more"));
    }
    match parts.len() {
        0 => String::new(),
        1 => parts.remove(0),
        _ => {
            let last = parts.pop().unwrap_or_default();
            format!("{} and {last}", parts.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_roundtrip() {
        let fields = ["plain", "has,comma", "has \"quote\"", ""];
        let line = csv_line(&fields);
        assert_eq!(line, "plain,\"has,comma\",\"has \"\"quote\"\"\",");
        assert_eq!(parse_csv_line(&line), fields);
    }

    #[test]
    fn csv_formulas_open_as_text() {
        assert_eq!(csv_field("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0");
        assert_eq!(
            csv_field("=HYPERLINK(\"http://x/\",\"click\")"),
            "\"'=HYPERLINK(\"\"http://x/\"\",\"\"click\"\")\""
        );
        for f in ["+1", "-2+3", "@SUM(1)", "\tx"] {
            assert!(
                csv_field(f).trim_start_matches('"').starts_with('\''),
                "{f}"
            );
        }
        assert_eq!(csv_field("10.0.0.5"), "10.0.0.5");
    }

    #[test]
    fn html_escapes() {
        assert_eq!(
            html("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }

    #[test]
    fn wraps_with_hanging_indent() {
        let w = wrap("one two three four five", 12, "1. ", "   ");
        assert_eq!(w, "1. one two\n   three\n   four five");
    }

    #[test]
    fn english_lists() {
        let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(english_list(&v(&["a"]), 3), "a");
        assert_eq!(english_list(&v(&["a", "b"]), 3), "a and b");
        assert_eq!(english_list(&v(&["a", "b", "c"]), 3), "a, b and c");
        assert_eq!(
            english_list(&v(&["a", "b", "c", "d"]), 2),
            "a, b and 2 more"
        );
    }
}
