pub fn bytes(n: u64) -> String {
    if n == 0 {
        return String::new();
    }
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v < 10.0 && i > 0 {
        format!("{:.1} {}", v, units[i])
    } else {
        format!("{} {}", v.round() as u64, units[i])
    }
}

pub fn bytes_or_zero(n: u64) -> String {
    if n == 0 { "0 B".into() } else { bytes(n) }
}

pub fn rate(n: u64) -> String {
    if n < 1024 { String::new() } else { format!("{}/s", bytes(n)) }
}

pub fn rate_or_zero(n: u64) -> String {
    if n < 1024 { "0 B/s".into() } else { format!("{}/s", bytes(n)) }
}

pub fn pct(n: f32) -> String {
    if n < 0.05 {
        String::new()
    } else if n < 10.0 {
        format!("{:.1}%", n)
    } else {
        format!("{:.0}%", n)
    }
}

pub fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn time_of(unix_ms: i64) -> String {
    if unix_ms <= 0 {
        return String::new();
    }
    keyhole::sys::local_time_text(unix_ms)
}

pub fn fmt_age(ms: i64) -> String {
    let mut s = (ms.max(0) / 1000) as u64;
    let d = s / 86400;
    s -= d * 86400;
    let h = s / 3600;
    s -= h * 3600;
    let m = s / 60;
    s -= m * 60;
    if d > 0 {
        format!("{}d {}h", d, h)
    } else if h > 0 {
        format!("{}h {}m", h, m)
    } else if m > 0 {
        format!("{}m {}s", m, s)
    } else {
        format!("{}s", s)
    }
}

pub fn fmt_uptime(ms: u64) -> String {
    let mut s = ms / 1000;
    let d = s / 86400;
    s -= d * 86400;
    let h = s / 3600;
    s -= h * 3600;
    let m = s / 60;
    if d > 0 { format!("{}d {}h {}m", d, h, m) } else { format!("{}h {}m", h, m) }
}

pub fn fmt_ms(ms: u64) -> String {
    if ms == 0 {
        String::new()
    } else if ms < 1000 {
        format!("{} ms", ms)
    } else if ms < 60_000 {
        format!("{:.1} s", ms as f64 / 1000.0)
    } else {
        let secs = (ms + 500) / 1000;
        format!("{}m {}s", secs / 60, secs % 60)
    }
}

pub fn hex(n: u64, pad: usize) -> String {
    format!("0x{:0width$X}", n, width = pad)
}

pub fn short_user(u: &str) -> String {
    match u.find('\\') {
        Some(i) if keyhole::sys::accounts::is_local_prefix(&u[..i]) => u[i + 1..].to_string(),
        _ => u.to_string(),
    }
}

pub fn is_file_path(p: &str) -> bool {
    let b = p.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\') || (p.starts_with("\\\\") && p[2..].contains('\\'))
}

pub fn compress_ranges(nums: &[u32]) -> String {
    let mut out = Vec::new();
    let mut start: Option<u32> = None;
    let mut prev = 0u32;
    for &n in nums {
        match start {
            None => {
                start = Some(n);
                prev = n;
            }
            Some(s) => {
                if n == prev + 1 {
                    prev = n;
                } else {
                    out.push(if s == prev { s.to_string() } else { format!("{}-{}", s, prev) });
                    start = Some(n);
                    prev = n;
                }
            }
        }
    }
    if let Some(s) = start {
        out.push(if s == prev { s.to_string() } else { format!("{}-{}", s, prev) });
    }
    out.join(", ")
}

pub fn affinity_text(cpus: &[u32], system: &[u32]) -> String {
    if cpus.is_empty() {
        return String::new();
    }
    if !system.is_empty() && cpus.len() == system.len() {
        return format!("all {}", system.len());
    }
    format!("CPU {} ({} of {})", compress_ranges(cpus), cpus.len(), system.len())
}

pub fn trust_text(t: &str) -> String {
    match t {
        "signed" => "Valid signature",
        "unsigned" => "Not signed",
        "expired" => "Signature expired",
        "untrusted" => "Signature not trusted",
        "error" => "Could not be checked",
        other => other,
    }
    .to_string()
}

pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{} {}", n, if n == 1 { one } else { many })
}

pub fn shown_of(shown: usize, total: usize, noun: &str) -> String {
    if shown == total { format!("{} {}", total, noun) } else { format!("{} of {} {}", shown, total, noun) }
}

pub fn csv(rows: &[Vec<String>], header: &[&str]) -> String {
    let quote = |s: &str| -> String {
        let mut chars = s.chars();
        let formula = match (chars.next(), chars.next()) {
            (Some('=' | '+' | '@' | '\t' | '\r'), _) => true,
            (Some('-'), Some(c)) => !c.is_ascii_digit(),
            _ => false,
        };
        if formula {
            format!("\"'{}\"", s.replace('"', "\"\""))
        } else if s.contains(',') || s.contains('"') || s.contains('\n') {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    };
    let mut out = header.iter().map(|h| quote(h)).collect::<Vec<_>>().join(",");
    for r in rows {
        out.push('\n');
        out.push_str(&r.iter().map(|c| quote(c)).collect::<Vec<_>>().join(","));
    }
    out
}

pub fn tsv(rows: &[Vec<String>], header: &[&str]) -> String {
    let mut out = header.join("\t");
    for r in rows {
        out.push('\n');
        out.push_str(&r.join("\t"));
    }
    out
}

pub fn safe_name(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect()
}

pub fn chart_paths(values: &[f32]) -> (String, String) {
    if values.len() < 2 {
        return (String::new(), String::new());
    }
    let n = values.len();
    let mut line = String::with_capacity(n * 16);
    for (i, v) in values.iter().enumerate() {
        let x = i as f32 / (n - 1) as f32 * 100.0;
        let y = 100.0 - v.clamp(0.0, 1.0) * 96.0 - 2.0;
        if i == 0 {
            line.push_str(&format!("M {:.2} {:.2}", x, y));
        } else {
            line.push_str(&format!(" L {:.2} {:.2}", x, y));
        }
    }
    let fill = format!("{} L 100 100 L 0 100 Z", line);
    (line, fill)
}

pub fn normalized(values: &[u64], floor: u64) -> Vec<f32> {
    let max = values.iter().copied().max().unwrap_or(0).max(floor).max(1) as f32;
    values.iter().map(|v| *v as f32 / max).collect()
}

pub fn filter_terms(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut term = String::new();
    let mut quoted = false;
    let flush = |term: &mut String, out: &mut Vec<(String, String)>| {
        if term.is_empty() {
            return;
        }
        let t = term.to_lowercase();
        let split = t.find(':').filter(|&i| i >= 2 && t[..i].chars().all(|c| c.is_ascii_alphabetic()));
        match split {
            Some(i) => {
                let rest = &t[i + 1..];
                let value = match rest.strip_prefix('=') {
                    Some(exact) => format!("={}", exact.trim_matches('"')),
                    None => rest.trim_matches('"').to_string(),
                };
                out.push((t[..i].to_string(), value))
            }
            None => out.push((String::new(), t.trim_matches('"').to_string())),
        }
        term.clear();
    };
    for ch in text.chars() {
        match ch {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => flush(&mut term, &mut out),
            c => term.push(c),
        }
    }
    flush(&mut term, &mut out);
    out.retain(|(k, v)| !(k.is_empty() && v.is_empty()));
    out
}

pub fn term_matches(terms: &[(String, String)], field: impl Fn(&str) -> Option<String>, free_text: &str) -> bool {
    let free = free_text.to_lowercase();
    terms.iter().all(|(k, v)| {
        if k.is_empty() {
            return free.contains(v.as_str());
        }
        let Some(f) = field(k) else { return free.contains(&format!("{}:{}", k, v.trim_start_matches('='))) };
        let f = f.to_lowercase();
        match v.strip_prefix('=') {
            Some(exact) => f.lines().any(|part| part == exact),
            None => f.contains(v.as_str()),
        }
    })
}

pub fn exact_filter(key: &str, value: &str) -> String {
    format!("{}:=\"{}\"", key, value)
}
