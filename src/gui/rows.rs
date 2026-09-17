use super::{model, ss};
use crate::{Badge, Cell, DocItem, Row};
use slint::SharedString;

pub fn sig_text(t: &str) -> String {
    match t {
        "" | "unchecked" => "-".into(),
        "error" => "?".into(),
        other => other.into(),
    }
}

pub fn sig_tone(t: &str) -> i32 {
    match t {
        "signed" => 2,
        "unsigned" => 3,
        "expired" | "untrusted" => 4,
        _ => 1,
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn cmp_vals(a: &SortVal, b: &SortVal) -> std::cmp::Ordering {
    match (a, b) {
        (SortVal::N(x), SortVal::N(y)) => x.total_cmp(y),
        (SortVal::S(x), SortVal::S(y)) => x.cmp(y),
        (SortVal::N(_), SortVal::S(_)) => std::cmp::Ordering::Less,
        (SortVal::S(_), SortVal::N(_)) => std::cmp::Ordering::Greater,
    }
}

pub fn sort_indices<T>(rows: &[T], indices: &mut Vec<usize>, key: &str, desc: bool, val: impl Fn(&T, &str) -> SortValue) {
    if key.is_empty() {
        return;
    }
    let keyed: Vec<(SortValue, usize)> = indices.iter().map(|&i| (val(&rows[i], key), i)).collect();
    let mut order: Vec<usize> = (0..keyed.len()).collect();
    order.sort_by(|&a, &b| {
        let o = cmp_vals(&keyed[a].0.0, &keyed[b].0.0);
        if desc { o.reverse() } else { o }
    });
    *indices = order.into_iter().map(|k| keyed[k].1).collect();
}

enum SortVal {
    S(String),
    N(f64),
}

pub struct SortValue(SortVal);

pub fn sv_s(s: &str) -> SortValue {
    SortValue(SortVal::S(s.to_lowercase()))
}

pub fn sv_n(n: f64) -> SortValue {
    SortValue(SortVal::N(n))
}

pub fn sv_b(b: bool) -> SortValue {
    SortValue(SortVal::N(if b { 1.0 } else { 0.0 }))
}

pub fn cell(text: &str, tone: i32) -> Cell {
    Cell { text: ss(text), tone, dot: 0, mono: false, suffix: SharedString::default(), bar: 0.0, bar_tone: 0 }
}

pub fn num(text: &str) -> Cell {
    cell(text, 0)
}

pub fn hexc(text: &str) -> Cell {
    cell(text, 0)
}

pub fn dot_cell(text: &str, dot: i32) -> Cell {
    Cell { dot, ..cell(text, 0) }
}

pub fn suffix_cell(text: &str, suffix: &str) -> Cell {
    Cell { suffix: ss(suffix), ..cell(text, 0) }
}

pub fn simple_row(id: i32, cells: Vec<Cell>, tone: i32, tip: &str) -> Row {
    Row {
        id,
        cells: model(cells),
        tone,
        selected: false,
        indent: 0,
        twisty: 0,
        icon: slint::Image::default(),
        has_icon: false,
        badges: model(Vec::<Badge>::new()),
        tip: ss(tip),
    }
}

pub fn kv(key: &str, value: &str) -> DocItem {
    DocItem { kind: 1, key: ss(key), value: ss(value), ..doc_default() }
}

pub fn doc_default() -> DocItem {
    DocItem {
        kind: 0,
        key: SharedString::default(),
        value: SharedString::default(),
        tip: SharedString::default(),
        tone: 0,
        badge: SharedString::default(),
        badge_kind: 0,
        badges: model(Vec::<Badge>::new()),
        pct: -1.0,
        sub: SharedString::default(),
        sub2: SharedString::default(),
        id: SharedString::default(),
        id2: SharedString::default(),
        jump: 0,
    }
}

pub fn section(title: &str, hint: &str) -> DocItem {
    DocItem { kind: 0, key: ss(title), sub: ss(hint), ..doc_default() }
}
