use super::{Kind, RenderInput, Rendered};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{self, ListData, ListState};
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, dot_cell, num, simple_row, sort_indices, sv_n, sv_s};
use crate::gui::simple_action;
use crate::gui::{Shared, chip, copy_text};
use crate::{Chip, Row};
use keyhole::api::{self, Action, EventWindow};
use keyhole::state::App;
use keyhole::sys::crashes::{CrashKind, CrashRow};

pub const COLUMNS: &[ColDef] = &[
    c("time", "Time", 96.0, true, "When it happened, from the report or the dump file's timestamp. Hover a row for the exact time."),
    c("kind", "Kind", 110.0, false, "Blue screen, application crash, hang, or a shutdown that was not a clean one. Click to sort."),
    c("subject", "Program / code", 220.0, false, "The program that crashed or hung, or the bugcheck code of a blue screen. Click to sort."),
    c("detail", "Detail", 420.0, false, "Faulting module and exception code, bugcheck name and parameters, or who initiated a shutdown."),
    c("path", "Path", 300.0, false, "The dump file or report folder. Hover for the full path."),
    c("size", "Size", 84.0, true, "Size of the dump on disk. Click to sort largest first."),
];

fn columns(_st: &ListState) -> &'static [ColDef] {
    COLUMNS
}

fn default_sort(_st: &ListState) -> (&'static str, bool) {
    ("time", true)
}

pub static KIND: Kind = Kind {
    name: "crashes",
    title: "Crashes and unexpected shutdowns",
    placeholder: ("Filter by program, code or path", "Show only records whose program, code, detail or path contains this text. Prefixes: kind:bluescreen  kind:crash  kind:hang  kind:shutdown  process:name.exe"),
    columns,
    table: super::same_table,
    segment: super::no_segment,
    default_sort,
    buttons,
    refresh,
    render,
    menu,
    multi: None,
    double,
    button,
    csv: export_csv,
    segments: super::no_segments,
    segment_picked: super::no_segment_picked,
    toggle: super::no_toggle,
    toggled: super::no_toggled,
    after_load: super::no_after_load,
};

fn buttons(_st: &ListState) -> Vec<Chip> {
    vec![chip("rescan", "Rescan", None, "Scan the dump folders, WER reports and the System log again")]
}

fn refresh(_app: &App, _st: &ListState) -> ListData {
    ListData::Crashes(api::crashes())
}

fn tone_of(kind: CrashKind) -> i32 {
    match kind {
        CrashKind::BlueScreen | CrashKind::AppCrash => 4,
        CrashKind::Hang | CrashKind::Shutdown => 3,
        CrashKind::Other => 1,
    }
}

fn field_of(r: &CrashRow, key: &str) -> Option<String> {
    match key {
        "kind" => Some(r.kind.id().to_string()),
        "process" => Some(r.subject.clone()),
        "path" => Some(r.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default()),
        _ => None,
    }
}

fn render(_ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Crashes(d) = data else { return Rendered::default() };
    let terms = filter_terms(&input.filter);
    let now = crate::gui::rows::now_ms();
    let week = 7 * 86_400_000;
    let chip_ok = |r: &CrashRow| match input.chip.as_str() {
        "bsod" => r.kind == CrashKind::BlueScreen,
        "crash" => r.kind == CrashKind::AppCrash,
        "hang" => r.kind == CrashKind::Hang,
        "shutdown" => r.kind == CrashKind::Shutdown,
        "week" => now - r.time_ms <= week,
        _ => true,
    };
    let count_of = |k: CrashKind| d.rows.iter().filter(|r| r.kind == k).count();
    let chips = vec![
        chip("", "All", Some(d.rows.len()), "Every crash record found on this machine"),
        chip("bsod", "Blue screens", Some(count_of(CrashKind::BlueScreen)), "Kernel crashes: minidumps, MEMORY.DMP and bugcheck events"),
        chip("crash", "App crashes", Some(count_of(CrashKind::AppCrash)), "Programs that crashed, from WER reports and user mode dumps"),
        chip("hang", "Hangs", Some(count_of(CrashKind::Hang)), "Programs that stopped responding and were reported by Windows Error Reporting"),
        chip("shutdown", "Shutdowns", Some(count_of(CrashKind::Shutdown)), "Unexpected reboots, power loss and who initiated planned restarts"),
        chip("week", "Last 7 days", Some(d.rows.iter().filter(|r| now - r.time_ms <= week).count()), "Only records from the last week"),
    ];
    let mut shown: Vec<usize> = (0..d.rows.len()).filter(|&i| { let r = &d.rows[i]; chip_ok(r) && (terms.is_empty() || term_matches(&terms, |k| field_of(r, k), &format!("{} {} {}", r.subject, r.detail, r.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default()))) }).collect();
    sort_indices(&d.rows, &mut shown, &input.sort.0, input.sort.1, |r, k| match k {
        "time" => sv_n(r.time_ms as f64),
        "kind" => sv_s(r.kind.label()),
        "subject" => sv_s(&r.subject),
        "detail" => sv_s(&r.detail),
        "path" => sv_s(&r.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default()),
        "size" => sv_n(r.size as f64),
        _ => sv_s(""),
    });
    let rows: Vec<Row> = shown
        .iter()
        .map(|&i| {
            let r = &d.rows[i];
            let path = r.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
            let mut row = simple_row(
                i as i32,
                vec![
                    num(&fmt_age((now - r.time_ms).max(0))),
                    dot_cell(r.kind.label(), tone_of(r.kind)),
                    cell(&r.subject, 0),
                    cell(&r.detail, if r.kind == CrashKind::Other { 7 } else { 0 }),
                    cell(&path, 7),
                    num(&if r.size > 0 { bytes(r.size) } else { String::new() }),
                ],
                0,
                &format!("{}  ·  {}\n{}\n{}{}", time_of(r.time_ms), r.kind.label(), r.subject, r.detail, if path.is_empty() { String::new() } else { format!("\n\n{}", path) }),
            );
            row.id = i as i32;
            row
        })
        .collect();
    let mut count = format!("{}  ·  dumps use {}", plural(shown.len(), "record", "records"), bytes(d.dump_bytes));
    for n in &d.notes {
        count.push_str(&format!("  ·  {}", n));
    }
    let empty = ("\u{EA39}".into(), if input.filter.is_empty() && input.chip.is_empty() { "No crashes, hangs or unexpected shutdowns found.".to_string() } else { lists::nothing_matches(&input.filter) }, "Blue screens leave dumps in Minidump, app crashes leave WER reports and unclean reboots leave System log events. None were found.".into());
    Rendered { chips, rows, shown, count, empty }
}

fn row_at(ctx: &Shared, src: usize) -> Option<CrashRow> {
    let st = ctx.st.borrow();
    let ListData::Crashes(d) = &st.lists.data else { return None };
    d.rows.get(src).cloned()
}

fn show_in_events(ctx: &Shared, r: &CrashRow) {
    let Some((_, provider, id)) = &r.log_ref else { return };
    let age = crate::gui::rows::now_ms() - r.time_ms;
    let window = if age <= 7 * 86_400_000 { EventWindow::Week } else if age <= 30 * 86_400_000 { EventWindow::Month } else { EventWindow::All };
    super::events::show_with_window(ctx, window, "", &format!("{} id:={}", exact_filter("source", provider), id));
}

fn double(ctx: &Shared, src: usize) {
    let Some(r) = row_at(ctx, src) else { return };
    match &r.path {
        Some(p) => simple_action(ctx, Action::Reveal(p.display().to_string()), "Revealed", None),
        None => show_in_events(ctx, &r),
    }
}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let Some(r) = row_at(ctx, src) else { return };
    let path = r.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
    let running = crate::gui::tree::find_running_pid(ctx, &r.subject);
    let items = vec![
        MenuItem::new("copySummary", "Copy summary", { let v = format!("{} {} {} {}{}", time_of(r.time_ms), r.kind.label(), r.subject, r.detail, if path.is_empty() { String::new() } else { format!(" {}", path) }); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("copyPath", "Copy path", { let v = path.clone(); move |ctx| copy_text(ctx, &v) }).disabled(path.is_empty()),
        MenuItem::sep(),
        MenuItem::new("analyze", "Analyze dump", { let p = path.clone(); move |ctx| crate::gui::dumpview::open(ctx, &p) }).disabled(!keyhole::sys::dumpan::looks_like_dump(&path)).tip("Built-in analysis like WinDbg's !analyze: the bug check or exception, the module that probably caused it, the crashing stack and the loaded modules. Nothing to install, never goes online."),
        MenuItem::new("reveal", "Show in Explorer", { let p = path.clone(); move |ctx| simple_action(ctx, Action::Reveal(p), "Revealed", None) }).disabled(path.is_empty()),
        MenuItem::sep(),
        MenuItem::new("proc", "Jump to process", { let pid = running.unwrap_or(0); move |ctx| crate::gui::tree::select_pid(ctx, pid) }).disabled(running.is_none()),
        MenuItem::new("events", "Show in Events", { let r2 = r.clone(); move |ctx| show_in_events(ctx, &r2) }).disabled(r.log_ref.is_none()),
    ];
    menus::show(ctx, x, y, &format!("{}  ·  {}  ·  {}", r.kind.label(), r.subject, time_of(r.time_ms)), items);
}

fn button(_ctx: &Shared, _id: &str) {}

fn export_csv(data: &ListData, shown: &[usize], _st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Crashes(d) = data else { return None };
    Some(("keyhole-crashes", csv(&shown.iter().map(|&i| { let r = &d.rows[i]; vec![time_of(r.time_ms), r.kind.label().to_string(), r.subject.clone(), r.detail.clone(), r.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default(), if r.size > 0 { r.size.to_string() } else { String::new() }, r.log_ref.as_ref().map(|(log, source, id)| format!("{} / {} / {}", log, source, id)).unwrap_or_default()] }).collect::<Vec<_>>(), &["Time", "Kind", "Program or code", "Detail", "Path", "Size", "Event log / source / ID"])))
}
