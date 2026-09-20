use super::{Kind, RenderInput, Rendered};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{self, ListData, ListState};
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, dot_cell, num, simple_row, sort_indices, sv_n, sv_s};
use crate::gui::simple_action;
use crate::gui::{Shared, bad, chip, copy_text, good, model, spawn, ss, ui};
use crate::{Badge, Chip, Row};
use keyhole::api::{self, Action, EventWindow};
use keyhole::state::App;
use keyhole::sys::eventlog::{EventRow, level_name};
use std::collections::HashMap;

pub const COLUMNS: &[ColDef] = &[
    c("time", "Time", 96.0, true, "When the event was logged. Hover a row for the exact time. Newest first by default."),
    c("level", "Level", 104.0, false, "Critical, Error, Warning, Audit failure or Information. Click to sort."),
    c("log", "Log", 100.0, false, "Which log the event came from. Click to sort, or filter with log:name."),
    c("source", "Source", 200.0, false, "The provider that logged the event. Click to sort, right-click a row to show only this source."),
    c("id", "ID", 64.0, true, "Event ID within its source. Click to sort."),
    c("message", "Message", 520.0, false, "First line of the message. Hover a row for the whole text, right-click to copy it."),
];

pub const MAX_ROWS: usize = 15_000;

pub struct EventsUi {
    pub window: EventWindow,
    pub security: bool,
    pub all_logs: bool,
    pub seq: u64,
    pub since_frozen: Vec<EventRow>,
    pub fresh: HashMap<(String, u64), u64>,
}

impl Default for EventsUi {
    fn default() -> Self {
        EventsUi { window: EventWindow::Day, security: false, all_logs: true, seq: 0, since_frozen: Vec::new(), fresh: HashMap::new() }
    }
}

impl EventsUi {
    pub fn settings_only(&self) -> EventsUi {
        EventsUi { window: self.window, security: self.security, all_logs: self.all_logs, ..Default::default() }
    }
}

fn columns(_st: &ListState) -> &'static [ColDef] {
    COLUMNS
}

fn default_sort(_st: &ListState) -> (&'static str, bool) {
    ("time", true)
}

fn segment(st: &ListState) -> String {
    st.events.window.id().to_string()
}

pub static KIND: Kind = Kind {
    name: "events",
    title: "Events",
    placeholder: ("Filter by log, source, ID, message, user", "Show only events whose log, source, ID, message, task or user contains this text. Prefixes: log:system  log:taskscheduler  source:disk  id:7034  level:error  user:greg"),
    columns,
    table: super::same_table,
    segment,
    default_sort,
    buttons,
    refresh,
    render,
    menu,
    multi: None,
    double,
    button,
    csv: export_csv,
    segments,
    segment_picked,
    toggle,
    toggled,
    after_load,
};

fn buttons(st: &ListState) -> Vec<Chip> {
    vec![
        if st.events.all_logs {
            chip("logs", "All logs", None, "Every enabled Admin and Operational log on this machine is loaded: Task Scheduler, PowerShell, Remote Desktop, Windows Update, Defender, SMB, DNS, Hyper-V and the rest. Click to load only System, Application and Setup")
        } else {
            chip("logs", "Core logs", None, "Only System, Application and Setup are loaded. Click to load every enabled Admin and Operational log as well")
        },
        chip("evtx", "Save .evtx", None, "Save System, Application and, when included, Security for this window as .evtx files that Event Viewer on any machine can open"),
    ]
}

fn segments(st: &ListState) -> Vec<Chip> {
    let _ = st;
    vec![
        chip("hour", "1 h", None, "Events from the last hour"),
        chip("day", "24 h", None, "Events from the last 24 hours"),
        chip("week", "7 d", None, "Events from the last 7 days"),
        chip("month", "30 d", None, "Events from the last 30 days"),
        chip("all", "All", None, "Everything each log still holds, newest first, up to 10,000 errors and 2,000 informational events per log"),
    ]
}

fn segment_picked(ctx: &Shared, id: &str) {
    ctx.st.borrow_mut().lists.events.window = EventWindow::parse(id);
    ui(ctx).set_list_segment(ss(id));
    lists::refresh_current(ctx, true);
}

fn toggle(st: &ListState) -> Option<(&'static str, &'static str, bool)> {
    Some(("Include Security", "Also load and tail the Security log. It is large and mostly logon noise, so it is off by default.", st.events.security))
}

fn toggled(ctx: &Shared, on: bool) {
    ctx.st.borrow_mut().lists.events.security = on;
    lists::refresh_current(ctx, true);
}

fn refresh(app: &App, st: &ListState) -> ListData {
    ListData::Events(api::events(app, st.events.window, st.events.security, st.events.all_logs))
}

fn after_load(ctx: &Shared, data: &ListData) {
    let ListData::Events(data) = data else { return };
    let mut st = ctx.st.borrow_mut();
    st.lists.events.seq = data.seq;
    st.lists.events.since_frozen.clear();
    st.lists.events.fresh.clear();
    let u = ui(ctx);
    u.set_list_segment(ss(data.window.id()));
}

fn routine(level: u8) -> bool {
    !(1..=3).contains(&level) && level != 6
}

fn level_tone(level: u8) -> i32 {
    match level {
        1 | 2 => 4,
        3 | 6 => 3,
        0 | 4 => 5,
        _ => 1,
    }
}

fn field_of(r: &EventRow, key: &str) -> Option<String> {
    match key {
        "log" => Some(r.log.clone()),
        "source" => Some(r.source.clone()),
        "id" => Some(r.id.to_string()),
        "level" => Some(level_name(r.level).to_string()),
        "user" => Some(r.user.clone()),
        "task" => Some(r.task.clone()),
        _ => None,
    }
}

fn render(ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Events(d) = data else { return Rendered::default() };
    let (fresh, ticks, frozen_count) = {
        let st = ctx.st.borrow();
        (st.lists.events.fresh.clone(), st.ticks, st.lists.events.since_frozen.len())
    };
    let terms = filter_terms(&input.filter);
    let wants_information = input.chip == "information" || terms.iter().any(|(k, v)| (k == "level" && v.starts_with("info")) || k == "id");
    let level_ok = |r: &EventRow| match input.chip.as_str() {
        "critical" => r.level == 1,
        "error" => r.level == 2,
        "warning" => r.level == 3 || r.level == 6,
        "information" => routine(r.level),
        _ => !routine(r.level) || wants_information,
    };
    let count_of = |f: &dyn Fn(&EventRow) -> bool| d.rows.iter().filter(|r| f(r)).count();
    let chips = vec![
        chip("", "All", Some(count_of(&|r| !routine(r.level))), "Every critical, error and warning event in the window"),
        chip("critical", "Critical", Some(count_of(&|r| r.level == 1)), "Events the provider marked critical"),
        chip("error", "Errors", Some(count_of(&|r| r.level == 2)), "Error events"),
        chip("warning", "Warnings", Some(count_of(&|r| r.level == 3 || r.level == 6)), "Warning events and Security audit failures"),
        chip("information", "Information", Some(count_of(&|r| routine(r.level))), "Informational and verbose events: loaded but hidden until you ask, because there are so many"),
    ];
    let mut shown: Vec<usize> = (0..d.rows.len()).filter(|&i| { let r = &d.rows[i]; level_ok(r) && (terms.is_empty() || term_matches(&terms, |k| field_of(r, k), &format!("{} {} {} {} {} {}", r.log, r.source, r.id, r.message, r.task, r.user))) }).collect();
    sort_indices(&d.rows, &mut shown, &input.sort.0, input.sort.1, |r, k| match k {
        "time" => sv_n(r.time_ms as f64),
        "level" => sv_n(r.level as f64),
        "log" => sv_s(&r.log),
        "source" => sv_s(&r.source),
        "id" => sv_n(r.id as f64),
        "message" => sv_s(&r.first_line),
        _ => sv_s(""),
    });
    let now = crate::gui::rows::now_ms();
    let rows: Vec<Row> = shown
        .iter()
        .map(|&i| {
            let r = &d.rows[i];
            let is_fresh = fresh.get(&(r.log.clone(), r.record_id)).map(|t| ticks.saturating_sub(*t) < 2).unwrap_or(false);
            let mut row = simple_row(
                i as i32,
                vec![
                    num(&fmt_age((now - r.time_ms).max(0))),
                    dot_cell(level_name(r.level), level_tone(r.level)),
                    cell(&r.log, 0),
                    cell(&r.source, 0),
                    num(&r.id.to_string()),
                    cell(&r.first_line, if routine(r.level) { 7 } else { 0 }),
                ],
                if is_fresh { 3 } else { 0 },
                &format!("{}  ·  {}  ·  {} {}{}{}\n\n{}", time_of(r.time_ms), r.log, r.source, r.id, if r.task.is_empty() { String::new() } else { format!("  ·  {}", r.task) }, if r.user.is_empty() { String::new() } else { format!("  ·  {}", r.user) }, r.message),
            );
            row.id = r.record_id as i32;
            if r.service.is_some() {
                row.badges = model(vec![Badge { text: ss("service"), kind: 0, tip: ss("A Service Control Manager event about a service. Right-click to jump to it") }]);
            }
            row
        })
        .collect();
    let mut count = format!(
        "{} {} from {}  ·  newest first",
        plural(shown.len(), "event", "events"),
        if d.window == EventWindow::All { "held".to_string() } else { format!("in the last {}", d.window.label()) },
        plural(d.channels.len(), "log", "logs")
    );
    if !d.capped.is_empty() {
        count.push_str(&format!("  ·  newest only for {}", if d.capped.len() <= 3 { d.capped.join(", ") } else { format!("{} logs", d.capped.len()) }));
    }
    if d.errors.len() > 2 {
        count.push_str(&format!("  ·  {} logs could not be read", d.errors.len()));
    } else {
        for (ch, e) in &d.errors {
            count.push_str(&format!("  ·  {}: {}", ch, e.split(": ").last().unwrap_or(e)));
        }
    }
    if frozen_count > 0 {
        count.push_str(&format!("  ·  {} new since frozen", frozen_count));
    }
    let empty = ("\u{E7BA}".into(), if input.filter.is_empty() && input.chip.is_empty() { if d.window == EventWindow::All { "No errors or warnings in these logs.".to_string() } else { format!("No errors or warnings in the last {}.", d.window.label()) } } else { lists::nothing_matches(&input.filter) }, "Pick a longer window above, or the Information chip to see routine events.".into());
    Rendered { chips, rows, shown, count, empty }
}

fn row_at(ctx: &Shared, src: usize) -> Option<EventRow> {
    let st = ctx.st.borrow();
    let ListData::Events(d) = &st.lists.data else { return None };
    d.rows.get(src).cloned()
}

fn summary(r: &EventRow) -> String {
    format!("{} {} {} {} {}: {}", time_of(r.time_ms), level_name(r.level), r.log, r.source, r.id, r.first_line)
}

fn double(ctx: &Shared, src: usize) {
    if let Some(r) = row_at(ctx, src) {
        copy_text(ctx, &r.message);
    }
}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let Some(r) = row_at(ctx, src) else { return };
    let alive = r.pid.map(|p| crate::gui::tree::row_of(ctx, p).is_some()).unwrap_or(false);
    let service = r.service.clone();
    let log = r.log.clone();
    let items = vec![
        MenuItem::new("copy", "Copy message", { let v = r.message.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("copySummary", "Copy summary", { let v = summary(&r); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("copyXml", "Copy event XML", { let log = r.log.clone(); let id = r.record_id; move |ctx| {
            spawn(ctx, move |_| api::event_xml(&log, id), |ctx, res| match res {
                Ok(xml) => copy_text(ctx, &xml),
                Err(e) => bad(ctx, &e),
            });
        } }).tip("The full event as Event Viewer's XML view shows it, with every data field"),
        MenuItem::sep(),
        MenuItem::new("source", "Show all from this source", { let s = r.source.clone(); move |ctx| lists::set_filter_and_show(ctx, "events", &exact_filter("source", &s)) }),
        MenuItem::new("onlyId", "Show only this event ID", { let s = r.source.clone(); let id = r.id; move |ctx| lists::set_filter_and_show(ctx, "events", &format!("{} id:={}", exact_filter("source", &s), id)) }),
        MenuItem::sep(),
        MenuItem::new("proc", "Jump to process", { let pid = r.pid.unwrap_or(0); move |ctx| crate::gui::tree::select_pid(ctx, pid) }).disabled(!alive),
        MenuItem::new("svc", "Jump to service", { let s = service.clone().unwrap_or_default(); move |ctx| lists::set_filter_and_show(ctx, "services", &s) }).disabled(service.is_none()),
        MenuItem::sep(),
        MenuItem::new("eventvwr", "Open in Event Viewer", { let log = log.clone(); move |ctx| simple_action(ctx, Action::OpenTool(format!("eventvwr:{}", log)), "Opened Event Viewer", None) }),
    ];
    menus::show(ctx, x, y, &format!("{}  ·  {}  ·  {}", r.source, r.id, time_of(r.time_ms)), items);
}

fn button(ctx: &Shared, id: &str) {
    if id == "logs" {
        {
            let mut st = ctx.st.borrow_mut();
            st.lists.events.all_logs = !st.lists.events.all_logs;
        }
        let buttons = buttons(&ctx.st.borrow().lists);
        ui(ctx).set_list_buttons(model(buttons));
        lists::refresh_current(ctx, true);
        return;
    }
    if id != "evtx" {
        return;
    }
    let (window, security, information) = {
        let st = ctx.st.borrow();
        (st.lists.events.window, st.lists.events.security, st.lists.chip.get("events").map(|c| c == "information").unwrap_or(false))
    };
    let logs: Vec<&'static str> = if security { vec!["System", "Application", "Security"] } else { vec!["System", "Application"] };
    let stamp = keyhole::sys::local_stamp();
    let Some(first) = keyhole::sys::dialogs::save_file(crate::gui::window_hwnd(ctx), &format!("System-{}.evtx", stamp), "evtx") else { return };
    let dir = std::path::Path::new(&first).parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let stem = std::path::Path::new(&first).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let sibling = |log: &str| -> std::path::PathBuf {
        match stem.strip_prefix("System") {
            Some(suffix) => dir.join(format!("{}{}.evtx", log, suffix)),
            None => dir.join(format!("{}-{}.evtx", stem, log)),
        }
    };
    for log in logs {
        let path = if log == "System" { std::path::PathBuf::from(&first) } else { sibling(log) };
        let shown = path.display().to_string();
        if log != "System" && path.exists() {
            bad(ctx, &format!("{} already exists. The {} log was not exported", shown, log));
            continue;
        }
        spawn(ctx, move |_| api::event_export(log, window, information, &path), move |ctx, r| match r {
            Ok(()) => good(ctx, &format!("Saved {}", shown)),
            Err(e) => bad(ctx, &e),
        });
    }
}

fn export_csv(data: &ListData, shown: &[usize], _st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Events(d) = data else { return None };
    Some(("keyhole-events", csv(&shown.iter().map(|&i| { let r = &d.rows[i]; vec![time_of(r.time_ms), level_name(r.level).to_string(), r.log.clone(), r.source.clone(), r.id.to_string(), r.task.clone(), r.user.clone(), r.computer.clone(), r.pid.map(|p| p.to_string()).unwrap_or_default(), r.service.clone().unwrap_or_default(), r.record_id.to_string(), r.message.clone()] }).collect::<Vec<_>>(), &["Time", "Level", "Log", "Source", "ID", "Task", "User", "Computer", "PID", "Service", "Record", "Message"])))
}

pub fn tick(ctx: &Shared) {
    let seq = ctx.st.borrow().lists.events.seq;
    let (rows, new_seq, _dropped) = api::event_tail(&ctx.app, seq);
    let paused = ctx.app.paused.load(std::sync::atomic::Ordering::Relaxed);
    let ticks = ctx.st.borrow().ticks;
    let (had_fresh, pending) = {
        let st = ctx.st.borrow();
        (!st.lists.events.fresh.is_empty(), !st.lists.events.since_frozen.is_empty())
    };
    if rows.is_empty() && !had_fresh && !(pending && !paused) {
        return;
    }
    {
        let mut st = ctx.st.borrow_mut();
        st.lists.events.seq = new_seq;
        st.lists.events.fresh.retain(|_, t| ticks.saturating_sub(*t) < 2);
        if paused {
            st.lists.events.since_frozen.extend(rows);
            let extra = st.lists.events.since_frozen.len().saturating_sub(MAX_ROWS);
            if extra > 0 {
                st.lists.events.since_frozen.drain(..extra);
            }
        } else {
            let known: std::collections::HashSet<(String, u64)> = match &st.lists.data {
                ListData::Events(d) => d.rows.iter().take(2000).map(|r| (r.log.clone(), r.record_id)).collect(),
                _ => std::collections::HashSet::new(),
            };
            let pending: Vec<EventRow> = st.lists.events.since_frozen.drain(..).chain(rows).filter(|r| !known.contains(&(r.log.clone(), r.record_id))).collect();
            for r in &pending {
                st.lists.events.fresh.insert((r.log.clone(), r.record_id), ticks);
            }
            if let ListData::Events(d) = &mut st.lists.data {
                let keep = d.rows.len().max(MAX_ROWS);
                for r in pending.into_iter().rev() {
                    d.rows.insert(0, r);
                }
                d.rows.truncate(keep);
            }
        }
    }
    lists::render(ctx);
}

pub fn show_for_service(ctx: &Shared, display: &str) {
    show_with_window(ctx, EventWindow::Week, "information", &format!("\"{}\"", display));
}

pub fn show_with_window(ctx: &Shared, window: EventWindow, chip: &str, filter: &str) {
    let reload = {
        let mut st = ctx.st.borrow_mut();
        let changed = st.lists.events.window != window;
        st.lists.events.window = window;
        st.lists.chip.insert("events".into(), chip.to_string());
        changed && st.mode == "events"
    };
    lists::set_filter_and_show(ctx, "events", filter);
    if reload {
        lists::refresh_current(ctx, true);
    }
}

pub fn resume(ctx: &Shared) {
    if ctx.st.borrow().lists.kind == "events" {
        tick(ctx);
    }
}
