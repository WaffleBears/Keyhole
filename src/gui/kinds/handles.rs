use super::{Kind, RenderInput, Rendered, plural};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{ListData, ListState};
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, num, simple_row, sort_indices, sv_n, sv_s};
use crate::gui::{Shared, batch_action, chip, copy_text, dialogs};
use crate::{Chip, Row};
use keyhole::api::{self};
use keyhole::state::App;
use std::collections::HashMap;

pub const COLUMNS: &[ColDef] = &[
    c("type_name", "Type", 100.0, false, "Object type. Click to sort."),
    c("display", "Name", 460.0, false, "Resolved path or object name. Click to sort."),
    c("process", "Process", 190.0, false, "Process holding the handle. Double-click a row to jump to it."),
    c("pid", "PID", 72.0, true, "Owning process ID."),
    c("access_text", "Access", 190.0, false, "Granted access rights."),
    c("shared_with", "Shared", 72.0, true, "How many processes share this object (needs SeDebugPrivilege). Click to sort."),
];

fn columns(_st: &ListState) -> &'static [ColDef] {
    COLUMNS
}

fn default_sort(_st: &ListState) -> (&'static str, bool) {
    ("display", false)
}

pub static KIND: Kind = Kind {
    name: "handles",
    title: "Open handles",
    placeholder: ("Filter by path or name", "Show only handles whose name or owning process contains this text"),
    columns,
    table: super::same_table,
    segment: super::no_segment,
    default_sort,
    buttons,
    refresh,
    render,
    menu,
    multi: Some(multi),
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
    vec![chip("rescan", "Rescan", None, "Rescan all handles now")]
}

fn refresh(app: &App, st: &ListState) -> ListData {
    let _ = (app, st);
    ListData::Handles(api::all_handles(app, &st.gh_type))
}

fn render(ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Handles(h) = data else { return Rendered::default() };
    let _ = ctx;
    let filter = input.filter.clone();
    let sort = input.sort.clone();
    let mut chips: Vec<Chip> = Vec::new();
    
    let gh_type = input.gh_type.clone();
    let counts: HashMap<&str, u32> = h.summary.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    chips.push(chip("", "Files, keys, sections", if gh_type.is_empty() { Some(h.total as usize) } else { None }, "The default scan: files, registry keys, shared memory sections, object directories and symbolic links"));
    for (t, tip) in GH_TYPES {
        let n = if gh_type == *t { Some(h.total as usize) } else if gh_type.is_empty() { counts.get(t).map(|c| *c as usize) } else { None };
        chips.push(chip(t, t, n, &format!("{}. Click to scan only this type.", tip)));
    }
    let f = filter.replace('/', "\\");
    let mut shown = (0..h.rows.len()).filter(|&i| { let r = &h.rows[i]; f.is_empty() || r.display.to_lowercase().contains(&f) || r.process.to_lowercase().contains(&f) || r.type_name.to_lowercase().contains(&f) || r.pid.to_string().contains(&f) }).collect();
    sort_indices(&h.rows, &mut shown, &sort.0, sort.1, |r, k| match k {
        "type_name" => sv_s(&r.type_name),
        "display" => sv_s(&r.display),
        "process" => sv_s(&r.process),
        "pid" => sv_n(r.pid as f64),
        "access_text" => sv_s(&r.access_text),
        "shared_with" => sv_n(r.shared_with as f64),
        _ => sv_s(""),
    });
    let count = format!(
        "{}{} handles{}{}{}",
        if f.is_empty() { String::new() } else { format!("{} of ", thousands(shown.len() as u64)) },
        thousands(h.total as u64),
        if h.total as usize > h.rows.len() && f.is_empty() { format!(" (first {} shown)", h.rows.len()) } else { String::new() },
        if h.stats.pending > 0 { format!("  ·  {} not yet named, press Rescan for more", h.stats.pending) } else { String::new() },
        if h.stats.threads_abandoned > 0 { format!("  ·  {} could not be named", h.stats.threads_abandoned) } else { String::new() }
    );
    let rows: Vec<Row> = shown
        .iter()
        .map(|&i| {
            let r = &h.rows[i];
            let mut row = simple_row(i as i32, vec![cell(&r.type_name, 0), if r.display.is_empty() { cell("unnamed", 1) } else { cell(&r.display, 0) }, cell(&r.process, 0), num(&r.pid.to_string()), cell(&r.access_text, 0), num(&if r.shared_with > 1 { r.shared_with.to_string() } else { String::new() })], 0, &r.display);
            row.id = r.pid as i32;
            row
        })
        .collect();
    let empty = ("\u{E8D7}".into(), format!("No {}{}.", if gh_type.is_empty() { "open handles".to_string() } else { format!("{} handles", gh_type) }, if filter.is_empty() { " found".to_string() } else { format!(" match \"{}\"", filter) }), String::new());
    Rendered { chips, rows, shown, count, empty }
}

fn double(ctx: &Shared, src: usize) {
    let st = ctx.st.borrow();
    let ListData::Handles(h) = &st.lists.data else { return };
    let Some(pid) = h.rows.get(src).map(|r| r.pid) else { return };
    drop(st);
    crate::gui::tree::select_pid(ctx, pid);
}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let d = {
        let st = ctx.st.borrow();
        let ListData::Handles(h) = &st.lists.data else { return };
        let Some(row) = h.rows.get(src) else { return };
        row.clone()
    };
    menus::handle_menu(ctx, x, y, &d);
}

const GH_TYPES: &[(&str, &str)] = &[
    ("File", "Open files, folders, devices and pipes"),
    ("Key", "Open registry keys"),
    ("Section", "Shared memory and mapped files"),
    ("Directory", "Object manager directories"),
    ("SymbolicLink", "Object manager symbolic links"),
    ("Mutant", "Mutexes: often used by programs to ensure a single instance"),
    ("Event", "Named events used for signalling between processes"),
    ("Semaphore", "Named semaphores"),
    ("Process", "Handles one process holds to another process"),
    ("Thread", "Handles to threads in other processes"),
    ("Token", "Access tokens"),
    ("Job", "Job objects grouping processes"),
    ("ALPC Port", "Local interprocess communication ports"),
    ("Desktop", "Desktop objects"),
    ("WindowStation", "Window station objects"),
];

fn button(ctx: &Shared, id: &str) {
    let _ = (ctx, id);
}

fn export_csv(data: &ListData, shown: &[usize], _st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Handles(h) = data else { return None };
    Some(("keyhole-open-handles", csv(&shown.iter().map(|&i| { let r = &h.rows[i]; vec![r.type_name.clone(), r.display.clone(), r.process.clone(), r.pid.to_string(), r.access_text.clone(), r.shared_with.to_string()] }).collect::<Vec<_>>(), &["Type", "Name", "Process", "PID", "Access", "Shared"])))
}

fn multi(ctx: &Shared, srcs: &[usize], x: f32, y: f32) {
    let rows: Vec<keyhole::model::HandleRow> = {
        let st = ctx.st.borrow();
        let ListData::Handles(h) = &st.lists.data else { return };
        srcs.iter().filter_map(|&i| h.rows.get(i).cloned()).collect()
    };
    if rows.is_empty() {
        return;
    }
    let n = rows.len();
    let close: Vec<(String, keyhole::api::Action)> = rows.iter().map(|r| (format!("{} in {}", r.display, r.process), keyhole::api::Action::CloseHandle { pid: r.pid, handle: r.handle, object: r.object })).collect();
    let items = vec![
        MenuItem::new("copy", "Copy names", { let v = rows.iter().map(|r| r.display.clone()).collect::<Vec<_>>().join("\n"); move |ctx| copy_text(ctx, &v) }),
        MenuItem::sep(),
        MenuItem::new("close", &format!("Close {}", plural(n, "handle", "handles")), move |ctx| {
            let a = close.clone();
            dialogs::confirm(ctx, "Close handles?", &format!("This forcibly closes {} inside the owning processes. Programs that still use them can crash or corrupt data.", plural(a.len(), "handle", "handles")), "Close handles", true, Box::new(move |ctx| batch_action(ctx, a, "Closed", ("handle", "handles"), super::refresh_after("handles"))));
        })
        .danger(),
    ];
    menus::show(ctx, x, y, &format!("{} selected", plural(n, "handle", "handles")), items);
}
