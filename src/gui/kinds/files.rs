use super::{Kind, RenderInput, Rendered};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{self, ListData, ListState};
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, num, simple_row, sort_indices, suffix_cell, sv_b, sv_n, sv_s};
use crate::gui::simple_action;
use crate::gui::{Shared, bad, chip, copy_text, dialogs, finder};
use crate::{Chip, Row};
use keyhole::api::{self, Action};
use keyhole::model::OpenFileRow;
use keyhole::state::App;

pub const COLUMNS: &[ColDef] = &[
    c("name", "File", 260.0, false, "File name. Hover for the full path. Double-click to list every handle to it."),
    c("folder", "Folder", 300.0, false, "The folder the file lives in."),
    c("procs_text", "Held by", 200.0, false, "Processes that have this file open. Hover to see which ones can write."),
    c("write", "Access", 96.0, false, "Write means at least one process can change the file. Read means every handle is read-only."),
    c("handles", "Handles", 76.0, true, "How many open handles point at this file, across all processes."),
    c("activity", "Activity", 150.0, true, "Bytes read and written in the last few seconds (needs kernel tracing, see the status bar pill)."),
    c("drive_kind", "Drive", 90.0, false, "Local disk, removable drive or network share."),
];

fn columns(_st: &ListState) -> &'static [ColDef] {
    COLUMNS
}

fn default_sort(_st: &ListState) -> (&'static str, bool) {
    ("name", false)
}

pub static KIND: Kind = Kind {
    name: "files",
    title: "Open files",
    placeholder: ("Filter by path or process", "Show only files whose path or holding process contains this text"),
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
    vec![chip("rescan", "Rescan", None, "Rescan every open file now")]
}

fn refresh(app: &App, st: &ListState) -> ListData {
    let _ = (app, st);
    ListData::Files(api::open_files(app))
}

fn render(ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Files(f) = data else { return Rendered::default() };
    let _ = ctx;
    let filter = input.filter.clone();
    let chip_id = input.chip.clone();
    let sort = input.sort.clone();
    
    let rows: Vec<Row>;
    let matches = |id: &str, r: &OpenFileRow| match id {
        "write" => r.open && r.write,
        "active" => r.active,
        "user" => !r.system_area,
        "removable" => r.drive_kind == "Removable" || r.drive_kind == "Network" || r.drive_kind == "Optical",
        "shared" => r.processes.len() > 1,
        _ => true,
    };
    let chips = vec![
        chip("", "All", Some(f.rows.len()), "Every file that is open, plus files touched in the last few seconds"),
        chip("write", "Open for writing", Some(f.rows.iter().filter(|r| r.open && r.write).count()), "Files some process can modify: these are the ones that block deletes, moves and edits"),
        chip("active", "Active now", Some(f.rows.iter().filter(|r| r.active).count()), &format!("Files read or written in the last few seconds{}", if f.tracing { "" } else { " (kernel tracing is off)" })),
        chip("shared", "Held by several processes", Some(f.rows.iter().filter(|r| r.processes.len() > 1).count()), "Files more than one process has open at the same time"),
        chip("user", "Outside Windows and Program Files", Some(f.rows.iter().filter(|r| !r.system_area).count()), "Documents, data and logs rather than program and system files"),
        chip("removable", "Removable or network", Some(f.rows.iter().filter(|r| r.drive_kind == "Removable" || r.drive_kind == "Network" || r.drive_kind == "Optical").count()), "Files on USB drives, discs or network shares: what stops a drive ejecting or a share unmapping"),
    ];
    let fl = filter.replace('/', "\\");
    let mut shown = (0..f.rows.len()).filter(|&i| { let r = &f.rows[i]; matches(&chip_id, r) && (fl.is_empty() || format!("{} {} {} {} {}", r.path, r.remote, r.drive_kind, r.procs_text, r.processes.iter().map(|p| format!("{} {}", p.name, p.pid)).collect::<Vec<_>>().join(" ")).to_lowercase().contains(&fl)) }).collect();
    sort_indices(&f.rows, &mut shown, &sort.0, sort.1, |r, k| match k {
        "name" => sv_s(&r.name),
        "folder" => sv_s(&r.folder),
        "procs_text" => sv_s(&r.procs_text),
        "write" => sv_b(r.write && r.open),
        "handles" => sv_n(r.handles as f64),
        "activity" => sv_n((r.read_bytes + r.write_bytes) as f64),
        "drive_kind" => sv_s(&r.drive_kind),
        _ => sv_s(""),
    });
    let count: String = format!(
        "{} files{}{}{}",
        if shown.len() == f.rows.len() { f.rows.len().to_string() } else { format!("{} of {}", shown.len(), f.rows.len()) },
        if f.writing > 0 { format!(", {} open for writing", f.writing) } else { String::new() },
        if f.tracing { "" } else { "  ·  tracing off, so no live activity" },
        if f.stats.threads_abandoned > 0 { format!("  ·  {} could not be named", f.stats.threads_abandoned) } else { String::new() }
    );
    rows = shown
        .iter()
        .map(|&i| {
            let r = &f.rows[i];
            let access = if !r.open {
                cell("closed", 1)
            } else if r.write {
                cell(if r.delete_access { "write, delete" } else { "write" }, 3)
            } else {
                cell("read", 1)
            };
            let act = format!("{}{}", if r.read_bytes > 0 { format!("↓{}", bytes(r.read_bytes)) } else { String::new() }, if r.write_bytes > 0 { format!(" ↑{}", bytes(r.write_bytes)) } else { String::new() });
            let held = if r.processes.is_empty() { r.procs_text.clone() } else { r.processes.iter().map(|p| format!("{} ({}){}", p.name, p.pid, if p.write { " writes" } else { "" })).collect::<Vec<_>>().join("\n") };
            simple_row(
                i as i32,
                vec![
                    cell(&r.name, 0),
                    cell(&r.folder, 7),
                    cell(&r.procs_text, 0),
                    access,
                    num(&if r.handles > 0 { r.handles.to_string() } else { String::new() }),
                    cell(act.trim(), 5),
                    suffix_cell(&r.drive_kind, &r.remote),
                ],
                if r.active { 4 } else { 0 },
                &format!("{}\n\nHeld by:\n{}{}", r.path, held, if r.remote.is_empty() { String::new() } else { format!("\n\nShare: {}", r.remote) }),
            )
        })
        .collect();
    let empty = ("\u{E8A5}".into(), format!("No open files match{}.", if filter.is_empty() { String::new() } else { format!(" \"{}\"", filter) }), String::new());
    Rendered { chips, rows, shown, count, empty }
}

fn double(ctx: &Shared, src: usize) {
    let st = ctx.st.borrow();
    let ListData::Files(f) = &st.lists.data else { return };
    let Some(path) = f.rows.get(src).map(|r| r.path.clone()) else { return };
    drop(st);
    finder::find_open(ctx, &path, false);
}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let d = {
        let st = ctx.st.borrow();
        let ListData::Files(f) = &st.lists.data else { return };
        let Some(row) = f.rows.get(src) else { return };
        row.clone()
    };
    file_menu(ctx, x, y, &d);
}

fn file_menu(ctx: &Shared, x: f32, y: f32, d: &OpenFileRow) {
    let mut items = vec![MenuItem::new("who", "Show every handle to this file", { let p = d.path.clone(); move |ctx| finder::find_open(ctx, &p, false) })];
    for p in d.processes.iter().take(6) {
        let pid = p.pid;
        items.push(MenuItem::new(&format!("p{}", pid), &format!("Go to {} ({}){}", p.name, p.pid, if p.write { "  writes" } else { "" }), move |ctx| crate::gui::tree::select_pid(ctx, pid)));
    }
    items.push(MenuItem::sep());
    items.push(MenuItem::new("copy", "Copy path", { let v = d.path.clone(); move |ctx| copy_text(ctx, &v) }));
    items.push(MenuItem::new("copyFolder", "Copy folder", { let v = d.folder.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.folder.is_empty()));
    items.push(MenuItem::new("copyShare", &format!("Copy share path{}", if d.remote.is_empty() { String::new() } else { format!(" ({})", d.remote) }), { let v = d.remote.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.remote.is_empty()));
    items.push(MenuItem::sep());
    items.push(MenuItem::new("reveal", "Show in Explorer", { let p = d.path.clone(); move |ctx| simple_action(ctx, Action::Reveal(p), "Revealed", None) }));
    items.push(MenuItem::new("folderOpen", "Find everything open in this folder", { let f = d.folder.clone(); move |ctx| finder::find_open(ctx, &f, true) }).disabled(d.folder.is_empty()));
    items.extend(menus::file_items(&d.path));
    items.push(MenuItem::sep());
    items.push(
        MenuItem::new("release", "Release the file (force close every handle)", {
            let d = d.clone();
            move |ctx| {
                let p = d.path.clone();
                let n = d.name.clone();
                dialogs::confirm(
                    ctx,
                    &format!("Release {}?", d.name),
                    &format!("Keyhole will force close all {} to {} held by {}. Those programs are not told. A file being written can end up corrupted. Closing the program normally is safer.", plural(d.handles as usize, "handle", "handles"), d.path, d.procs_text),
                    "Release the file",
                    true,
                    Box::new(move |ctx| simple_action(ctx, Action::CloseFileHandles(p), &format!("Released {}", n), Some(Box::new(|ctx| lists::refresh_current(ctx, true))))),
                );
            }
        })
        .danger()
        .disabled(!d.open),
    );
    items.push(
        MenuItem::new("killAll", "Terminate the process holding it", {
            let pid = d.processes.first().map(|p| p.pid).unwrap_or(0);
            move |ctx| match crate::gui::tree::row_of(ctx, pid) {
                Some(p) => crate::gui::tree::confirm_kill(ctx, &p),
                None => bad(ctx, "That process is no longer running"),
            }
        })
        .danger()
        .disabled(d.processes.len() != 1),
    );
    menus::show(ctx, x, y, &d.path, items);
}

fn button(ctx: &Shared, id: &str) {
    let _ = (ctx, id);
}

fn export_csv(data: &ListData, shown: &[usize], _st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Files(f) = data else { return None };
    Some(("keyhole-open-files", csv(&shown.iter().map(|&i| { let r = &f.rows[i]; vec![r.path.clone(), r.processes.iter().map(|p| format!("{} ({})", p.name, p.pid)).collect::<Vec<_>>().join("; "), r.write.to_string(), r.delete_access.to_string(), r.handles.to_string(), r.read_bytes.to_string(), r.write_bytes.to_string(), r.drive_kind.clone(), r.remote.clone()] }).collect::<Vec<_>>(), &["Path", "Held by", "Writable", "Deletable", "Handles", "Read bytes", "Write bytes", "Drive", "Share"])))
}
