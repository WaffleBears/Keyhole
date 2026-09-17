use super::format::*;
use super::menus::{self, MenuItem};
use super::kinds::{Kind, RenderInput};
use super::lists::{ListData, ListState};
use super::{Shared, activity, bad, copy_text, detail, finder, good, lists, rows, system, tree, ui, window_hwnd};

const VIEW_LABELS: &[(&str, &str)] = &[
    ("processes", "Process list"),
    ("activity", "Disk activity"),
    ("network", "Connections"),
    ("resources", "Resources"),
    ("files", "Open files"),
    ("handles", "Handles"),
    ("services", "Services"),
    ("startup", "Startup entries"),
    ("tasks", "Scheduled tasks"),
    ("drivers", "Drivers"),
    ("software", "Installed software"),
    ("firewall", "Firewall rules"),
    ("sessions", "Sessions"),
    ("events", "Events"),
    ("crashes", "Crashes"),
    ("shares", "Shares"),
    ("users", "Users and groups"),
    ("updates", "Updates"),
    ("certs", "Certificates"),
    ("netconfig", "Network configuration"),
    ("environment", "System overview"),
];

pub fn export_menu(ctx: &Shared, x: f32, y: f32) {
    let finder_open = ui(ctx).get_finder_open();
    let mode = ctx.st.borrow().mode.clone();
    let mut items: Vec<MenuItem> = Vec::new();
    if finder_open {
        items.push(MenuItem::new("view", "Search results (CSV)", |ctx| save_view(ctx, "search")));
    } else {
        let label = VIEW_LABELS.iter().find(|(m, _)| *m == mode).map(|(_, l)| *l).unwrap_or("This view");
        let ext = if mode == "environment" { "text" } else { "CSV" };
        let m = mode.clone();
        let filtered = if mode == "processes" {
            !ctx.st.borrow().tree.filter.trim().is_empty()
        } else {
            super::kinds::kind_of(&mode).is_some() && {
                let st = ctx.st.borrow();
                !st.lists.filter.get(&mode).map(|f| f.trim().is_empty()).unwrap_or(true) || !st.lists.chip.get(&mode).map(|c| c.is_empty()).unwrap_or(true)
            }
        };
        items.push(MenuItem::new("view", &format!("{} ({}){}", label, ext, if filtered { ", rows shown now" } else { "" }), move |ctx| save_view(ctx, &m)).tip(if filtered { "Only the rows that pass the current filter and chip" } else { "Every row in this view, every column, including hidden ones" }));
        if filtered {
            let m2 = mode.clone();
            items.push(MenuItem::new("viewall", &format!("{} ({}), all rows", label, ext), move |ctx| save_view_all(ctx, &m2)).tip("Ignores the filter and chip"));
        }
    }
    if !finder_open && mode == "processes"
        && let Some(r) = tree::selected_row(ctx) {
            let tab = ui(ctx).get_tab().to_string();
            if tab == "details" {
                items.push(MenuItem::new("details", &format!("{}: Details (text)", r.name), save_details));
            } else {
                let label = match tab.as_str() {
                    "handles" => "Handles",
                    "network" => "Network",
                    "modules" => "Modules",
                    _ => "Threads",
                };
                items.push(MenuItem::new("tab", &format!("{}: {} tab (CSV)", r.name, label), save_tab));
            }
        }
    items.push(MenuItem::new("snapshot", "Whole system snapshot: every process with details (JSON)", save_snapshot));
    items.push(MenuItem::new("everything", "Everything: every view into a folder (CSV, text, JSON)", save_everything).tip("Every view unfiltered, plus the system overview, process list and snapshot, in a new keyhole-<host>-<time> folder"));
    if !finder_open && mode == "processes" {
        items.push(MenuItem::new("copy", "Copy the process list to the clipboard as tab separated text", |ctx| {
            let rows = tree::process_rows_table(ctx);
            if rows.is_empty() {
                bad(ctx, "Nothing to copy");
            } else {
                copy_text(ctx, &tsv(&rows, tree::PROCESS_HEADER));
            }
        }));
    }
    menus::show(ctx, x, y, "Export", items);
}

fn file_bytes(name: &str, content: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 3);
    if name.to_ascii_lowercase().ends_with(".csv") {
        out.extend_from_slice("\u{FEFF}".as_bytes());
    }
    out.extend_from_slice(content.as_bytes());
    out
}

fn write_to(ctx: &Shared, path: &str, content: String) {
    match std::fs::write(path, file_bytes(path, &content)) {
        Ok(()) => good(ctx, &format!("Saved to {}", path)),
        Err(e) => bad(ctx, &e.to_string()),
    }
}

fn write(ctx: &Shared, name: &str, ext: &str, content: String) {
    let Some(path) = keyhole::sys::dialogs::save_file(window_hwnd(ctx), &format!("{}.{}", name, ext), ext) else { return };
    write_to(ctx, &path, content);
}

fn unfiltered_csv(ctx: &Shared, k: &'static Kind, data: &ListData) -> Option<(String, String)> {
    let st = ctx.st.borrow();
    let table = (k.table)(&st.lists);
    let sort = st.lists.sort.get(&table).cloned().unwrap_or_else(|| { let d = (k.default_sort)(&st.lists); (d.0.to_string(), d.1) });
    let input = RenderInput { filter: String::new(), chip: String::new(), sort, gh_type: st.lists.gh_type.clone(), table };
    let rendered = (k.render)(ctx, data, &input);
    (k.csv)(data, &rendered.shown, &st.lists).map(|(n, b)| (n.to_string(), b))
}

fn save_view(ctx: &Shared, mode: &str) {
    match mode {
        "search" => write(ctx, "keyhole-search", "csv", csv(&finder::csv_rows(ctx), &["Process", "PID", "Type", "Handle", "Path", "Access"])),
        "processes" => {
            if ctx.st.borrow().tree.filter.trim().is_empty() {
                save_view_all(ctx, "processes");
            } else {
                write(ctx, "keyhole-processes", "csv", csv(&tree::process_rows_table(ctx), tree::PROCESS_HEADER));
            }
        }
        "environment" => write(ctx, "keyhole-system", "txt", system::system_text(ctx)),
        "resources" => match super::resources::resources_csv(ctx) {
            Some((name, content)) => write(ctx, &name, "csv", content),
            None => bad(ctx, "Nothing to export here yet"),
        },
        "activity" => match activity::activity_csv(ctx) {
            Some((name, content)) => write(ctx, &name, "csv", content),
            None => bad(ctx, "Nothing to export here yet"),
        },
        _ => match lists::csv_of(ctx) {
            Some((name, content)) => write(ctx, &name, "csv", content),
            None => bad(ctx, "Nothing to export here yet"),
        },
    }
}

fn save_view_all(ctx: &Shared, mode: &str) {
    if mode == "processes" {
        let Some(path) = keyhole::sys::dialogs::save_file(window_hwnd(ctx), "keyhole-processes.csv", "csv") else { return };
        super::spawn(ctx, |app| csv(&tree::rows_table(&app.full_rows()), tree::PROCESS_HEADER), move |ctx, body| write_to(ctx, &path, body));
        return;
    }
    let Some(k) = super::kinds::kind_of(mode) else { return save_view(ctx, mode) };
    if mode == "network" {
        let Some(path) = keyhole::sys::dialogs::save_file(window_hwnd(ctx), "keyhole-connections.csv", "csv") else { return };
        super::spawn(ctx, |app| ListData::Connections(keyhole::api::connections(app, false, "")), move |ctx, data| match unfiltered_csv(ctx, k, &data) {
            Some((_, body)) => write_to(ctx, &path, body),
            None => bad(ctx, "Nothing to export here yet"),
        });
        return;
    }
    let result = {
        let st = ctx.st.borrow();
        unfiltered_csv(ctx, k, &st.lists.data)
    };
    match result {
        Some((name, body)) => write(ctx, &name, "csv", body),
        None => bad(ctx, "Nothing to export here yet"),
    }
}

fn save_details(ctx: &Shared) {
    let Some(text) = detail::details_text(ctx) else {
        bad(ctx, "Nothing to export here yet");
        return;
    };
    let name = tree::selected_row(ctx).map(|r| safe_name(&r.name)).unwrap_or_else(|| "process".into());
    write(ctx, &format!("keyhole-{}-details", name), "txt", text);
}

fn save_tab(ctx: &Shared) {
    match detail::detail_tab_csv(ctx) {
        Some((name, content)) => write(ctx, &name, "csv", content),
        None => bad(ctx, "Nothing to export here yet"),
    }
}

fn save_snapshot(ctx: &Shared) {
    let Some(path) = keyhole::sys::dialogs::save_file(window_hwnd(ctx), "keyhole-snapshot.json", "json") else { return };
    super::spawn(ctx, keyhole::api::snapshot_json, move |ctx, r| match r {
        Ok(body) => match std::fs::write(&path, body) {
            Ok(()) => good(ctx, &format!("Saved to {}", path)),
            Err(e) => bad(ctx, &e.to_string()),
        },
        Err(e) => bad(ctx, &e),
    });
}

struct Collected {
    kind: &'static Kind,
    data: ListData,
    took_ms: u128,
}

fn file_stem(csv_name: &str) -> String {
    csv_name.strip_prefix("keyhole-").unwrap_or(csv_name).to_string()
}

fn write_part(folder: &std::path::Path, manifest: &mut Vec<String>, name: &str, content: &str, rows: Option<usize>) {
    let path = folder.join(name);
    match std::fs::write(&path, file_bytes(name, content)) {
        Ok(()) => manifest.push(match rows {
            Some(n) => format!("{:<40} {} {}", name, n, if n == 1 { "row" } else { "rows" }),
            None => format!("{:<40} {} bytes", name, content.len()),
        }),
        Err(e) => manifest.push(format!("{:<40} FAILED: {}", name, e)),
    }
}

pub fn save_everything(ctx: &Shared) {
    let Some(dir) = keyhole::sys::dialogs::pick_folder(window_hwnd(ctx), "Choose where Keyhole should create the export folder") else { return };
    save_everything_to(ctx, &dir, true);
}

pub fn save_everything_to(ctx: &Shared, dir: &str, subfolder: bool) {
    let (host, _) = keyhole::sys::sysinfo::host_and_domain();
    let folder = if subfolder { std::path::PathBuf::from(dir).join(format!("keyhole-{}-{}", safe_name(&host.to_lowercase()), keyhole::sys::local_stamp())) } else { std::path::PathBuf::from(dir) };
    let resources = super::resources::resources_csv(ctx);
    let activity = activity::activity_csv(ctx);
    let base = {
        let st = ctx.st.borrow();
        ListState { events: st.lists.events.settings_only(), ..Default::default() }
    };
    good(ctx, "Collecting every view. This can take a minute");
    ui(ctx).set_list_loading(true);
    let folder2 = folder.clone();
    super::spawn(
        ctx,
        move |app| -> Result<(Vec<String>, Vec<Collected>), String> {
            std::fs::create_dir_all(&folder2).map_err(|e| format!("could not create {}: {}", folder2.display(), e))?;
            let mut manifest = Vec::new();
            let system_text = super::system::text_of(&keyhole::api::environment());
            write_part(&folder2, &mut manifest, "system.txt", &system_text, None);
            let process_rows = tree::rows_table(&app.full_rows());
            let processes = csv(&process_rows, tree::PROCESS_HEADER);
            write_part(&folder2, &mut manifest, "processes.csv", &processes, Some(process_rows.len()));
            if let Some((_, body)) = &resources {
                write_part(&folder2, &mut manifest, "resources.csv", body, None);
            }
            if let Some((_, body)) = &activity {
                write_part(&folder2, &mut manifest, "disk-activity.csv", body, None);
            }
            match keyhole::api::snapshot_json(app) {
                Ok(body) => write_part(&folder2, &mut manifest, "snapshot.json", &body, None),
                Err(e) => manifest.push(format!("{:<40} FAILED: {}", "snapshot.json", e)),
            }
            let mut collected = Vec::new();
            for k in super::kinds::ALL {
                let started = std::time::Instant::now();
                let data = if k.name == "network" {
                    ListData::Connections(keyhole::api::connections(app, false, ""))
                } else {
                    let st = ListState { kind: k.name.to_string(), events: base.events.settings_only(), ..Default::default() };
                    (k.refresh)(app, &st)
                };
                collected.push(Collected { kind: k, data, took_ms: started.elapsed().as_millis() });
            }
            Ok((manifest, collected))
        },
        move |ctx, res| {
            let (manifest, collected) = match res {
                Ok(v) => v,
                Err(e) => {
                    ui(ctx).set_list_loading(false);
                    bad(ctx, &e);
                    return;
                }
            };
            let mut plan: Vec<(&'static Kind, Vec<(String, Vec<usize>, usize)>, String, u128)> = Vec::new();
            for c in &collected {
                let k = c.kind;
                let mut st = ListState { kind: k.name.to_string(), ..Default::default() };
                let segments: Vec<String> = (k.segments)(&st).iter().map(|s| s.id.to_string()).collect();
                let segments = if segments.is_empty() { vec![String::new()] } else { segments };
                let mut summary = String::new();
                let mut segs = Vec::new();
                for seg in segments {
                    if !seg.is_empty() {
                        st.segment.insert(k.name.to_string(), seg.clone());
                    }
                    let table = (k.table)(&st);
                    let sort = (k.default_sort)(&st);
                    let input = RenderInput { filter: String::new(), chip: String::new(), sort: (sort.0.to_string(), sort.1), gh_type: st.gh_type.clone(), table };
                    let rendered = (k.render)(ctx, &c.data, &input);
                    if summary.is_empty() {
                        summary = rendered.count.clone();
                    }
                    let count = rendered.shown.len();
                    segs.push((seg, rendered.shown, count));
                }
                plan.push((k, segs, summary, c.took_ms));
            }
            let folder3 = folder.clone();
            super::spawn(
                ctx,
                move |_| {
                    let mut manifest = manifest;
                    let mut files = 0usize;
                    let mut written: std::collections::HashSet<String> = std::collections::HashSet::new();
                    for (c, (k, segs, summary, took)) in collected.iter().zip(plan) {
                        let mut st = ListState { kind: k.name.to_string(), ..Default::default() };
                        for (seg, shown, count) in segs {
                            if !seg.is_empty() {
                                st.segment.insert(k.name.to_string(), seg.clone());
                            }
                            let Some((name, body)) = (k.csv)(&c.data, &shown, &st) else { continue };
                            let file = format!("{}.csv", file_stem(name));
                            if !written.insert(file.clone()) {
                                continue;
                            }
                            write_part(&folder3, &mut manifest, &file, &body, Some(count));
                            files += 1;
                        }
                        manifest.push(format!("{:<40} {} (collected in {} ms)", k.name, summary, took));
                    }
                    let (host, domain) = keyhole::sys::sysinfo::host_and_domain();
                    let mut text = format!("Keyhole export from {}{}\n{}\n\n", host, if domain.is_empty() { String::new() } else { format!(" ({})", domain) }, keyhole::sys::local_time_text(rows::now_ms()));
                    text.push_str("Every view is exported unfiltered. CSV files open in Excel, and snapshot.json holds every process with its details.\n\n");
                    for line in &manifest {
                        text.push_str(line);
                        text.push('\n');
                    }
                    let _ = std::fs::write(folder3.join("README.txt"), text);
                    files
                },
                move |ctx, files| {
                    ui(ctx).set_list_loading(false);
                    good(ctx, &format!("Saved {} views to {}", files, folder.display()));
                    let _ = keyhole::sys::actions::reveal_in_explorer(&folder.display().to_string());
                },
            );
        },
    );
}
