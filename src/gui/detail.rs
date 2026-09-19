use super::columns::{self, ColDef};
use super::format::*;
use super::menus::{self, MenuItem};
use super::rows::*;
use super::tree::{icon_of, selected_row};
use super::{Shared, chip, copy_text, finder, model, save_settings, simple_action, spawn, ss, ui};
use crate::{Badge, Cell, Chip, DocItem, Row, TabInfo};
use keyhole::api::{self, Action};
use keyhole::model::{EndpointRow, HandleRow, LifeState, ModuleRow, ProcessRow, ThreadRow};
use slint::{Model, SharedString};

const CHIP_LIMIT: usize = 9;

#[derive(Default)]
pub enum DetailRows {
    #[default]
    None,
    Handles(Vec<HandleRow>),
    Network(Vec<EndpointRow>),
    Modules(Vec<ModuleRow>),
    Threads(Vec<ThreadRow>),
}


pub fn set_tabs(ctx: &Shared) {
    update_tab_counts(ctx);
}

pub fn tab_label(id: &str) -> &'static str {
    match id {
        "handles" => "Handles",
        "network" => "Network",
        "modules" => "Modules",
        "threads" => "Threads",
        _ => "Details",
    }
}

pub fn update_tab_counts(ctx: &Shared) {
    let st = ctx.st.borrow();
    let tips = [
        ("handles", "Every open object this process holds: files, registry keys, sockets and more"),
        ("network", "TCP and UDP endpoints owned by this process"),
        ("modules", "DLLs and the executable image loaded into this process"),
        ("threads", "Threads, their start address and CPU time"),
        ("details", "Command line, working directory, user, integrity, signature, parent chain, token groups, privileges and processor affinity"),
    ];
    let tabs: Vec<TabInfo> = tips
        .iter()
        .map(|(id, tip)| {
            let count = st.tree.tab_counts.get(*id).map(|c| format!("  {}", c)).unwrap_or_default();
            TabInfo { id: ss(id), label: ss(&format!("{}{}", tab_label(id), count)), tip: ss(tip) }
        })
        .collect();
    drop(st);
    ui(ctx).set_tabs(model(tabs));
}

pub fn update_detail_header(ctx: &Shared) {
    let u = ui(ctx);
    let row = selected_row(ctx);
    match row {
        None => {
            u.set_sel_visible(false);
            u.set_sel_has_icon(false);
            u.set_sel_badges(model(Vec::<Badge>::new()));
            u.set_sel_name(ss("No process selected"));
            u.set_sel_sub(ss("Click a process above to inspect what it has open."));
        }
        Some(row) => {
            let icon = icon_of(ctx, row.icon);
            u.set_sel_has_icon(icon.is_some());
            u.set_sel_icon(icon.unwrap_or_default());
            u.set_sel_name(ss(&row.name));
            u.set_sel_sub(ss(&format!("PID {}  ·  {}", row.pid, if row.image_path.is_empty() { "path unavailable" } else { &row.image_path })));
            u.set_sel_visible(true);
            update_header_stats(ctx, &row);
        }
    }
}

pub fn update_header_stats(ctx: &Shared, row: &ProcessRow) {
    let u = ui(ctx);
    u.set_suspend_label(ss(if row.suspended { "Resume" } else { "Suspend" }));
    u.set_suspend_tip(ss(if row.suspended { "Let every thread in this process run again" } else { "Freeze every thread in this process. The button turns into Resume" }));
    u.set_cpu_text(ss(&if row.cpu >= 0.05 { pct(row.cpu) } else { "0%".into() }));
    u.set_cpu_tone(if row.cpu >= 40.0 { 4 } else if row.cpu >= 12.0 { 3 } else { 0 });
    u.set_priv_text(ss(&if row.private_bytes > 0 { bytes(row.private_bytes) } else { "-".into() }));
    u.set_ws_text(ss(&if row.working_set > 0 { bytes(row.working_set) } else { "-".into() }));
    let mut badges: Vec<Badge> = Vec::new();
    if row.state == LifeState::Dead {
        badges.push(Badge { text: ss("exited"), kind: 4, tip: ss("This process has exited") });
    }
    if !row.user.is_empty() {
        badges.push(Badge { text: ss(&short_user(&row.user)), kind: 9, tip: ss(&row.user) });
    }
    badges.push(Badge { text: ss(&format!("session {}", row.session)), kind: 3, tip: ss("Logon session") });
    if row.start_time > 0 {
        badges.push(Badge { text: ss(&format!("up {}", fmt_age(now_ms() - row.start_time))), kind: 3, tip: ss(&format!("Started {}", time_of(row.start_time))) });
    }
    if row.elevated {
        badges.push(Badge { text: ss("elevated"), kind: 2, tip: ss("Running with administrator rights") });
    }
    if !row.protection.is_empty() {
        badges.push(Badge { text: ss(&row.protection), kind: 3, tip: ss("Protected process") });
    }
    if row.suspended {
        badges.push(Badge { text: ss("suspended"), kind: 4, tip: ss("Every thread is suspended") });
    }
    if !row.trust.is_empty() && row.trust != "unchecked" {
        badges.push(Badge { text: ss(&sig_text(&row.trust)), kind: match row.trust.as_str() { "signed" => 5, "unsigned" => 6, "error" => 3, _ => 7 }, tip: ss(&trust_text(&row.trust)) });
    }
    if !row.service_names.is_empty() {
        badges.push(Badge { text: ss(&plural(row.service_names.len(), "service", "services")), kind: 1, tip: ss(&row.service_names.join(", ")) });
    }
    u.set_sel_badges(model(badges));
    u.set_handles_text(ss(&thousands(row.handle_count as u64)));
    u.set_threads_text(ss(&row.thread_count.to_string()));
    let hist = ctx.st.borrow().tree.cpu_history.clone();
    let max = hist.iter().cloned().fold(5.0f32, f32::max);
    let mut vals: Vec<f32> = hist.iter().map(|v| (v / max).clamp(0.0, 1.0)).collect();
    while vals.len() < 40 {
        vals.insert(0, 0.0);
    }
    let (line, fill) = chart_paths(&vals);
    u.set_cpu_path(ss(&line));
    u.set_cpu_fill(ss(&fill));
}

pub fn show_tab(ctx: &Shared, tab: &str) {
    ctx.settings.borrow_mut().tab = tab.to_string();
    save_settings(ctx);
    let u = ui(ctx);
    u.set_tab(ss(tab));
    u.set_detail_filter(SharedString::default());
    {
        let mut st = ctx.st.borrow_mut();
        st.tree.detail_filter.clear();
        st.tree.detail_sort = (String::new(), false);
    }
    load_detail(ctx);
}

pub fn detail_defs(tab: &str) -> &'static [ColDef] {
    match tab {
        "network" => columns::NETWORK,
        "modules" => columns::MODULES,
        "threads" => columns::THREADS,
        _ => columns::HANDLES,
    }
}

pub fn render_detail_head(ctx: &Shared) {
    let tab = ui(ctx).get_tab().to_string();
    let (cols, fixed) = columns::build(ctx, &format!("detail.{}", tab), detail_defs(&tab), ui(ctx).get_detail_cols());
    let u = ui(ctx);
    u.set_detail_cols(cols);
    u.set_detail_fixed(fixed);
    let (sort, desc) = ctx.st.borrow().tree.detail_sort.clone();
    u.set_detail_sort(ss(&sort));
    u.set_detail_desc(desc);
}

pub fn load_detail(ctx: &Shared) {
    let pid = ctx.st.borrow().tree.selected;
    let tab = ui(ctx).get_tab().to_string();
    let token = {
        let mut st = ctx.st.borrow_mut();
        st.tree.detail_sel = None;
        st.tree.detail_sel_key = None;
        st.tree.pending_detail += 1;
        st.tree.pending_detail
    };
    let u = ui(ctx);
    u.set_detail_is_doc(false);
    u.set_show_named(tab == "handles");
    u.set_show_dns(tab == "network");
    u.set_show_detail_filter(tab != "details");
    u.set_type_chips(model(Vec::<Chip>::new()));
    u.set_type_chips_more(super::no_chip_rows());
    u.set_chip_note(SharedString::default());
    render_detail_head(ctx);
    let Some(pid) = pid else {
        {
            let mut st = ctx.st.borrow_mut();
            st.tree.detail = DetailRows::None;
            st.tree.handle_summary.clear();
            st.tree.shown.clear();
        }
        u.set_detail_rows(model(Vec::<Row>::new()));
        u.set_detail_loading(false);
        u.set_detail_empty_icon(ss("\u{E8FD}"));
        u.set_detail_empty_text(ss("Select a process to inspect what it has open."));
        u.set_detail_empty_sub(SharedString::default());
        return;
    };
    u.set_detail_loading(true);
    u.set_detail_rows(model(Vec::<Row>::new()));
    u.set_detail_empty_text(SharedString::default());
    u.set_detail_empty_sub(SharedString::default());
    if tab == "details" {
        u.set_detail_is_doc(true);
        u.set_detail_doc(model(Vec::<DocItem>::new()));
        spawn(ctx, move |app| api::details(app, pid), move |ctx, d| {
            if ctx.st.borrow().tree.pending_detail != token {
                return;
            }
            ui(ctx).set_detail_loading(false);
            ctx.st.borrow_mut().tree.details = Some(d);
            render_details_doc(ctx);
        });
        return;
    }
    let resolve = ctx.st.borrow().tree.resolve_dns;
    spawn(
        ctx,
        move |app| match tab.as_str() {
            "handles" => {
                let h = api::handles(app, pid);
                (DetailRows::Handles(h.rows), h.note, String::new(), h.summary, h.total, h.stats.pending)
            }
            "network" => (DetailRows::Network(api::network(app, pid, resolve)), String::new(), String::new(), Vec::new(), 0, 0),
            "modules" => match api::modules(app, pid) {
                Ok(rows) => (DetailRows::Modules(rows), String::new(), String::new(), Vec::new(), 0, 0),
                Err(e) => (DetailRows::Modules(Vec::new()), String::new(), e, Vec::new(), 0, 0),
            },
            _ => (DetailRows::Threads(api::threads(app, pid)), String::new(), String::new(), Vec::new(), 0, 0),
        },
        move |ctx, (rows, note, error, summary, total, pending)| {
            if ctx.st.borrow().tree.pending_detail != token {
                return;
            }
            ui(ctx).set_detail_loading(false);
            let tab = ui(ctx).get_tab().to_string();
            {
                let mut st = ctx.st.borrow_mut();
                let count = match &rows {
                    DetailRows::Handles(r) => r.len(),
                    DetailRows::Network(r) => r.len(),
                    DetailRows::Modules(r) => r.len(),
                    DetailRows::Threads(r) => r.len(),
                    DetailRows::None => 0,
                };
                st.tree.tab_counts.insert(tab.clone(), if tab == "handles" { total } else { count });
                st.tree.detail = rows;
                st.tree.detail_note = note;
                st.tree.detail_error = error;
                st.tree.handle_summary = summary;
                st.tree.handles_total = total;
                st.tree.handles_pending = pending;
            }
            update_tab_counts(ctx);
            if tab == "handles" {
                render_type_chips(ctx);
            }
            apply_detail_filter(ctx);
        },
    );
}

pub fn render_type_chips(ctx: &Shared) {
    let (summary, total, pending, filter, expanded) = {
        let st = ctx.st.borrow();
        let count = match &st.tree.detail {
            DetailRows::Handles(r) => r.len(),
            _ => 0,
        };
        (st.tree.handle_summary.clone(), count, st.tree.handles_pending, st.tree.type_filter.clone(), st.tree.chips_expanded)
    };
    let u = ui(ctx);
    if summary.is_empty() {
        u.set_type_chips(model(Vec::<Chip>::new()));
        u.set_type_chips_more(super::no_chip_rows());
        return;
    }
    let mut sorted = summary.clone();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    let filter = filter.filter(|f| sorted.iter().any(|s| &s.0 == f));
    ctx.st.borrow_mut().tree.type_filter = filter.clone();
    let expanded = expanded || sorted.iter().enumerate().any(|(i, s)| i >= CHIP_LIMIT && Some(&s.0) == filter.as_ref());
    let shown: Vec<&(String, u32)> = if expanded { sorted.iter().collect() } else { sorted.iter().take(CHIP_LIMIT).collect() };
    let mut chips = vec![chip("", "All", Some(total), "Show handles of every type")];
    for s in shown {
        chips.push(chip(&s.0, &s.0, Some(s.1 as usize), &format!("Show only {} handles ({})", s.0, s.1)));
    }
    if sorted.len() > CHIP_LIMIT {
        chips.push(chip("__more", &if expanded { "fewer".to_string() } else { format!("+{} more", sorted.len() - CHIP_LIMIT) }, None, if expanded { "Show only the most common types" } else { "Show every object type" }));
    }
    let (chips, chips2) = super::split_chips(ctx, chips, 260.0);
    u.set_type_chips(model(chips));
    u.set_type_chips_more(chips2);
    u.set_type_chip(ss(filter.as_deref().unwrap_or("")));
    u.set_chip_note(ss(&if pending > 0 { format!("{} still resolving, reopen the tab for more", pending) } else { String::new() }));
}

pub fn apply_detail_filter(ctx: &Shared) {
    let named_only = ctx.settings.borrow().named_only;
    let (filter, type_filter, sort, error, note) = {
        let st = ctx.st.borrow();
        (
            st.tree.detail_filter.trim().to_lowercase(),
            st.tree.type_filter.clone(),
            st.tree.detail_sort.clone(),
            st.tree.detail_error.clone(),
            st.tree.detail_note.clone(),
        )
    };
    let mut rows: Vec<Row> = Vec::new();
    let mut shown: Vec<usize> = Vec::new();
    let mut kind = "";
    {
        let st = ctx.st.borrow();
        match &st.tree.detail {
            DetailRows::Handles(list) => {
                kind = "handles";
                shown = (0..list.len())
                    .filter(|&i| {
                        let r = &list[i];
                        (!named_only || r.named)
                            && type_filter.as_ref().map(|t| &r.type_name == t).unwrap_or(true)
                            && (filter.is_empty() || format!("{} {} {} {}", r.type_name, r.display, r.name, r.access_text).to_lowercase().contains(&filter))
                    })
                    .collect();
                sort_indices(list, &mut shown, &sort.0, sort.1, |r, k| match k {
                    "type_name" => sv_s(&r.type_name),
                    "display" => sv_s(&r.display),
                    "access_text" => sv_s(&r.access_text),
                    "handle" => sv_n(r.handle as f64),
                    "shared_with" => sv_n(r.shared_with as f64),
                    _ => sv_s(""),
                });
                rows = shown
                    .iter()
                    .map(|&i| {
                        let r = &list[i];
                        simple_row(
                            i as i32,
                            vec![
                                cell(&r.type_name, 0),
                                if r.display.is_empty() { cell("unnamed", 1) } else { cell(&r.display, 0) },
                                cell(&r.access_text, 0),
                                hexc(&hex(r.handle, 4)),
                                num(&if r.shared_with > 1 { r.shared_with.to_string() } else { String::new() }),
                            ],
                            0,
                            &r.display,
                        )
                    })
                    .collect();
            }
            DetailRows::Network(list) => {
                kind = "network";
                shown = (0..list.len())
                    .filter(|&i| {
                        let r = &list[i];
                        filter.is_empty() || format!("{} {} {} {} {}", r.proto, r.local, r.remote, r.remote_host, r.state).to_lowercase().contains(&filter)
                    })
                    .collect();
                sort_indices(list, &mut shown, &sort.0, sort.1, |r, k| match k {
                    "proto" => sv_s(&r.proto),
                    "local" => sv_s(&r.local),
                    "remote" => sv_s(&r.remote),
                    "state" => sv_s(&r.state),
                    _ => sv_s(""),
                });
                rows = shown
                    .iter()
                    .map(|&i| {
                        let r = &list[i];
                        simple_row(i as i32, vec![cell(&r.proto, 0), hexc(&r.local), remote_cell(r), cell(&r.state, 0)], 0, &if r.remote_host.is_empty() { r.remote.clone() } else { r.remote_host.clone() })
                    })
                    .collect();
            }
            DetailRows::Modules(list) => {
                kind = "modules";
                shown = (0..list.len())
                    .filter(|&i| {
                        let r = &list[i];
                        filter.is_empty() || format!("{} {} {} {}", r.name, r.path, r.company, r.version).to_lowercase().contains(&filter)
                    })
                    .collect();
                sort_indices(list, &mut shown, &sort.0, sort.1, |r, k| match k {
                    "name" => sv_s(&r.name),
                    "version" => sv_s(&r.version),
                    "company" => sv_s(&r.company),
                    "base" => sv_n(r.base as f64),
                    "size" => sv_n(r.size as f64),
                    "path" => sv_s(&r.path),
                    _ => sv_s(""),
                });
                rows = shown
                    .iter()
                    .map(|&i| {
                        let r = &list[i];
                        simple_row(i as i32, vec![cell(&r.name, 0), cell(&r.version, 0), cell(&r.company, 0), hexc(&hex(r.base, 0)), num(&bytes(r.size)), cell(&r.path, 7)], 0, &r.path)
                    })
                    .collect();
            }
            DetailRows::Threads(list) => {
                kind = "threads";
                shown = (0..list.len())
                    .filter(|&i| {
                        let r = &list[i];
                        filter.is_empty() || format!("{} {} {}", r.tid, r.start_module, r.state).to_lowercase().contains(&filter)
                    })
                    .collect();
                sort_indices(list, &mut shown, &sort.0, sort.1, |r, k| match k {
                    "tid" => sv_n(r.tid as f64),
                    "start_module" => sv_s(&r.start_module),
                    "state" => sv_s(&r.state),
                    "cpu_time_ms" => sv_n(r.cpu_time_ms as f64),
                    "priority" => sv_n(r.priority as f64),
                    "created" => sv_n(r.created as f64),
                    _ => sv_s(""),
                });
                rows = shown
                    .iter()
                    .map(|&i| {
                        let r = &list[i];
                        simple_row(
                            i as i32,
                            vec![
                                num(&r.tid.to_string()),
                                cell(&if r.start_module.is_empty() { hex(r.start_address, 0) } else { r.start_module.clone() }, 0),
                                cell(&r.state, 0),
                                num(&fmt_ms(r.cpu_time_ms)),
                                num(&r.priority.to_string()),
                                cell(&time_of(r.created), 0),
                            ],
                            0,
                            "",
                        )
                    })
                    .collect();
            }
            DetailRows::None => {}
        }
    }
    let sel = {
        let mut st = ctx.st.borrow_mut();
        let want = st.tree.detail_sel_key.clone();
        st.tree.detail_sel = want.and_then(|w| shown.iter().position(|&s| detail_key(&st.tree.detail, s).as_deref() == Some(w.as_str())));
        st.tree.shown = shown;
        st.tree.detail_sel
    };
    if let Some(i) = sel {
        rows[i].selected = true;
    }
    let u = ui(ctx);
    let empty = rows.is_empty();
    super::reconcile_tip(ctx, &rows);
    u.set_detail_rows(model(rows));
    if empty {
        let (icon, text, sub) = if !error.is_empty() {
            ("", error, String::new())
        } else if !note.is_empty() {
            ("", note, String::new())
        } else if !filter.is_empty() {
            ("\u{E721}", format!("Nothing in this tab matches \"{}\".", filter), String::new())
        } else {
            match kind {
                "handles" => match &type_filter {
                    Some(t) => ("", format!("No {} handles{}.", t, if named_only { " with a name" } else { "" }), String::new()),
                    None if named_only => ("\u{E8FD}", "No named objects open.".to_string(), "Untick Named only to see events, mutants and semaphores too.".to_string()),
                    None => ("", "No handles visible for this process.".to_string(), String::new()),
                },
                "network" => ("\u{E968}", "No network connections or listening ports.".to_string(), String::new()),
                "modules" => ("", "No modules could be read from this process.".to_string(), String::new()),
                "threads" => ("", "No threads could be read from this process.".to_string(), String::new()),
                _ => ("", "Nothing to show here.".to_string(), String::new()),
            }
        };
        u.set_detail_empty_icon(ss(icon));
        u.set_detail_empty_text(ss(&text));
        u.set_detail_empty_sub(ss(&sub));
    }
}

pub fn remote_cell(r: &EndpointRow) -> Cell {
    if r.remote_host.is_empty() {
        hexc(&r.remote)
    } else {
        suffix_cell(&r.remote_host, &format!("· {}", r.remote))
    }
}

pub fn render_details_doc(ctx: &Shared) {
    let Some(d) = ctx.st.borrow().tree.details.clone() else { return };
    let live = selected_row(ctx);
    let mut items = Vec::new();
    let push = |items: &mut Vec<DocItem>, k: &str, v: String| {
        if !v.is_empty() {
            items.push(kv(k, &v));
        }
    };
    if !d.accessible && d.image_path.is_empty() && !d.note.is_empty() {
        items.push(DocItem { kind: 4, value: ss(&d.note), tone: 3, ..doc_default() });
    }
    push(&mut items, "Description", d.description.clone());
    push(&mut items, "Company", d.company.clone());
    push(&mut items, "Product", if !d.product.is_empty() && d.product != d.description { format!("{}{}", d.product, if d.file_version.is_empty() { String::new() } else { format!("  {}", d.file_version) }) } else { d.file_version.clone() });
    push(&mut items, "Image path", d.image_path.clone());
    push(&mut items, "Command line", d.command_line.clone());
    push(&mut items, "Working directory", d.working_dir.clone());
    push(&mut items, "PID", d.pid.to_string());
    push(&mut items, "Parent", if d.ppid > 0 { if d.parent_name.is_empty() { format!("PID {}  (no longer running)", d.ppid) } else { format!("{}  ({})", d.parent_name, d.ppid) } } else { String::new() });
    push(&mut items, "Session", d.session.to_string());
    let started = time_of(d.started_unix_ms);
    push(&mut items, "Started", if let Some(l) = live.as_ref().filter(|l| l.start_time > 0) { format!("{}  ({} ago)", started, fmt_age(now_ms() - l.start_time)) } else { started });
    push(&mut items, "User", d.user.clone());
    push(&mut items, "Integrity", format!("{}{}", d.integrity, if d.elevated { "  (running as administrator)" } else { "" }));
    push(&mut items, "Architecture", d.arch.clone());
    push(&mut items, "Processors", affinity_text(&d.cpus, &d.system_cpus));
    push(&mut items, "Protection", d.protection.clone());
    push(&mut items, "Signature", if d.trust != "unchecked" && !d.trust.is_empty() { trust_text(&d.trust) } else { String::new() });
    if let Some(l) = &live {
        if l.private_bytes > 0 {
            push(&mut items, "Memory", format!("{} private  ·  {} working set", bytes(l.private_bytes), bytes(l.working_set)));
        }
        if l.read_total > 0 || l.write_total > 0 {
            push(&mut items, "I/O total", format!("{} read  ·  {} written (all handles, not only disk)", bytes_or_zero(l.read_total), bytes_or_zero(l.write_total)));
        }
    }
    if !d.parent_chain.is_empty() {
        items.push(section("Parent chain", "click a link to jump to that process"));
        let badges: Vec<Badge> = d.parent_chain.iter().map(|c| Badge { text: ss(&format!("{} ({})", c.name, c.pid)), kind: c.pid as i32, tip: ss("Jump to this process") }).collect();
        items.push(DocItem { kind: 7, badges: model(badges), ..doc_default() });
    }
    if !d.note.is_empty() && (d.accessible || !d.image_path.is_empty()) {
        items.push(section("Note", ""));
        items.push(DocItem { kind: 4, value: ss(&d.note), tone: 3, ..doc_default() });
    }
    if !d.privileges.is_empty() {
        items.push(section(&format!("Privileges ({})", d.privileges.len()), "what the token is allowed to do. Enabled ones are in effect now"));
        let mut badges: Vec<Badge> = d.privileges.iter().filter(|p| p.1).map(|p| Badge { text: ss(&p.0), kind: 10, tip: ss("Enabled") }).collect();
        badges.extend(d.privileges.iter().filter(|p| !p.1).map(|p| Badge { text: ss(&p.0), kind: 3, tip: ss("Present but disabled") }));
        items.push(DocItem { kind: 2, badges: model(badges), ..doc_default() });
    }
    if !d.groups.is_empty() {
        items.push(section(&format!("Groups ({})", d.groups.len()), ""));
        let badges: Vec<Badge> = d.groups.iter().map(|g| Badge { text: ss(g), kind: if g.contains("(deny only)") || g.contains("(disabled)") { 3 } else { 9 }, tip: SharedString::default() }).collect();
        items.push(DocItem { kind: 2, badges: model(badges), ..doc_default() });
    }
    ui(ctx).set_detail_doc(model(items));
}

pub fn details_text(ctx: &Shared) -> Option<String> {
    let u = ui(ctx);
    if !u.get_detail_is_doc() {
        return None;
    }
    let mut lines = Vec::new();
    for it in u.get_detail_doc().iter() {
        match it.kind {
            0 => lines.push(format!("\r\n{}", it.key)),
            1 => lines.push(format!("{}: {}", it.key, it.value)),
            2 | 7 => lines.push(it.badges.iter().map(|b| b.text.to_string()).collect::<Vec<_>>().join(", ")),
            4 => lines.push(it.value.to_string()),
            _ => {}
        }
    }
    Some(lines.join("\r\n") + "\r\n")
}

pub fn maybe_live_detail(ctx: &Shared) {
    let mode = ctx.st.borrow().mode.clone();
    if mode != "processes" {
        return;
    }
    let Some(pid) = ctx.st.borrow().tree.selected else { return };
    let tab = ui(ctx).get_tab().to_string();
    if tab != "network" && tab != "threads" {
        return;
    }
    if ctx.st.borrow().tree.live_busy {
        return;
    }
    ctx.st.borrow_mut().tree.live_busy = true;
    let token = ctx.st.borrow().tree.pending_detail;
    let resolve = ctx.st.borrow().tree.resolve_dns;
    let tab2 = tab.clone();
    spawn(
        ctx,
        move |app| if tab2 == "network" { DetailRows::Network(api::network(app, pid, resolve)) } else { DetailRows::Threads(api::threads(app, pid)) },
        move |ctx, rows| {
            ctx.st.borrow_mut().tree.live_busy = false;
            let same = {
                let st = ctx.st.borrow();
                st.tree.pending_detail == token && st.tree.selected == Some(pid)
            };
            if !same || ui(ctx).get_tab() != tab.as_str() {
                return;
            }
            let count = match &rows {
                DetailRows::Network(r) => r.len(),
                DetailRows::Threads(r) => r.len(),
                _ => 0,
            };
            {
                let mut st = ctx.st.borrow_mut();
                st.tree.detail = rows;
                st.tree.tab_counts.insert(tab.clone(), count);
            }
            update_tab_counts(ctx);
            apply_detail_filter(ctx);
        },
    );
}

fn detail_key(rows: &DetailRows, src: usize) -> Option<String> {
    match rows {
        DetailRows::Handles(list) => list.get(src).map(|r| format!("h{}", r.handle)),
        DetailRows::Network(list) => list.get(src).map(|r| format!("n{} {} {}", r.proto, r.local, r.remote)),
        DetailRows::Modules(list) => list.get(src).map(|r| format!("m{}", r.base)),
        DetailRows::Threads(list) => list.get(src).map(|r| format!("t{}", r.tid)),
        DetailRows::None => None,
    }
}

pub fn select_detail_index(ctx: &Shared, i: usize) {
    let old = {
        let mut st = ctx.st.borrow_mut();
        let key = st.tree.shown.get(i).and_then(|&src| detail_key(&st.tree.detail, src));
        st.tree.detail_sel_key = key;
        st.tree.detail_sel.replace(i)
    };
    if old != Some(i) {
        super::highlight_row(&ui(ctx).get_detail_rows(), old, Some(i));
    }
}

pub fn detail_menu(ctx: &Shared, index: usize, x: f32, y: f32) {
    let selected = selected_row(ctx);
    let st = ctx.st.borrow();
    let Some(&src) = st.tree.shown.get(index) else { return };
    match &st.tree.detail {
        DetailRows::Handles(rows) => {
            let Some(mut r) = rows.get(src).cloned() else { return };
            r.process = selected.as_ref().map(|s| s.name.clone()).unwrap_or_default();
            drop(st);
            menus::handle_menu(ctx, x, y, &r);
        }
        DetailRows::Modules(rows) => {
            let Some(m) = rows.get(src).cloned() else { return };
            drop(st);
            let mut items = vec![
                MenuItem::new("copyName", "Copy name", { let n = m.name.clone(); move |ctx| copy_text(ctx, &n) }),
                MenuItem::new("copy", "Copy path", { let p = m.path.clone(); move |ctx| copy_text(ctx, &p) }),
                MenuItem::sep(),
                MenuItem::new("reveal", "Show in Explorer", { let p = m.path.clone(); move |ctx| simple_action(ctx, Action::Reveal(p.clone()), "Revealed", None) }).disabled(m.path.is_empty()),
                MenuItem::new("folder", "Open containing folder", { let p = m.path.clone(); move |ctx| simple_action(ctx, Action::OpenFolder(p.clone()), "Opened folder", None) }).disabled(m.path.is_empty()),
                MenuItem::new("whoelse", "Find what else has this open", { let p = m.path.clone(); move |ctx| finder::find_open(ctx, &p, false) }).disabled(m.path.is_empty()),
            ];
            items.extend(menus::file_items(&m.path));
            menus::show(ctx, x, y, &m.path, items);
        }
        DetailRows::Network(rows) => {
            let Some(d) = rows.get(src).cloned() else { return };
            drop(st);
            let items = vec![
                MenuItem::new("copyL", "Copy local address", { let v = d.local.clone(); move |ctx| copy_text(ctx, &v) }),
                MenuItem::new("copyR", "Copy remote address", { let v = d.remote.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.remote.is_empty()),
                MenuItem::new("copyH", "Copy remote host name", { let v = d.remote_host.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.remote_host.is_empty()),
                MenuItem::sep(),
                menus::close_connection_item(&d, Box::new(load_detail)),
            ];
            menus::show(ctx, x, y, &if d.remote.is_empty() { d.local.clone() } else { d.remote.clone() }, items);
        }
        DetailRows::Threads(rows) => {
            let Some(t) = rows.get(src).cloned() else { return };
            drop(st);
            let tid = t.tid;
            let items = vec![
                MenuItem::new("copyTid", "Copy thread ID", move |ctx| copy_text(ctx, &tid.to_string())),
                MenuItem::new("copyStart", "Copy start address", { let s = if t.start_module.is_empty() { hex(t.start_address, 0) } else { t.start_module.clone() }; move |ctx| copy_text(ctx, &s) }),
            ];
            menus::show(ctx, x, y, &format!("Thread {}", t.tid), items);
        }
        DetailRows::None => {}
    }
}

pub fn detail_doc_menu(ctx: &Shared, index: usize, x: f32, y: f32) {
    let items = ui(ctx).get_detail_doc();
    let Some(it) = items.row_data(index) else { return };
    if it.kind != 1 {
        return;
    }
    let name = it.key.to_string();
    let value = it.value.to_string();
    let is_path = is_file_path(value.trim().trim_matches('"'));
    let v2 = value.clone();
    let n2 = name.clone();
    let entries = vec![
        MenuItem::new("cv", "Copy value", { let v = value.clone(); move |ctx| copy_text(ctx, &v) }).disabled(value.is_empty()),
        MenuItem::new("cb", "Copy name and value", move |ctx| copy_text(ctx, &format!("{}: {}", n2, v2))),
        MenuItem::sep(),
        MenuItem::new("open", "Show in Explorer", { let v = value.clone(); let n3 = name.clone(); move |ctx| {
            let p = if n3 == "Command line" { keyhole::sys::actions::exe_from_command(&v) } else { v.trim().trim_matches('"').to_string() };
            simple_action(ctx, Action::Reveal(p), "Revealed", None);
        } }).disabled(!is_path),
    ];
    menus::show(ctx, x, y, &name, entries);
}

pub fn detail_tab_csv(ctx: &Shared) -> Option<(String, String)> {
    let st = ctx.st.borrow();
    let name = st.tree.last_selected.as_ref().map(|r| safe_name(&r.name)).unwrap_or_else(|| "process".into());
    let tab = ui(ctx).get_tab().to_string();
    let base = format!("keyhole-{}-{}", name, tab);
    let shown = &st.tree.shown;
    let content = match &st.tree.detail {
        DetailRows::Handles(rows) => csv(&shown.iter().map(|&i| { let x = &rows[i]; vec![x.type_name.clone(), x.display.clone(), x.access_text.clone(), hex(x.handle, 0), x.shared_with.to_string()] }).collect::<Vec<_>>(), &["Type", "Name", "Access", "Handle", "Shared with"]),
        DetailRows::Network(rows) => csv(&shown.iter().map(|&i| { let x = &rows[i]; vec![x.proto.clone(), x.local.clone(), x.remote.clone(), x.remote_host.clone(), x.state.clone()] }).collect::<Vec<_>>(), &["Protocol", "Local", "Remote", "Remote host", "State"]),
        DetailRows::Modules(rows) => csv(&shown.iter().map(|&i| { let x = &rows[i]; vec![x.name.clone(), x.version.clone(), x.company.clone(), hex(x.base, 0), x.size.to_string(), x.path.clone()] }).collect::<Vec<_>>(), &["Module", "Version", "Company", "Base", "Size", "Path"]),
        DetailRows::Threads(rows) => csv(&shown.iter().map(|&i| { let x = &rows[i]; vec![x.tid.to_string(), if x.start_module.is_empty() { hex(x.start_address, 0) } else { x.start_module.clone() }, x.state.clone(), x.cpu_time_ms.to_string(), x.priority.to_string(), time_of(x.created)] }).collect::<Vec<_>>(), &["TID", "Start", "State", "CPU ms", "Priority", "Created"]),
        DetailRows::None => return None,
    };
    Some((base, content))
}
