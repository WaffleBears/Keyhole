use super::columns::{self, ColDef};
use super::detail::{DetailRows, apply_detail_filter, detail_defs, detail_menu, load_detail, render_detail_head, render_type_chips, select_detail_index, show_tab, update_detail_header, update_header_stats, update_tab_counts};
use super::format::*;
use super::menus::{self, MenuItem};
use super::rows::*;
use super::{Shared, bad, copy_text, dialogs, do_action, finder, good, model, save_settings, spawn, ss, ui};
use crate::{Badge, Cell, Pill, Row, StatusPart};
use keyhole::api::{self, Action, ProcessDetails, TreeView};
use keyhole::model::{Access, LifeState, ProcessRow};
use slint::SharedString;
use std::collections::HashMap;

#[derive(Default)]
pub struct TreeState {
    pub view: Option<TreeView>,
    pub by_pid: HashMap<u32, usize>,
    pub selected: Option<u32>,
    pub last_selected: Option<ProcessRow>,
    pub cpu_history: Vec<f32>,
    pub detail: DetailRows,
    pub detail_note: String,
    pub detail_error: String,
    pub handle_summary: Vec<(String, u32)>,
    pub handles_total: usize,
    pub handles_pending: u64,
    pub type_filter: Option<String>,
    pub chips_expanded: bool,
    pub detail_filter: String,
    pub detail_sort: (String, bool),
    pub detail_sel: Option<usize>,
    pub detail_sel_key: Option<String>,
    pub live_busy: bool,
    pub cpu_tick: u64,
    pub pending_detail: u64,
    pub tab_counts: HashMap<String, usize>,
    pub details: Option<ProcessDetails>,
    pub shown: Vec<usize>,
    pub resolve_dns: bool,
    pub filter: String,
}

pub fn visible_defs(ctx: &Shared) -> Vec<ColDef> {
    let hidden = ctx.settings.borrow().hidden_cols.clone();
    columns::TREE.iter().filter(|c| c.id == "name" || !hidden.contains(&c.id.to_string())).copied().collect()
}

pub fn rebuild_tree_cols(ctx: &Shared) {
    let defs = visible_defs(ctx);
    let (cols, fixed) = columns::build(ctx, "tree", &defs, ui(ctx).get_tree_cols());
    let u = ui(ctx);
    u.set_tree_cols(cols);
    u.set_tree_fixed(fixed);
}

pub fn wire(ctx: &Shared) {
    rebuild_tree_cols(ctx);
    let u = ui(ctx);
    {
        let ctx = ctx.clone();
        u.on_tree_sort_clicked(move |key| {
            let key = key.to_string();
            {
                let mut s = ctx.settings.borrow_mut();
                if s.sort == key {
                    s.descending = !s.descending;
                } else {
                    s.sort = key.clone();
                    s.descending = !matches!(key.as_str(), "name" | "user" | "description" | "company" | "path" | "trust");
                }
            }
            save_settings(&ctx);
            let (sort, desc) = {
                let s = ctx.settings.borrow();
                (s.sort.clone(), s.descending)
            };
            let u = ui(&ctx);
            u.set_tree_sort(ss(&sort));
            u.set_tree_desc(desc);
            let change = api::ViewChange::sort(keyhole::state::SortKey::parse(&sort), desc);
            spawn(&ctx, move |app| api::set_view(app, change), apply_tree);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_tree_resize(move |i, w| {
            let defs = visible_defs(&ctx);
            columns::set_width(&ctx, "tree", &defs, i as usize, w);
            rebuild_tree_cols(&ctx);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_tree_resized_done(move || save_settings(&ctx));
    }
    {
        let ctx = ctx.clone();
        u.on_tree_clicked(move |i| {
            let pid = row_pid(&ctx, i as usize);
            if let Some(pid) = pid {
                set_selected(&ctx, Some(pid));
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_tree_double(move |i| {
            if let Some(pid) = row_pid(&ctx, i as usize) {
                set_selected(&ctx, Some(pid));
                show_tab(&ctx, "details");
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_tree_right(move |i, x, y| {
            if let Some(pid) = row_pid(&ctx, i as usize) {
                set_selected(&ctx, Some(pid));
                if let Some(row) = row_of(&ctx, pid) {
                    process_menu(&ctx, x, y, &row);
                }
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_tree_twisty(move |i| {
            if let Some(row) = row_pid(&ctx, i as usize).and_then(|pid| row_of(&ctx, pid)) {
                let expanded = row.collapsed_descendants > 0;
                let pid = row.pid;
                spawn(&ctx, move |app| api::set_expanded(app, pid, expanded), apply_tree);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_tree_header_right(move |x, y| column_chooser(&ctx, x, y));
    }
    {
        let ctx = ctx.clone();
        u.on_tree_filter_edited(move |text| {
            let text = text.to_string();
            ctx.st.borrow_mut().tree.filter = text.clone();
            let ctx2 = ctx.clone();
            let timer = slint::Timer::default();
            timer.start(slint::TimerMode::SingleShot, std::time::Duration::from_millis(140), move || {
                let current = ctx2.st.borrow().tree.filter.clone();
                if current == text {
                    let change = api::ViewChange::filter(&text);
                    spawn(&ctx2, move |app| api::set_view(app, change), apply_tree);
                }
            });
            ctx.st.borrow_mut().tree_filter_timer = Some(timer);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_tree_flat_changed(move |flat| {
            ctx.settings.borrow_mut().flat = flat;
            save_settings(&ctx);
            ui(&ctx).set_tree_flat(flat);
            spawn(&ctx, move |app| api::set_view(app, api::ViewChange::flat(flat)), apply_tree);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_collapse_all(move || spawn(&ctx, api::collapse_all, apply_tree));
    }
    {
        let ctx = ctx.clone();
        u.on_expand_all(move || spawn(&ctx, api::expand_all, apply_tree));
    }
    {
        let ctx = ctx.clone();
        u.on_dh_suspend(move || {
            let Some(row) = selected_row(&ctx) else { return };
            if row.suspended {
                do_action(&ctx, Action::Resume(row.pid), &format!("Resumed {}", row.name));
            } else {
                confirm_suspend(&ctx, &row);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_dh_kill(move || {
            if let Some(row) = selected_row(&ctx) {
                confirm_kill(&ctx, &row);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_dh_more(move |x, y| {
            if let Some(row) = selected_row(&ctx) {
                process_menu(&ctx, x.max(8.0), y, &row);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_tab_clicked(move |t| show_tab(&ctx, t.as_str()));
    }
    {
        let ctx = ctx.clone();
        u.on_detail_sort_clicked(move |key| {
            {
                let mut st = ctx.st.borrow_mut();
                if st.tree.detail_sort.0 == key.as_str() {
                    st.tree.detail_sort.1 = !st.tree.detail_sort.1;
                } else {
                    st.tree.detail_sort = (key.to_string(), false);
                }
            }
            apply_detail_filter(&ctx);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_detail_resize(move |i, w| {
            let tab = ui(&ctx).get_tab().to_string();
            columns::set_width(&ctx, &format!("detail.{}", tab), detail_defs(&tab), i as usize, w);
            render_detail_head(&ctx);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_detail_resized_done(move || save_settings(&ctx));
    }
    {
        let ctx = ctx.clone();
        u.on_detail_clicked(move |i| select_detail_index(&ctx, i as usize));
    }
    {
        let ctx = ctx.clone();
        u.on_detail_right(move |i, x, y| {
            select_detail_index(&ctx, i as usize);
            detail_menu(&ctx, i as usize, x, y);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_detail_double(move |i| {
            let st = ctx.st.borrow();
            if let (DetailRows::Handles(rows), Some(&src)) = (&st.tree.detail, st.tree.shown.get(i as usize)) {
                let Some(path) = rows.get(src).map(|r| r.display.clone()) else { return };
                if is_file_path(&path) {
                    drop(st);
                    finder::find_open(&ctx, &path, false);
                }
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_detail_filter_edited(move |t| {
            ctx.st.borrow_mut().tree.detail_filter = t.to_string();
            apply_detail_filter(&ctx);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_named_toggled(move |v| {
            ctx.settings.borrow_mut().named_only = v;
            save_settings(&ctx);
            apply_detail_filter(&ctx);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_dns_toggled(move |v| {
            ctx.st.borrow_mut().tree.resolve_dns = v;
            if ui(&ctx).get_tab() == "network" {
                load_detail(&ctx);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_type_chip_picked(move |id| {
            if id == "__more" {
                let mut st = ctx.st.borrow_mut();
                st.tree.chips_expanded = !st.tree.chips_expanded;
                drop(st);
                render_type_chips(&ctx);
                return;
            }
            ctx.st.borrow_mut().tree.type_filter = if id.is_empty() { None } else { Some(id.to_string()) };
            render_type_chips(&ctx);
            apply_detail_filter(&ctx);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_doc_jump(move |pid| select_pid(&ctx, pid as u32));
    }
}

fn row_pid(ctx: &Shared, index: usize) -> Option<u32> {
    ctx.st.borrow().tree.view.as_ref().and_then(|v| v.rows.get(index)).map(|r| r.pid)
}

pub fn row_of(ctx: &Shared, pid: u32) -> Option<ProcessRow> {
    let st = ctx.st.borrow();
    st.tree.by_pid.get(&pid).and_then(|&i| st.tree.view.as_ref().and_then(|v| v.rows.get(i)).cloned())
}

pub fn selected_row(ctx: &Shared) -> Option<ProcessRow> {
    let st = ctx.st.borrow();
    let pid = st.tree.selected?;
    if let Some(&i) = st.tree.by_pid.get(&pid)
        && let Some(r) = st.tree.view.as_ref().and_then(|v| v.rows.get(i)) {
            return Some(r.clone());
        }
    st.tree.last_selected.clone().filter(|r| r.pid == pid)
}

pub fn apply_tree(ctx: &Shared, view: TreeView) {
    let by_pid: HashMap<u32, usize> = view.rows.iter().enumerate().map(|(i, r)| (r.pid, i)).collect();
    let selected = ctx.st.borrow().tree.selected;
    let rows = build_rows(ctx, &view, selected);
    let icon_count = view.icon_count;
    let filtering = !ctx.st.borrow().tree.filter.trim().is_empty();
    let shown = view.rows.iter().filter(|r| r.state != LifeState::Dead && !r.filter_context).count();
    let total = view.stats.processes as usize;
    let u = ui(ctx);
    super::reconcile_tip(ctx, &rows);
    u.set_tree_rows(model(rows));
    u.set_tree_count(ss(&if filtering {
        format!("{} of {} match", shown, total)
    } else if shown < total {
        format!("{} of {} shown", shown, total)
    } else {
        format!("{} processes", total)
    }));
    if view.rows.is_empty() {
        u.set_tree_empty_text(ss("No process matches that filter."));
        u.set_tree_empty_sub(ss("Try part of a name, a PID, or a path. You can also type user:name, pid:1234 or session:1."));
    }
    render_status(ctx, &view);
    {
        let mut st = ctx.st.borrow_mut();
        st.tree.by_pid = by_pid;
        st.tree.view = Some(view);
    }
    super::update_pause_button(ctx);
    if icon_count > ctx.st.borrow().icon_count && !ctx.st.borrow().icons_pending {
        fetch_icons(ctx);
    }
    if let Some(pid) = selected {
        let row = row_of(ctx, pid);
        match row {
            Some(row) => {
                let paused = ctx.app.paused.load(std::sync::atomic::Ordering::Relaxed);
                {
                    let mut st = ctx.st.borrow_mut();
                    st.tree.last_selected = Some(row.clone());
                    if !paused && row.state != LifeState::Dead && st.tree.cpu_tick != st.ticks {
                        st.tree.cpu_tick = st.ticks;
                        st.tree.cpu_history.push(row.cpu.max(0.0));
                        if st.tree.cpu_history.len() > 40 {
                            st.tree.cpu_history.remove(0);
                        }
                    }
                }
                update_header_stats(ctx, &row);
                u.set_sel_sub(ss(&format!("PID {}  ·  {}", row.pid, if row.image_path.is_empty() { "path unavailable" } else { &row.image_path })));
            }
            None => {
                let live = ctx.st.borrow().tree.view.as_ref().map(|v| v.live_pids.contains(&pid)).unwrap_or(false);
                if live {
                    u.set_sel_sub(ss(&format!("PID {}  ·  hidden by the current filter or a collapsed branch", pid)));
                } else {
                    set_selected(ctx, None);
                }
            }
        }
    }
}

fn fetch_icons(ctx: &Shared) {
    let since = ctx.st.borrow().icon_count;
    ctx.st.borrow_mut().icons_pending = true;
    spawn(
        ctx,
        move |app| {
            let raw = api::new_icons(app, since);
            let mut out = Vec::new();
            for (id, bytes) in raw {
                if let Some(img) = decode_png(&bytes) {
                    out.push((id, img));
                }
            }
            (out, app.icons.len())
        },
        |ctx, (icons, count)| {
            {
                let mut st = ctx.st.borrow_mut();
                for (id, (w, h, rgba)) in icons {
                    let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(&rgba, w, h);
                    st.icons.insert(id, slint::Image::from_rgba8(buf));
                }
                st.icon_count = count.max(st.icon_count);
                st.icons_pending = false;
            }
            if let Some(view) = ctx.st.borrow().tree.view.clone() {
                let selected = ctx.st.borrow().tree.selected;
                let rows = build_rows(ctx, &view, selected);
                ui(ctx).set_tree_rows(model(rows));
            }
            update_detail_header(ctx);
        },
    );
}

fn decode_png(bytes: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0u8; reader.output_buffer_size()?];
    let info = reader.next_frame(&mut buf).ok()?;
    if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight {
        return None;
    }
    buf.truncate(info.buffer_size());
    Some((info.width, info.height, buf))
}

pub fn icon_of(ctx: &Shared, id: u32) -> Option<slint::Image> {
    ctx.st.borrow().icons.get(&id).cloned()
}

fn build_rows(ctx: &Shared, view: &TreeView, selected: Option<u32>) -> Vec<Row> {
    let defs = visible_defs(ctx);
    let flat = ctx.settings.borrow().flat;
    let now = now_ms();
    let mem_scale = view.rows.iter().map(|r| r.private_bytes.max(r.working_set)).max().unwrap_or(0).max(256 << 20) as f32;
    view.rows
        .iter()
        .map(|r| {
            let dead = r.state == LifeState::Dead;
            let mut badges = Vec::new();
            if !r.service_names.is_empty() {
                let label = if r.service_names.len() > 2 { format!("{} services", r.service_names.len()) } else { r.service_names.join(", ") };
                badges.push(Badge { text: ss(&label), kind: 1, tip: ss(&r.service_names.join(", ")) });
            }
            if r.collapsed_descendants > 0 {
                badges.push(Badge { text: ss(&format!("+{}", r.collapsed_descendants)), kind: 0, tip: ss(&format!("{} hidden child process{}", r.collapsed_descendants, if r.collapsed_descendants == 1 { "" } else { "es" })) });
            }
            if dead {
                badges.push(Badge { text: ss("exited"), kind: 4, tip: ss("This process has just exited. The row disappears after a moment") });
            } else if r.state == LifeState::New {
                badges.push(Badge { text: ss("new"), kind: 5, tip: ss("Started since the previous refresh") });
            }
            if !dead {
                match r.access {
                    Access::Denied => badges.push(Badge { text: ss("locked"), kind: 3, tip: ss(if r.access_note.is_empty() { "Windows refused to open this process, so its details cannot be read" } else { &r.access_note }) }),
                    Access::Protected => badges.push(Badge { text: ss(if r.protection.is_empty() { "kernel" } else { &r.protection }), kind: 3, tip: ss(if r.access_note.is_empty() { "Protected process: Windows never lets other programs inspect it" } else { &r.access_note }) }),
                    Access::Partial => badges.push(Badge { text: ss("partial"), kind: 3, tip: ss(&r.access_note) }),
                    Access::Full => {}
                }
                if r.elevated {
                    badges.push(Badge { text: ss("elevated"), kind: 2, tip: ss("Running with administrator rights") });
                }
                if r.critical {
                    badges.push(Badge { text: ss("critical"), kind: 4, tip: ss("Windows marks this process critical. If it ends the machine blue screens, so Keyhole will not terminate or suspend it") });
                }
                if r.suspended {
                    badges.push(Badge { text: ss("suspended"), kind: 4, tip: ss("Every thread in this process is suspended. Right-click and choose Resume") });
                }
            }
            let cells: Vec<Cell> = defs.iter().map(|d| tree_cell(r, d.id, now, mem_scale)).collect();
            let icon = icon_of(ctx, r.icon);
            Row {
                id: r.pid as i32,
                cells: model(cells),
                tone: if dead { 2 } else if r.state == LifeState::New { 3 } else if r.filter_context { 1 } else { 0 },
                selected: selected == Some(r.pid),
                indent: if flat { 0 } else { r.depth as i32 },
                twisty: if r.children > 0 { if r.collapsed_descendants > 0 { 1 } else { 2 } } else { 0 },
                has_icon: icon.is_some(),
                icon: icon.unwrap_or_default(),
                badges: model(badges),
                tip: ss(&row_tip(r)),
            }
        })
        .collect()
}

fn tree_cell(r: &ProcessRow, id: &str, now: i64, mem_scale: f32) -> Cell {
    let text = |t: String| cell(&t, 0);
    let num = |t: String| cell(&t, 0);
    match id {
        "name" => text(r.name.clone()),
        "pid" => num(r.pid.to_string()),
        "cpu" => Cell { bar: if r.cpu >= 2.0 { (r.cpu / 100.0).max(0.06) } else { 0.0 }, bar_tone: if r.cpu >= 40.0 { 4 } else if r.cpu >= 12.0 { 3 } else { 5 }, ..cell(&pct(r.cpu), if r.cpu >= 40.0 { 4 } else if r.cpu >= 12.0 { 3 } else { 0 }) },
        "private" => Cell { bar: if r.private_bytes > 32 << 20 { (r.private_bytes as f32 / mem_scale).clamp(0.04, 1.0) } else { 0.0 }, bar_tone: 7, ..cell(&bytes(r.private_bytes), 0) },
        "working" => Cell { bar: if r.working_set > 32 << 20 { (r.working_set as f32 / mem_scale).clamp(0.04, 1.0) } else { 0.0 }, bar_tone: 7, ..cell(&bytes(r.working_set), 0) },
        "handles" => num(if r.handle_count > 0 { r.handle_count.to_string() } else { String::new() }),
        "threads" => num(if r.thread_count > 0 { r.thread_count.to_string() } else { String::new() }),
        "io" => num(rate(r.read_rate + r.write_rate)),
        "user" => text(short_user(&r.user)),
        "description" => text(r.description.clone()),
        "company" => text(r.company.clone()),
        "start" => num(if r.start_time > 0 { fmt_age(now - r.start_time) } else { String::new() }),
        "session" => num(r.session.to_string()),
        "trust" => cell(&sig_text(&r.trust), sig_tone(&r.trust)),
        "path" => cell(&r.image_path, 7),
        "cmd" => cell(&r.command_line, 7),
        _ => text(String::new()),
    }
}

fn row_tip(r: &ProcessRow) -> String {
    let mut t = format!("{}  ·  PID {}", r.name, r.pid);
    if !r.description.is_empty() || !r.company.is_empty() {
        let bits: Vec<&str> = [r.description.as_str(), r.company.as_str()].into_iter().filter(|s| !s.is_empty()).collect();
        t.push('\n');
        t.push_str(&bits.join("  ·  "));
    }
    if !r.image_path.is_empty() {
        t.push('\n');
        t.push_str(&r.image_path);
    }
    if !r.command_line.is_empty() && r.command_line != r.image_path {
        t.push_str("\n\n");
        t.push_str(&r.command_line);
    }
    if r.start_time > 0 {
        t.push_str("\n\nStarted ");
        t.push_str(&time_of(r.start_time));
    }
    if !r.service_names.is_empty() {
        t.push_str("\n\nServices: ");
        t.push_str(&r.service_names.join(", "));
    }
    if !r.access_note.is_empty() {
        t.push_str("\n\n");
        t.push_str(&r.access_note);
    }
    t
}

fn render_status(ctx: &Shared, view: &TreeView) {
    let s = &view.stats;
    let mem = if s.mem_total > 0 { (s.mem_used as f64 / s.mem_total as f64 * 100.0).round() as u64 } else { 0 };
    let mut parts = vec![
        StatusPart { bold: ss(&s.processes.to_string()), text: ss("processes"), tip: SharedString::default() },
        StatusPart { bold: ss(&thousands(s.threads as u64)), text: ss("threads"), tip: SharedString::default() },
        StatusPart { bold: ss(&thousands(s.handles as u64)), text: ss("handles"), tip: SharedString::default() },
        StatusPart { bold: ss(&format!("{:.1}%", s.cpu)), text: ss("CPU"), tip: SharedString::default() },
        StatusPart { bold: ss(&format!("{}%", mem)), text: ss(&format!("RAM of {}", bytes(s.mem_total))), tip: SharedString::default() },
    ];
    if s.inaccessible > 0 {
        parts.push(StatusPart { bold: ss(&s.inaccessible.to_string()), text: ss("not readable"), tip: ss("Protected processes Windows will not let Keyhole open even as administrator. Their paths, users and handles are unknown.") });
    }
    let etw_why = if s.etw_note.is_empty() { String::new() } else { format!(" {}.", s.etw_note) };
    let pills = vec![
        Pill { id: ss("admin"), text: ss("Administrator"), ok: true, clickable: false, tip: ss("Running as administrator: every process and handle is visible") },
        if s.debug_privilege {
            Pill { id: ss("dbg"), text: ss("Shared counts"), ok: true, clickable: false, tip: ss("Debug privilege is on, so Keyhole can tell when several processes share one object (the Shared column)") }
        } else {
            Pill { id: ss("dbg"), text: ss("No shared counts"), ok: false, clickable: false, tip: ss("Without debug privilege Windows hides object addresses, so the Shared column stays empty") }
        },
        if s.etw_active {
            Pill { id: ss("etw"), text: ss("Tracing on"), ok: true, clickable: true, tip: ss("Kernel disk and network tracing is on, so the Disk and Network views show live throughput. Click to stop it.") }
        } else {
            Pill { id: ss("etw"), text: ss("Tracing off"), ok: false, clickable: true, tip: ss(&format!("Kernel tracing is off, so the Disk view has no per file activity and the Network view no throughput.{} Click to start it.", etw_why)) }
        },
    ];
    let u = ui(ctx);
    u.set_status_parts(model(parts));
    u.set_pills(model(pills));
}

pub fn set_selected(ctx: &Shared, pid: Option<u32>) {
    select(ctx, pid, false);
}

fn select(ctx: &Shared, pid: Option<u32>, defer: bool) {
    let (old, new) = {
        let mut st = ctx.st.borrow_mut();
        let old = st.tree.selected;
        if pid != old {
            st.tree.cpu_history.clear();
            st.tree.last_selected = None;
        }
        st.tree.selected = pid;
        st.tree.tab_counts.clear();
        st.detail_timer = None;
        (old.and_then(|p| st.tree.by_pid.get(&p).copied()), pid.and_then(|p| st.tree.by_pid.get(&p).copied()))
    };
    super::highlight_row(&ui(ctx).get_tree_rows(), old, new);
    update_detail_header(ctx);
    if let Some(row) = pid.and_then(|p| row_of(ctx, p)) {
        let mut st = ctx.st.borrow_mut();
        st.tree.tab_counts.insert("handles".into(), row.handle_count as usize);
        st.tree.tab_counts.insert("threads".into(), row.thread_count as usize);
    }
    update_tab_counts(ctx);
    if !defer {
        load_detail(ctx);
        return;
    }
    let ctx2 = ctx.clone();
    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::SingleShot, std::time::Duration::from_millis(220), move || {
        if ctx2.st.borrow().tree.selected == pid {
            load_detail(&ctx2);
        }
    });
    ctx.st.borrow_mut().detail_timer = Some(timer);
}

pub fn on_key(ctx: &Shared, key: char) -> bool {
    use slint::platform::Key;
    let u = ui(ctx);
    if u.get_dialog_open() || u.get_finder_open() {
        return false;
    }
    if key == char::from(Key::Delete) {
        if let Some(row) = selected_row(ctx) {
            confirm_kill(ctx, &row);
        }
        return true;
    }
    if key == char::from(Key::DownArrow) || key == char::from(Key::UpArrow) {
        move_selection(ctx, if key == char::from(Key::DownArrow) { 1 } else { -1 });
        return true;
    }
    if key == char::from(Key::RightArrow) || key == char::from(Key::LeftArrow) {
        if let Some(row) = selected_row(ctx)
            && row.children > 0 {
                let collapsed = row.collapsed_descendants > 0;
                let pid = row.pid;
                if key == char::from(Key::RightArrow) && collapsed {
                    spawn(ctx, move |app| api::set_expanded(app, pid, true), apply_tree);
                } else if key == char::from(Key::LeftArrow) && !collapsed {
                    spawn(ctx, move |app| api::set_expanded(app, pid, false), apply_tree);
                }
            }
        return true;
    }
    false
}

fn move_selection(ctx: &Shared, delta: i32) {
    let (len, idx) = {
        let st = ctx.st.borrow();
        let Some(view) = st.tree.view.as_ref() else { return };
        let idx = st.tree.selected.and_then(|p| st.tree.by_pid.get(&p).copied());
        (view.rows.len(), idx)
    };
    if len == 0 {
        return;
    }
    let next = match idx {
        None => 0,
        Some(i) => (i as i32 + delta).clamp(0, len as i32 - 1) as usize,
    };
    if let Some(pid) = row_pid(ctx, next) {
        select(ctx, Some(pid), true);
        scroll_tree_to(ctx, next);
    }
}

fn scroll_tree_to(ctx: &Shared, index: usize) {
    let u = ui(ctx);
    u.set_tree_scroll_index(index as i32);
    u.set_tree_scroll_seq(u.get_tree_scroll_seq() + 1);
}

pub fn select_pid(ctx: &Shared, pid: u32) {
    super::set_mode(ctx, "processes");
    let idx = ctx.st.borrow().tree.by_pid.get(&pid).copied();
    if let Some(i) = idx {
        set_selected(ctx, Some(pid));
        scroll_tree_to(ctx, i);
        return;
    }
    let live = ctx.st.borrow().tree.view.as_ref().map(|v| v.live_pids.contains(&pid)).unwrap_or(false);
    if !live {
        bad(ctx, "That process has exited");
        return;
    }
    ui(ctx).set_tree_filter(ss(""));
    ctx.st.borrow_mut().tree.filter.clear();
    spawn(ctx, move |app| api::reveal(app, pid), move |ctx, view| {
        apply_tree(ctx, view);
        set_selected(ctx, Some(pid));
        let idx = ctx.st.borrow().tree.by_pid.get(&pid).copied();
        match idx {
            Some(i) => scroll_tree_to(ctx, i),
            None => bad(ctx, "That process has exited"),
        }
    });
}

pub fn filter_tree(ctx: &Shared, query: &str) {
    super::set_mode(ctx, "processes");
    ui(ctx).set_tree_filter(ss(query));
    ctx.st.borrow_mut().tree.filter = query.to_string();
    let change = api::ViewChange::filter(query);
    spawn(ctx, move |app| api::set_view(app, change), apply_tree);
}

pub fn find_running_pid(ctx: &Shared, name: &str) -> Option<u32> {
    let exe = name.rsplit('\\').next().unwrap_or("").to_lowercase();
    if exe.is_empty() {
        return None;
    }
    let st = ctx.st.borrow();
    st.tree.view.as_ref()?.rows.iter().find(|r| r.name.to_lowercase() == exe && r.state != LifeState::Dead).map(|r| r.pid)
}

pub fn find_running(ctx: &Shared, path: &str) {
    let exe = path.rsplit('\\').next().unwrap_or("").to_string();
    if !exe.is_empty() {
        filter_tree(ctx, &exe);
    }
}

fn critical_note(row: &ProcessRow, verb: &str) -> String {
    format!("{} is a critical Windows process, so Keyhole will not {} it. Ending it would blue screen this machine", row.name, verb)
}

pub fn confirm_suspend(ctx: &Shared, row: &ProcessRow) {
    if row.critical {
        bad(ctx, &critical_note(row, "suspend"));
        return;
    }
    let pid = row.pid;
    let name = row.name.clone();
    dialogs::confirm(
        ctx,
        &format!("Suspend {}?", name),
        &format!("Every thread in {} (pid {}) is frozen until you choose Resume. Anything waiting on it hangs meanwhile.", name, pid),
        "Suspend",
        true,
        Box::new(move |ctx| do_action(ctx, Action::Suspend(pid), &format!("Suspended {}", name))),
    );
}

pub fn confirm_kill(ctx: &Shared, row: &ProcessRow) {
    if row.critical {
        bad(ctx, &critical_note(row, "terminate"));
        return;
    }
    let pid = row.pid;
    let name = row.name.clone();
    dialogs::confirm(
        ctx,
        &format!("Terminate {}?", name),
        &format!("This kills {} (pid {}) immediately. Anything it had not written to disk is lost.", name, pid),
        "Terminate",
        true,
        Box::new(move |ctx| do_action(ctx, Action::Terminate(pid), &format!("Terminated {}", name))),
    );
}

fn kill_tree_confirm(ctx: &Shared, row: &ProcessRow) {
    if row.critical {
        bad(ctx, &critical_note(row, "terminate"));
        return;
    }
    let pid = row.pid;
    let name = row.name.clone();
    spawn(ctx, move |app| api::descendant_names(app, pid), move |ctx, names| {
        let n = names.len() + 1;
        let more = if names.len() > 8 { format!(" and {} more", names.len() - 8) } else { String::new() };
        let shown = names.iter().take(8).cloned().collect::<Vec<_>>().join(", ") + &more;
        let body = if n <= 1 {
            format!("This terminates {} (pid {}). It has no children.", name, pid)
        } else {
            format!("This terminates {} and its {} descendant process{} ({}), {} in total, deepest first. Unsaved work in any of them is lost.", name, n - 1, if n - 1 == 1 { "" } else { "es" }, shown, n)
        };
        dialogs::confirm(ctx, "Terminate process tree?", &body, &format!("Terminate {}", n), true, Box::new(move |ctx| do_action(ctx, Action::KillTree(pid), &format!("Terminated {} process{}", n, if n == 1 { "" } else { "es" }))));
    });
}

pub fn process_menu(ctx: &Shared, x: f32, y: f32, row: &ProcessRow) {
    let parent = if row.ppid > 0 { row_of(ctx, row.ppid) } else { None };
    let same_name = ctx.st.borrow().tree.view.as_ref().map(|v| v.rows.iter().filter(|r| r.name == row.name && r.state != LifeState::Dead).count()).unwrap_or(0);
    let r = row.clone();
    let pid = row.pid;
    let mut items: Vec<MenuItem> = vec![
        MenuItem::new("details", "Properties", move |ctx| { select_pid(ctx, pid); show_tab(ctx, "details"); }),
        MenuItem::new("parent", &format!("Go to parent{}", parent.as_ref().map(|p| format!(" ({})", p.name)).unwrap_or_default()), { let ppid = row.ppid; move |ctx| select_pid(ctx, ppid) }).disabled(parent.is_none()),
        MenuItem::new("same", &format!("Show all {} processes{}", row.name, if same_name > 1 { format!(" ({})", same_name) } else { String::new() }), { let n = row.name.clone(); move |ctx| filter_tree(ctx, &n) }).disabled(same_name < 2),
        MenuItem::new("svcs", "Show hosted services", move |ctx| super::lists::show_services_for_pid(ctx, pid)).disabled(row.service_names.is_empty()),
        MenuItem::sep(),
        MenuItem::new("copyName", "Copy name", { let n = row.name.clone(); move |ctx| copy_text(ctx, &n) }),
        MenuItem::new("copyPid", "Copy PID", move |ctx| copy_text(ctx, &pid.to_string())),
        MenuItem::new("copyPath", "Copy image path", { let p = row.image_path.clone(); move |ctx| copy_text(ctx, &p) }).disabled(row.image_path.is_empty()),
        MenuItem::new("copyCmd", "Copy command line", { let p = row.command_line.clone(); move |ctx| copy_text(ctx, &p) }).disabled(row.command_line.is_empty()),
        MenuItem::new("copyUser", "Copy user", { let p = row.user.clone(); move |ctx| copy_text(ctx, &p) }).disabled(row.user.is_empty()),
        MenuItem::new("copySummary", "Copy summary (for a ticket or email)", { let r = r.clone(); move |ctx| copy_text(ctx, &process_summary(&r)) }),
        MenuItem::sep(),
        MenuItem::new("reveal", "Show file in Explorer", { let p = row.image_path.clone(); move |ctx| super::simple_action(ctx, Action::Reveal(p.clone()), "Revealed in Explorer", None) }).disabled(row.image_path.is_empty()),
        MenuItem::new("whoelse", "Find what else has this file open", { let p = row.image_path.clone(); move |ctx| finder::find_open(ctx, &p, false) }).disabled(row.image_path.is_empty()),
    ];
    items.extend(menus::file_items(&row.image_path));
    items.push(MenuItem::sep());
    items.push(MenuItem::new("suspend", "Suspend…", { let r = r.clone(); move |ctx| confirm_suspend(ctx, &r) }).disabled(row.suspended || row.critical));
    items.push(MenuItem::new("resume", "Resume", { let n = row.name.clone(); move |ctx| do_action(ctx, Action::Resume(pid), &format!("Resumed {}", n)) }).disabled(!row.suspended));
    items.push(MenuItem::new("dump", "Save minidump…", { let r = r.clone(); move |ctx| save_dump(ctx, &r, false) }).tip("Threads, stacks, handles and loaded modules: small, enough for most crash analysis"));
    items.push(MenuItem::sep());
    items.push(
        MenuItem::new("restart", "Restart", {
            let r = r.clone();
            move |ctx| {
                let n = r.name.clone();
                let pid = r.pid;
                dialogs::confirm(
                    ctx,
                    &format!("Restart {}?", n),
                    &format!("This terminates {} (pid {}) and starts it again with the same command line, working directory, user and session. Unsaved work is lost. If Windows will not lend Keyhole the original account, the new instance runs as administrator.", n, pid),
                    "Restart",
                    true,
                    Box::new(move |ctx| do_action(ctx, Action::Restart(pid), &format!("Restarted {}", n))),
                );
            }
        })
        .danger()
        .disabled(row.image_path.is_empty() || row.critical),
    );
    items.push(MenuItem::new("kill", "Terminate", { let r = r.clone(); move |ctx| confirm_kill(ctx, &r) }).danger().key("Del").disabled(row.critical).tip(if row.critical { "Windows marks this process critical. Ending it blue screens the machine" } else { "" }));
    items.push(MenuItem::new("killtree", "Terminate process tree", { let r = r.clone(); move |ctx| kill_tree_confirm(ctx, &r) }).danger().disabled(row.critical));
    menus::show(ctx, x, y, &format!("{}  ·  pid {}", row.name, row.pid), items);
}

fn save_dump(ctx: &Shared, row: &ProcessRow, full: bool) {
    let stem = match row.name.len().checked_sub(4).filter(|&i| i > 0 && row.name.is_char_boundary(i)) {
        Some(i) if row.name[i..].eq_ignore_ascii_case(".exe") => &row.name[..i],
        _ => &row.name,
    };
    let default_name = format!("{}-{}{}.dmp", stem, row.pid, if full { "-full" } else { "" });
    let Some(path) = keyhole::sys::dialogs::save_file(super::window_hwnd(ctx), &default_name, "dmp") else { return };
    let pid = row.pid;
    let path2 = path.clone();
    spawn(ctx, move |_| api::write_dump(pid, &path2, full), move |ctx, r| match r {
        Ok(()) => good(ctx, &format!("{} written to {}", if full { "Full dump" } else { "Minidump" }, path)),
        Err(e) => bad(ctx, &e),
    });
}

pub fn process_summary(row: &ProcessRow) -> String {
    let mut lines = vec![format!("{}  (PID {})", row.name, row.pid)];
    if !row.description.is_empty() {
        lines.push(format!("Description: {}", row.description));
    }
    if !row.company.is_empty() {
        lines.push(format!("Company: {}", row.company));
    }
    if !row.image_path.is_empty() {
        lines.push(format!("Path: {}", row.image_path));
    }
    if !row.command_line.is_empty() {
        lines.push(format!("Command line: {}", row.command_line));
    }
    if !row.user.is_empty() {
        lines.push(format!("User: {}", row.user));
    }
    if row.start_time > 0 {
        lines.push(format!("Started: {}", time_of(row.start_time)));
    }
    lines.push(format!("CPU: {}   Private: {}   Working set: {}   Handles: {}   Threads: {}", if row.cpu >= 0.05 { pct(row.cpu) } else { "0%".into() }, bytes_or_zero(row.private_bytes), bytes_or_zero(row.working_set), row.handle_count, row.thread_count));
    if !row.service_names.is_empty() {
        lines.push(format!("Services: {}", row.service_names.join(", ")));
    }
    lines.join("\n")
}

fn column_chooser(ctx: &Shared, x: f32, y: f32) {
    let hidden = ctx.settings.borrow().hidden_cols.clone();
    let mut items: Vec<MenuItem> = columns::TREE
        .iter()
        .filter(|c| c.id != "name")
        .map(|c| {
            let id = c.id.to_string();
            let on = !hidden.contains(&id);
            MenuItem::new(&format!("col-{}", id), &format!("{} {}", if on { "✓" } else { "   " }, c.label), move |ctx| {
                {
                    let mut s = ctx.settings.borrow_mut();
                    if s.hidden_cols.contains(&id) {
                        s.hidden_cols.retain(|h| h != &id);
                    } else {
                        s.hidden_cols.push(id.clone());
                    }
                }
                save_settings(ctx);
                rebuild_tree_cols(ctx);
                if let Some(view) = ctx.st.borrow().tree.view.clone() {
                    let selected = ctx.st.borrow().tree.selected;
                    let rows = build_rows(ctx, &view, selected);
                    ui(ctx).set_tree_rows(model(rows));
                }
            })
        })
        .collect();
    items.push(MenuItem::sep());
    let any_widths = !ctx.settings.borrow().widths.is_empty();
    items.push(
        MenuItem::new("reset", "Reset column widths", |ctx| {
            ctx.settings.borrow_mut().widths.clear();
            save_settings(ctx);
            rebuild_tree_cols(ctx);
            render_detail_head(ctx);
        })
        .disabled(!any_widths),
    );
    menus::show(ctx, x, y, "Show columns", items);
}

pub fn process_rows_table(ctx: &Shared) -> Vec<Vec<String>> {
    let st = ctx.st.borrow();
    let Some(view) = st.tree.view.as_ref() else { return Vec::new() };
    rows_table(&view.rows)
}

pub fn rows_table(rows: &[ProcessRow]) -> Vec<Vec<String>> {
    rows
        .iter()
        .filter(|r| !r.filter_context)
        .map(|r| {
            vec![
                r.name.clone(),
                r.pid.to_string(),
                r.ppid.to_string(),
                r.depth.to_string(),
                format!("{:.2}", r.cpu),
                r.private_bytes.to_string(),
                r.working_set.to_string(),
                r.handle_count.to_string(),
                r.thread_count.to_string(),
                r.user.clone(),
                r.integrity.clone(),
                r.description.clone(),
                r.company.clone(),
                r.session.to_string(),
                r.trust.clone(),
                time_of(r.start_time),
                r.image_path.clone(),
                r.command_line.clone(),
                match r.state {
                    LifeState::Dead => "exited",
                    LifeState::New => "new",
                    LifeState::Normal => "running",
                }
                .to_string(),
            ]
        })
        .collect()
}

pub const PROCESS_HEADER: &[&str] = &["Process", "PID", "Parent PID", "Depth", "CPU %", "Private bytes", "Working set", "Handles", "Threads", "User", "Integrity", "Description", "Company", "Session", "Signature", "Started", "Image path", "Command line", "State"];
