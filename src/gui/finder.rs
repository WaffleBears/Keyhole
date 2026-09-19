use super::columns;
use super::format::*;
use super::rows::{cell, hexc, num, simple_row, sort_indices, sv_n, sv_s};
use super::{Shared, chip, menus, model, save_settings, spawn, ss, ui};
use crate::Row;
use keyhole::api;
use keyhole::model::HandleRow;
use keyhole::objects::SearchResult;

#[derive(Default)]
pub struct FinderState {
    pub query: String,
    pub subtree: bool,
    pub all: Vec<HandleRow>,
    pub shown: Vec<usize>,
    pub sel: i32,
    pub chip: String,
    pub sort: (String, bool),
    pub pending: u64,
    pub foot: String,
}

pub fn writes(access: &str) -> bool {
    ["WriteData", "AppendData", "GenericWrite", "AllAccess", "Delete"].iter().any(|w| access.contains(w))
}

pub fn wire(ctx: &Shared) {
    let u = ui(ctx);
    render_head(ctx);
    {
        let ctx = ctx.clone();
        u.on_finder_close(move || close(&ctx));
    }
    {
        let ctx = ctx.clone();
        u.on_finder_rerun(move || rerun(&ctx));
    }
    {
        let ctx = ctx.clone();
        u.on_finder_export(move |x, y| super::export::export_menu(&ctx, x, y));
    }
    {
        let ctx = ctx.clone();
        u.on_finder_subtree_changed(move |v| {
            ctx.st.borrow_mut().finder.subtree = v;
            rerun(&ctx);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_finder_sort_clicked(move |k| {
            {
                let mut st = ctx.st.borrow_mut();
                if st.finder.sort.0 == k.as_str() {
                    st.finder.sort.1 = !st.finder.sort.1;
                } else {
                    st.finder.sort = (k.to_string(), false);
                }
            }
            render_head(&ctx);
            render_rows(&ctx, false);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_finder_resize(move |i, w| {
            columns::set_width(&ctx, "finder", columns::FINDER, i as usize, w);
            render_head(&ctx);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_finder_resized_done(move || save_settings(&ctx));
    }
    {
        let ctx = ctx.clone();
        u.on_finder_clicked(move |i| {
            ctx.st.borrow_mut().finder.sel = i;
            render_rows(&ctx, false);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_finder_double(move |i| {
            let pid = shown_row(&ctx, i as usize).map(|r| r.pid);
            if let Some(pid) = pid {
                close(&ctx);
                super::tree::select_pid(&ctx, pid);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_finder_right(move |i, x, y| {
            if let Some(r) = shown_row(&ctx, i as usize) {
                menus::handle_menu(&ctx, x, y, &r);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_finder_chip_picked(move |id| {
            {
                let mut st = ctx.st.borrow_mut();
                st.finder.chip = id.to_string();
                st.finder.sel = 0;
            }
            render_rows(&ctx, true);
        });
    }
}

pub fn render_head(ctx: &Shared) {
    let (cols, fixed) = columns::build(ctx, "finder", columns::FINDER, ui(ctx).get_finder_cols());
    let u = ui(ctx);
    u.set_finder_cols(cols);
    u.set_finder_fixed(fixed);
    let (s, d) = ctx.st.borrow().finder.sort.clone();
    u.set_finder_sort(ss(&s));
    u.set_finder_desc(d);
}

fn shown_row(ctx: &Shared, i: usize) -> Option<HandleRow> {
    let st = ctx.st.borrow();
    st.finder.shown.get(i).and_then(|&src| st.finder.all.get(src)).cloned()
}

pub fn close(ctx: &Shared) {
    ui(ctx).set_finder_open(false);
    super::focus_keys(ctx);
}

pub fn rerun(ctx: &Shared) {
    let (q, subtree) = {
        let st = ctx.st.borrow();
        (st.finder.query.clone(), st.finder.subtree)
    };
    if !q.is_empty() {
        run_search(ctx, &q, subtree);
    }
}

pub fn rerun_if_open(ctx: &Shared) {
    if ui(ctx).get_finder_open() {
        rerun(ctx);
    }
}

pub fn find_open(ctx: &Shared, path: &str, subtree: bool) {
    if path.is_empty() {
        return;
    }
    ui(ctx).set_search_text(ss(path));
    run_search(ctx, path, subtree);
}

pub fn on_drop(ctx: &Shared, path: &str) {
    let has_ext = path.rsplit('\\').next().map(|n| n.contains('.') && n.rsplit('.').next().map(|e| !e.is_empty() && e.len() <= 6).unwrap_or(false)).unwrap_or(false);
    let subtree = !has_ext;
    ui(ctx).set_search_text(ss(path));
    run_search(ctx, path, subtree);
}

pub fn run_search(ctx: &Shared, query: &str, subtree: bool) {
    let query = query.trim().to_string();
    if query.is_empty() {
        return;
    }
    ctx.settings.borrow_mut().push_history(&query);
    save_settings(ctx);
    super::sync_history(ctx);
    let token = {
        let mut st = ctx.st.borrow_mut();
        st.finder.query = query.clone();
        st.finder.subtree = subtree;
        st.finder.pending += 1;
        st.finder.all.clear();
        st.finder.shown.clear();
        st.finder.sel = -1;
        st.finder.pending
    };
    let u = ui(ctx);
    u.set_finder_query(ss(&query));
    u.set_finder_subtree(subtree);
    u.set_finder_foot(ss("Searching every process…"));
    u.set_finder_open(true);
    u.set_finder_loading(true);
    u.set_finder_rows(model(Vec::<Row>::new()));
    u.set_finder_chips(model(Vec::<crate::Chip>::new()));
    render_head(ctx);
    super::focus_keys(ctx);
    let q = query.clone();
    spawn(ctx, move |app| api::search(app, &q, subtree), move |ctx, res: SearchResult| {
        if ctx.st.borrow().finder.pending != token {
            return;
        }
        ui(ctx).set_finder_loading(false);
        let procs: std::collections::HashSet<u32> = res.rows.iter().map(|r| r.pid).collect();
        let foot = if res.rows.is_empty() {
            "Nothing has that open. Try a shorter fragment, or tick the folder option to match everything beneath a folder.".to_string()
        } else {
            let writers: std::collections::HashSet<u32> = res.rows.iter().filter(|r| writes(&r.access_text)).map(|r| r.pid).collect();
            let mut note = format!(
                "{} in {}{}  ·  right-click a row for actions, double-click to jump to the process",
                plural(res.rows.len(), "handle", "handles"),
                plural(procs.len(), "process", "processes"),
                if writers.is_empty() { String::new() } else { format!(", {} with write access", writers.len()) }
            );
            if res.truncated {
                note.push_str(&format!("  ·  only the first {} matches are shown, narrow the search for the rest", keyhole::objects::SEARCH_LIMIT));
            }
            if res.stats.pending > 0 {
                note.push_str(&format!("  ·  {} not reached in time, search again for more", plural(res.stats.pending as usize, "object was", "objects were")));
            }
            if res.stats.threads_abandoned > 0 {
                note.push_str(&if res.stats.threads_abandoned == 1 { "  ·  1 object skipped because it would not answer".to_string() } else { format!("  ·  {} objects skipped because they would not answer", res.stats.threads_abandoned) });
            }
            note
        };
        {
            let mut st = ctx.st.borrow_mut();
            st.finder.sel = if res.rows.is_empty() { -1 } else { 0 };
            st.finder.chip.clear();
            st.finder.all = res.rows;
            st.finder.foot = foot.clone();
        }
        ui(ctx).set_finder_foot(ss(&foot));
        render_rows(ctx, true);
    });
}

fn chip_match(chip: &str, r: &HandleRow) -> bool {
    match chip {
        "write" => writes(&r.access_text),
        "files" => r.type_name == "File",
        "keys" => r.type_name == "Key",
        _ => true,
    }
}

fn render_rows(ctx: &Shared, reset: bool) {
    let (rows, chips, current, sel) = {
        let mut st = ctx.st.borrow_mut();
        let all = std::mem::take(&mut st.finder.all);
        let chip_id = st.finder.chip.clone();
        let sort = st.finder.sort.clone();
        let mut shown: Vec<usize> = (0..all.len()).filter(|&i| chip_match(&chip_id, &all[i])).collect();
        sort_indices(&all, &mut shown, &sort.0, sort.1, |r, k| match k {
            "process" => sv_s(&r.process),
            "pid" => sv_n(r.pid as f64),
            "type_name" => sv_s(&r.type_name),
            "handle" => sv_n(r.handle as f64),
            "display" => sv_s(&r.display),
            "access_text" => sv_s(&r.access_text),
            _ => sv_s(""),
        });
        if st.finder.sel >= shown.len() as i32 {
            st.finder.sel = if shown.is_empty() { -1 } else { 0 };
        }
        let sel = st.finder.sel;
        let chips = if all.is_empty() {
            Vec::new()
        } else {
            vec![
                chip("", "All", Some(all.len()), "Every handle that matched"),
                chip("write", "Can write", Some(all.iter().filter(|r| writes(&r.access_text)).count()), "Handles opened with write or delete access: the ones that block edits, moves and deletes"),
                chip("files", "Files", Some(all.iter().filter(|r| r.type_name == "File").count()), "File and folder handles only"),
                chip("keys", "Registry keys", Some(all.iter().filter(|r| r.type_name == "Key").count()), "Registry key handles only"),
            ]
        };
        let rows: Vec<Row> = shown
            .iter()
            .enumerate()
            .map(|(pos, &i)| {
                let r = &all[i];
                let mut row = simple_row(
                    i as i32,
                    vec![
                        cell(&r.process, 0),
                        num(&r.pid.to_string()),
                        cell(&r.type_name, 0),
                        hexc(&hex(r.handle, 4)),
                        cell(&r.display, 0),
                        cell(&r.access_text, if writes(&r.access_text) { 3 } else { 1 }),
                    ],
                    0,
                    &r.display,
                );
                row.selected = pos as i32 == sel;
                row
            })
            .collect();
        st.finder.all = all;
        st.finder.shown = shown;
        (rows, chips, chip_id, sel)
    };
    let u = ui(ctx);
    let (chips, chips2) = super::split_chips(ctx, chips, 0.0);
    u.set_finder_chips(model(chips));
    u.set_finder_chips_more(chips2);
    u.set_finder_chip(ss(&current));
    u.set_finder_rows(model(rows));
    if reset {
        u.set_finder_scroll_index(0);
        u.set_finder_scroll_seq(u.get_finder_scroll_seq() + 1);
    } else if sel >= 0 {
        u.set_finder_scroll_index(sel);
        u.set_finder_scroll_seq(u.get_finder_scroll_seq() + 1);
    }
}

pub fn on_key(ctx: &Shared, key: char) -> bool {
    use slint::platform::Key;
    let len = ctx.st.borrow().finder.shown.len() as i32;
    if len == 0 {
        return false;
    }
    if key == char::from(Key::DownArrow) || key == char::from(Key::UpArrow) {
        {
            let mut st = ctx.st.borrow_mut();
            let delta = if key == char::from(Key::DownArrow) { 1 } else { -1 };
            st.finder.sel = (st.finder.sel + delta).clamp(0, len - 1);
        }
        render_rows(ctx, false);
        return true;
    }
    if key == char::from(Key::Return) {
        let sel = ctx.st.borrow().finder.sel;
        if sel >= 0
            && let Some(r) = shown_row(ctx, sel as usize) {
                close(ctx);
                super::tree::select_pid(ctx, r.pid);
            }
        return true;
    }
    false
}

pub fn csv_rows(ctx: &Shared) -> Vec<Vec<String>> {
    let st = ctx.st.borrow();
    st.finder.shown.iter().map(|&i| { let r = &st.finder.all[i]; vec![r.process.clone(), r.pid.to_string(), r.type_name.clone(), hex(r.handle, 0), r.display.clone(), r.access_text.clone()] }).collect()
}
