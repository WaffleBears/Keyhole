use super::format::*;
use super::menus::{self, MenuItem};
use super::simple_action;
use super::{Shared, bad, copy_text, dialogs, finder, good, lists, model, spawn, ss, ui};
use crate::{BoardRow, Metric};
use keyhole::api::{self, Action};
use keyhole::etw::ActivitySnapshot;
use keyhole::model::{ActivityRow, ActivityTotals, LifeState};
use slint::SharedString;
use std::sync::Arc;

#[derive(Default)]
pub struct ActivityState {
    pub busy: bool,
    pub layer: String,
    pub snapshot: Option<Arc<ActivitySnapshot>>,
    pub board: Vec<BoardSrc>,
    pub board2: Vec<BoardSrc>,
    pub token: u64,
}

#[derive(Clone, Default)]
pub struct BoardSrc {
    pub pid: u32,
    pub path: String,
    pub label: String,
}

pub fn wire(ctx: &Shared) {
    let u = ui(ctx);
    {
        let ctx = ctx.clone();
        u.on_layer_changed(move |l| {
            ctx.st.borrow_mut().activity.layer = l.to_string();
            ui(&ctx).set_layer(l);
            refresh_activity(&ctx);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_bar_link_clicked(move || toggle_tracing(&ctx));
    }
    {
        let ctx = ctx.clone();
        u.on_board_clicked(move |which, i| {
            let mode = ctx.st.borrow().mode.clone();
            if mode != "network" || which != "procs" {
                return;
            }
            let active = ctx.st.borrow().activity.snapshot.as_ref().map(|s| s.active && !s.net_procs.is_empty()).unwrap_or(false);
            if active {
                return;
            }
            let label = ctx.st.borrow().activity.board2.get(i as usize).map(|b| b.label.clone()).unwrap_or_default();
            let current = ctx.st.borrow().lists.filter.get("network").cloned().unwrap_or_default();
            let next = if current == label { String::new() } else { label };
            ctx.st.borrow_mut().lists.filter.insert("network".into(), next.clone());
            ui(&ctx).set_list_filter(ss(&next));
            refresh_network(&ctx);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_board_double(move |which, i| {
            let pid = board_src(&ctx, which.as_str(), i as usize).map(|b| b.pid).unwrap_or(0);
            if pid > 0 {
                super::tree::select_pid(&ctx, pid);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_board_right(move |which, i, x, y| {
            if let Some(b) = board_src(&ctx, which.as_str(), i as usize) {
                board_menu(&ctx, x, y, &b);
            }
        });
    }
}

fn board_src(ctx: &Shared, which: &str, i: usize) -> Option<BoardSrc> {
    let st = ctx.st.borrow();
    if which == "files" { st.activity.board.get(i).cloned() } else { st.activity.board2.get(i).cloned() }
}

fn board_menu(ctx: &Shared, x: f32, y: f32, b: &BoardSrc) {
    let pid = b.pid;
    let path = b.path.clone();
    let is_file = is_file_path(&path);
    let proc = if pid > 0 { super::tree::row_of(ctx, pid) } else { None };
    let items = vec![
        MenuItem::new("sel", "Go to process", move |ctx| super::tree::select_pid(ctx, pid)).disabled(pid == 0),
        MenuItem::new("copyName", "Copy process name", { let n = proc.as_ref().map(|p| p.name.clone()).unwrap_or_default(); move |ctx| copy_text(ctx, &n) }).disabled(proc.is_none()),
        MenuItem::new("copyPath", "Copy path", { let p = path.clone(); move |ctx| copy_text(ctx, &p) }).disabled(path.is_empty()),
        MenuItem::sep(),
        MenuItem::new("reveal", "Show in Explorer", { let p = path.clone(); move |ctx| simple_action(ctx, Action::Reveal(p), "Revealed", None) }).disabled(!is_file),
        MenuItem::new("whoelse", "Find what else has this open", { let p = path.clone(); move |ctx| finder::find_open(ctx, &p, false) }).disabled(!is_file),
        MenuItem::sep(),
        MenuItem::new("kill", "Terminate process", { let p = proc.clone(); move |ctx| if let Some(p) = &p { super::tree::confirm_kill(ctx, p) } }).danger().disabled(proc.is_none()),
    ];
    menus::show(ctx, x, y, &b.label, items);
}

pub fn toggle_tracing(ctx: &Shared) {
    let active = ctx.app.activity.is_running();
    if active {
        dialogs::confirm(
            ctx,
            "Stop kernel tracing?",
            "The Disk view loses per file activity and the Network view loses live throughput until you start it again from the status bar.",
            "Stop tracing",
            true,
            Box::new(|ctx| {
                spawn(ctx, api::stop_activity, |ctx, _| {
                    good(ctx, "Tracing stopped");
                    after_tracing_change(ctx);
                });
            }),
        );
        return;
    }
    spawn(ctx, api::start_activity, |ctx, r| match r {
        Ok(()) => {
            good(ctx, "Tracing started");
            after_tracing_change(ctx);
        }
        Err(e) => bad(ctx, &e),
    });
}

fn after_tracing_change(ctx: &Shared) {
    super::tree::apply_tree(ctx, api::tree(&ctx.app));
    let mode = ctx.st.borrow().mode.clone();
    match mode.as_str() {
        "activity" => refresh_activity(ctx),
        "network" => refresh_network(ctx),
        _ => {}
    }
}

fn metric(label: &str, value: String, tone: i32) -> Metric {
    Metric { label: ss(label), value: ss(&value), tone }
}

const TIMELINE_SLOTS: usize = 90;

fn timeline(ctx: &Shared, totals: &ActivityTotals) {
    let max = totals.history_read.iter().chain(totals.history_write.iter()).copied().max().unwrap_or(1).max(1) as f32;
    let norm = |v: &Vec<u64>| -> Vec<f32> {
        let tail: Vec<f32> = v.iter().rev().take(TIMELINE_SLOTS).rev().map(|x| *x as f32 / max).collect();
        let mut out = vec![0.0f32; TIMELINE_SLOTS - tail.len()];
        out.extend(tail);
        out
    };
    let u = ui(ctx);
    let (rp, rf) = chart_paths(&norm(&totals.history_read));
    let (wp, wf) = chart_paths(&norm(&totals.history_write));
    u.set_tl_read_path(ss(&rp));
    u.set_tl_read_fill(ss(&rf));
    u.set_tl_write_path(ss(&wp));
    u.set_tl_write_fill(ss(&wf));
    u.set_tl_scale(ss(&format!("peak {}/s", bytes(max as u64))));
}

fn board_rows(rows: &[ActivityRow], what: &str, disk: bool) -> (Vec<BoardRow>, Vec<BoardSrc>) {
    let mut out = Vec::new();
    let mut src = Vec::new();
    for (i, r) in rows.iter().take(120).enumerate() {
        let (spark, spark_fill) = chart_paths(&normalized(&r.spark, 1));
        let tip = format!(
            "{}\n{}{}\nLast 6 seconds: {} {} · {} {} · {} operations{}",
            r.label,
            r.detail,
            if r.who.is_empty() { String::new() } else { format!("\nUsed by {}", r.who) },
            if what == "net" { "received" } else { "read" },
            bytes_or_zero(r.read_bytes),
            if what == "net" { "sent" } else { "written" },
            bytes_or_zero(r.write_bytes),
            r.ops,
            if r.pid > 0 { "\nDouble-click to jump to the process" } else { "" }
        );
        out.push(BoardRow {
            rank: ss(&(i + 1).to_string()),
            pid: r.pid as i32,
            path: ss(&r.detail),
            label: ss(&r.label),
            who: ss(&r.who),
            sub: ss(&r.detail),
            read: ss(&if r.read_bytes > 0 { bytes(r.read_bytes) } else { "-".into() }),
            write: ss(&if r.write_bytes > 0 { bytes(r.write_bytes) } else { "-".into() }),
            total: SharedString::default(),
            spark: ss(&spark),
            spark_fill: ss(&spark_fill),
            tip: ss(&tip),
            on: false,
        });
        src.push(BoardSrc { pid: r.pid, path: if disk || !is_file_path(&r.detail) { String::new() } else { r.detail.clone() }, label: r.label.clone() });
    }
    (out, src)
}

pub fn enter_activity(ctx: &Shared) {
    let layer = ctx.st.borrow().activity.layer.clone();
    let layer = if layer.is_empty() { "file".to_string() } else { layer };
    ctx.st.borrow_mut().activity.layer = layer.clone();
    let u = ui(ctx);
    u.set_layer(ss(&layer));
    u.set_board_read_label(ss("Read"));
    u.set_board_write_label(ss("Write"));
    u.set_board2_visible(true);
    refresh_activity(ctx);
}

pub fn refresh_activity(ctx: &Shared) {
    let token = {
        let mut st = ctx.st.borrow_mut();
        if st.activity.busy {
            return;
        }
        st.activity.busy = true;
        st.activity.token += 1;
        st.activity.token
    };
    spawn(ctx, |app| (api::activity(app), api::tree(app)), move |ctx, (a, tree)| {
        ctx.st.borrow_mut().activity.busy = false;
        if ctx.st.borrow().mode != "activity" || ctx.st.borrow().activity.token != token {
            return;
        }
        let disk = ctx.st.borrow().activity.layer == "disk";
        ctx.st.borrow_mut().activity.snapshot = Some(a.clone());
        let u = ui(ctx);
        let etw_note = tree.stats.etw_note.clone();
        u.set_show_layer(a.active);
        u.set_show_timeline(a.active);
        u.set_tl_read_label(ss("read"));
        u.set_tl_write_label(ss("write"));
        u.set_tl_tip(ss("Read (blue) and write (amber) throughput over the last 90 seconds"));
        u.set_board_spark(a.active);
        if !a.active {
            let why = if etw_note.is_empty() { "Kernel tracing is off, so per file activity is unavailable.".to_string() } else { format!("Kernel tracing is off: {}.", etw_note) };
            u.set_bar_metrics(model(Vec::<Metric>::new()));
            u.set_bar_text(ss("Tracing off."));
            u.set_bar_text_tone(3);
            u.set_bar_text2(ss(&why));
            u.set_bar_link(ss("Start tracing"));
            u.set_board2_visible(false);
            u.set_board2_title(ss("Busiest processes"));
            u.set_board2_hint(ss("by I/O counters"));
            u.set_board_total_label(ss("Total"));
            let mut busy: Vec<&keyhole::model::ProcessRow> = tree.rows.iter().filter(|r| r.state != LifeState::Dead && r.read_rate + r.write_rate >= 1024).collect();
            busy.sort_by(|a, b| (b.read_rate + b.write_rate).cmp(&(a.read_rate + a.write_rate)));
            let rows: Vec<BoardRow> = busy
                .iter()
                .take(120)
                .enumerate()
                .map(|(i, r)| BoardRow {
                    rank: ss(&(i + 1).to_string()),
                    pid: r.pid as i32,
                    path: ss(&r.image_path),
                    label: ss(&r.name),
                    who: SharedString::default(),
                    sub: ss(&if r.image_path.is_empty() { format!("pid {}", r.pid) } else { r.image_path.clone() }),
                    read: ss(&if r.read_rate >= 1024 { rate(r.read_rate) } else { "-".into() }),
                    write: ss(&if r.write_rate >= 1024 { rate(r.write_rate) } else { "-".into() }),
                    total: ss(&format!("{}/s", bytes(r.read_rate + r.write_rate))),
                    spark: SharedString::default(),
                    spark_fill: SharedString::default(),
                    tip: ss(&format!("{}\npid {}\nReading {} · Writing {}\nDouble-click to jump to the process", r.name, r.pid, rate_or_zero(r.read_rate), rate_or_zero(r.write_rate))),
                    on: false,
                })
                .collect();
            let src: Vec<BoardSrc> = busy.iter().take(120).map(|r| BoardSrc { pid: r.pid, path: r.image_path.clone(), label: r.name.clone() }).collect();
            u.set_board2_rows(model(rows));
            u.set_board2_empty(ss("No process is reading or writing right now."));
            u.set_board2_empty_sub(ss("Per process rates come from Windows I/O counters. Start tracing for per file detail."));
            {
                let mut st = ctx.st.borrow_mut();
                st.activity.board.clear();
                st.activity.board2 = src;
            }
            return;
        }
        u.set_board2_visible(true);
        let (rows, procs, totals) = api::totals_of(&a, disk);
        u.set_bar_metrics(model(vec![metric("Read", rate_or_zero(totals.read_rate), 5), metric("Write", rate_or_zero(totals.write_rate), 3), metric("Operations", format!("{}/s", thousands(totals.ops_rate)), 0)]));
        u.set_bar_text(ss(&format!("{} I/O events seen{}", thousands(totals.events_seen), if totals.events_dropped > 0 { format!("  ·  {} dropped", thousands(totals.events_dropped)) } else { String::new() })));
        u.set_bar_text_tone(1);
        u.set_bar_text2(SharedString::default());
        u.set_bar_link(SharedString::default());
        u.set_board_title(ss(if disk { "Disks" } else { "Busiest files" }));
        u.set_board_hint(ss(if disk { "physical disks: bytes transferred and average response time per request" } else { "what programs asked for, including reads served from cache. The cache manager's own flushes and paging are left out" }));
        u.set_board2_title(ss("Busiest processes"));
        u.set_board2_hint(ss(if disk { "whose I/O reached a disk" } else { "by file I/O" }));
        u.set_board_total_label(SharedString::default());
        let (b1, s1) = board_rows(rows, "disk", disk);
        let (b2, s2) = board_rows(procs, "disk", true);
        u.set_board_rows(model(b1));
        u.set_board_empty(ss(if disk { "No disk transfers in the last few seconds." } else { "No file activity in the last few seconds." }));
        u.set_board_empty_sub(SharedString::default());
        u.set_board2_rows(model(b2));
        u.set_board2_empty(ss("Nothing is moving data right now."));
        u.set_board2_empty_sub(SharedString::default());
        timeline(ctx, totals);
        let mut st = ctx.st.borrow_mut();
        st.activity.board = s1;
        st.activity.board2 = s2;
    });
}

pub fn enter_network(ctx: &Shared) {
    lists::setup(ctx, "network");
    let u = ui(ctx);
    u.set_show_layer(false);
    u.set_board_read_label(ss("Received"));
    u.set_board_write_label(ss("Sent"));
    refresh_network(ctx);
}

pub fn refresh_network(ctx: &Shared) {
    let token = {
        let mut st = ctx.st.borrow_mut();
        if st.activity.busy {
            return;
        }
        st.activity.busy = true;
        st.activity.token += 1;
        st.activity.token
    };
    let (resolve, filter) = {
        let st = ctx.st.borrow();
        (st.lists.net_resolve, st.lists.filter.get("network").cloned().unwrap_or_default())
    };
    spawn(ctx, move |app| (api::activity(app), api::connections(app, resolve, &filter)), move |ctx, (a, conn)| {
        ctx.st.borrow_mut().activity.busy = false;
        if ctx.st.borrow().mode != "network" || ctx.st.borrow().activity.token != token {
            return;
        }
        ctx.st.borrow_mut().activity.snapshot = Some(a.clone());
        let u = ui(ctx);
        let totals = &a.totals_net;
        u.set_show_timeline(a.active);
        u.set_tl_tip(ss("Received (blue) and sent (amber) throughput over the last 90 seconds"));
        if a.active {
            u.set_bar_metrics(model(vec![metric("Received", rate_or_zero(totals.read_rate), 5), metric("Sent", rate_or_zero(totals.write_rate), 3)]));
            u.set_bar_text(ss(&format!("{} network events seen", thousands(totals.events_seen))));
            u.set_bar_text_tone(1);
            timeline(ctx, totals);
        } else {
            u.set_bar_metrics(model(Vec::<Metric>::new()));
            u.set_bar_text(ss("Throughput not available."));
            u.set_bar_text_tone(3);
        }
        u.set_bar_text2(ss(&format!("{} endpoints  ·  {} established  ·  {} listening{}", conn.rows.len(), conn.established, conn.listening, if a.active { "" } else { "  ·  kernel tracing could not be started" })));
        u.set_bar_link(ss(if a.active { "" } else { "Start tracing" }));
        let current_filter = ctx.st.borrow().lists.filter.get("network").cloned().unwrap_or_default();
        if a.active && !a.net_procs.is_empty() {
            u.set_board2_title(ss("Busiest processes"));
            u.set_board2_hint(ss("by network throughput"));
            u.set_board_spark(true);
            u.set_board_total_label(SharedString::default());
            let (rows, src) = board_rows(&a.net_procs, "net", true);
            u.set_board2_rows(model(rows));
            ctx.st.borrow_mut().activity.board2 = src;
        } else {
            u.set_board2_title(ss("Processes with connections"));
            u.set_board2_hint(ss(if a.active { "no traffic right now, showing open endpoints" } else { "by open endpoints" }));
            u.set_board_spark(false);
            u.set_board_total_label(ss("Endpoints"));
            let mut map: std::collections::HashMap<u32, (String, usize, usize, usize, std::collections::HashSet<String>)> = std::collections::HashMap::new();
            for r in &conn.rows {
                let e = map.entry(r.pid).or_insert_with(|| (r.process.clone(), 0, 0, 0, std::collections::HashSet::new()));
                e.1 += 1;
                if r.state == "ESTABLISHED" {
                    e.2 += 1;
                    if !r.remote.is_empty() {
                        e.4.insert(r.remote.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or(r.remote.clone()));
                    }
                }
                if r.state == "LISTEN" {
                    e.3 += 1;
                }
            }
            let mut entries: Vec<(u32, String, usize, usize, usize, usize)> = map.into_iter().map(|(pid, e)| (pid, e.0, e.1, e.2, e.3, e.4.len())).collect();
            entries.sort_by(|a, b| b.3.cmp(&a.3).then(b.2.cmp(&a.2)).then(a.1.to_lowercase().cmp(&b.1.to_lowercase())));
            let rows: Vec<BoardRow> = entries
                .iter()
                .take(200)
                .enumerate()
                .map(|(i, (pid, label, total, est, lis, remotes))| {
                    let sub = format!("{} established  ·  {} listening  ·  {} remote host{}", est, lis, remotes, if *remotes == 1 { "" } else { "s" });
                    BoardRow {
                        rank: ss(&(i + 1).to_string()),
                        pid: *pid as i32,
                        path: SharedString::default(),
                        label: ss(label),
                        who: SharedString::default(),
                        sub: ss(&format!("pid {}  ·  {}", pid, sub)),
                        read: SharedString::default(),
                        write: SharedString::default(),
                        total: ss(&total.to_string()),
                        spark: SharedString::default(),
                        spark_fill: SharedString::default(),
                        tip: ss(&format!("{}\n{}\nClick to show only this process, double-click to jump to it", label, sub)),
                        on: !current_filter.is_empty() && current_filter == *label,
                    }
                })
                .collect();
            u.set_board2_rows(model(rows));
            ctx.st.borrow_mut().activity.board2 = entries.iter().take(200).map(|(pid, label, ..)| BoardSrc { pid: *pid, path: String::new(), label: label.clone() }).collect();
        }
        u.set_board2_empty(ss("No process has a network endpoint open."));
        u.set_board2_empty_sub(SharedString::default());
        lists::set_connections(ctx, conn);
    });
}

pub fn activity_csv(ctx: &Shared) -> Option<(String, String)> {
    let st = ctx.st.borrow();
    let snap = st.activity.snapshot.as_ref()?;
    let disk = st.activity.layer == "disk";
    let rows = if disk { &snap.disk_rows } else { &snap.file_rows };
    let table: Vec<Vec<String>> = rows.iter().map(|r| vec![if disk { format!("{}  {}", r.label, r.detail) } else { r.detail.clone() }, if r.pid > 0 { r.pid.to_string() } else { String::new() }, r.read_bytes.to_string(), r.write_bytes.to_string(), r.ops.to_string()]).collect();
    Some((format!("keyhole-activity-{}", if disk { "disk" } else { "file" }), csv(&table, &[if disk { "Disk" } else { "File" }, "PID", "Read bytes", "Write bytes", "Operations"])))
}
