use super::{Kind, RenderInput, Rendered};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{self, ListData, ListState};
use crate::gui::dialogs;
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, dot_cell, num, simple_row, sort_indices, sv_b, sv_n, sv_s};
use crate::gui::simple_action;
use crate::gui::{Shared, bad, chip, copy_text, good, model, spawn, ss, ui};
use crate::Chip;
use keyhole::api::{self, Action};
use keyhole::state::App;
use keyhole::sys::updates::{PendingRow, UpdateRow};

pub const INSTALLED_COLUMNS: &[ColDef] = &[
    c("time", "Time", 110.0, true, "When Windows Update reported the result. Hover for the exact time."),
    c("result", "Result", 170.0, false, "Succeeded, Succeeded with errors, Failed, Aborted or still in progress. Click to sort."),
    c("title", "Update", 520.0, false, "The update's title as Windows Update names it."),
    c("kb", "KB", 130.0, false, "Knowledge Base article numbers mentioned in the title. Click to sort."),
    c("operation", "Operation", 120.0, false, "Installation or uninstallation."),
];

pub const PENDING_COLUMNS: &[ColDef] = &[
    c("title", "Update", 480.0, false, "An update the source offers that is not installed here."),
    c("kb", "KB", 130.0, false, "Knowledge Base article numbers."),
    c("severity", "Severity", 110.0, false, "Microsoft's security severity rating, when it has one."),
    c("downloaded", "Downloaded", 100.0, false, "Whether the payload is already on disk."),
    c("reboot", "Reboot", 110.0, false, "Whether installing it needs a restart. Never means no restart, Always means one is required, Can request means the installer decides at install time."),
    c("size", "Size", 90.0, true, "Maximum download size."),
];

pub const REBOOT_COLUMNS: &[ColDef] = &[
    c("source", "Reason", 200.0, false, "What is asking for the restart."),
    c("detail", "Detail", 700.0, false, "Where the pending state was found."),
];

pub static KIND: Kind = Kind {
    name: "updates",
    title: "Windows Update",
    placeholder: ("Filter by title, KB or result", "Show only rows whose title, KB or result contains this text. Prefixes: kb:5001234  result:failed"),
    columns,
    table,
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
    toggle: super::no_toggle,
    toggled: super::no_toggled,
    after_load: super::no_after_load,
};

fn current(st: &ListState) -> &str {
    match st.segment.get("updates").map(|s| s.as_str()) {
        Some("pending") => "pending",
        Some("reboot") => "reboot",
        _ => "installed",
    }
}

fn columns(st: &ListState) -> &'static [ColDef] {
    match current(st) {
        "pending" => PENDING_COLUMNS,
        "reboot" => REBOOT_COLUMNS,
        _ => INSTALLED_COLUMNS,
    }
}

fn table(st: &ListState) -> String {
    format!("updates.{}", current(st))
}

fn segment(st: &ListState) -> String {
    current(st).to_string()
}

fn default_sort(st: &ListState) -> (&'static str, bool) {
    match current(st) {
        "pending" => ("title", false),
        "reboot" => ("source", false),
        _ => ("time", true),
    }
}

fn buttons(st: &ListState) -> Vec<Chip> {
    let pending = match &st.updates_pending { Some(Ok(rows)) => rows.len(), _ => 0 };
    let mut out = vec![chip("check", "Check for pending updates", None, "Ask Windows Update or WSUS what is not installed here. The source must be reachable and it can take a while.")];
    if pending > 0 {
        out.push(chip("installall", &format!("Install {}…", plural(pending, "pending update", "pending updates")), None, "Download and install every pending update now through the Windows Update Agent, without restarting"));
    }
    out.push(chip("settings", "Windows Update", None, "Open the Windows Update settings page"));
    out
}

fn refresh_buttons(ctx: &Shared) {
    let buttons = buttons(&ctx.st.borrow().lists);
    ui(ctx).set_list_buttons(model(buttons));
}

fn run_check(ctx: &Shared, quiet: bool, then_reload: bool) {
    let source = match &ctx.st.borrow().lists.data { ListData::Updates(d) => d.source.clone(), _ => String::new() };
    ui(ctx).set_list_loading(true);
    switch(ctx, "pending");
    if !quiet {
        good(ctx, &format!("Checking {} for pending updates, this can take a while", source));
    }
    spawn(ctx, move |_| api::updates_pending(), move |ctx, res| {
        let n = res.as_ref().map(|r| r.len()).unwrap_or(0);
        let err = res.as_ref().err().cloned();
        let showing = {
            let mut st = ctx.st.borrow_mut();
            st.lists.updates_pending = Some(res.clone());
            if let ListData::Updates(d) = &mut st.lists.data {
                d.pending = Some(res);
            }
            st.lists.kind == "updates"
        };
        if !ctx.st.borrow().lists.inflight {
            ui(ctx).set_list_loading(false);
        }
        if showing {
            refresh_buttons(ctx);
            lists::render(ctx);
            if then_reload {
                lists::refresh_current(ctx, false);
            }
        }
        match err {
            Some(e) => bad(ctx, &e),
            None if quiet => {}
            None => good(ctx, &format!("{} pending", plural(n, "update", "updates"))),
        }
    });
}

fn install(ctx: &Shared, ids: Vec<(String, i32)>, what: String) {
    if ctx.st.borrow().lists.updates_installing {
        bad(ctx, "An installation is already running. Wait for it to finish");
        return;
    }
    let n = ids.len();
    dialogs::confirm(
        ctx,
        &format!("Install {}?", what),
        &format!("Keyhole downloads and installs {} now through the Windows Update Agent and accepts Microsoft's license terms for {}. This can take a long time and nothing else can install meanwhile. The machine is not restarted, but a restart may be needed afterwards.", what, if n == 1 { "it" } else { "them" }),
        "Install",
        true,
        Box::new(move |ctx| {
            ctx.st.borrow_mut().lists.updates_installing = true;
            if ctx.st.borrow().lists.kind == "updates" {
                ui(ctx).set_list_loading(true);
            }
            good(ctx, &format!("Installing {}. This can take a while", what));
            spawn(ctx, move |_| api::install_updates(&ids), move |ctx, res| {
                ctx.st.borrow_mut().lists.updates_installing = false;
                let showing = ctx.st.borrow().lists.kind == "updates";
                if showing {
                    ui(ctx).set_list_loading(false);
                }
                match res {
                    Ok(report) => {
                        let mut body = report.text();
                        if !report.failed.is_empty() {
                            body.push_str(".\n");
                            for (t, e) in report.failed.iter().take(6) {
                                body.push_str(&format!("\n{}: {}", t, e));
                            }
                            if report.failed.len() > 6 {
                                body.push_str(&format!("\n{} more failed", report.failed.len() - 6));
                            }
                        }
                        if report.reboot {
                            body.push_str("\n\nThe Reboot tab shows why once the list reloads. Restart the machine when convenient.");
                        }
                        dialogs::confirm(ctx, "Update results", &body, "OK", false, Box::new(|_| {}));
                        ctx.st.borrow_mut().lists.updates_pending = None;
                        if showing {
                            run_check(ctx, true, true);
                        }
                    }
                    Err(e) => bad(ctx, &format!("Nothing was installed. {}", e)),
                }
            });
        }),
    );
}

fn segments(_st: &ListState) -> Vec<Chip> {
    vec![
        chip("installed", "Installed", None, "What Windows Update installed or removed, newest first"),
        chip("pending", "Pending", None, "What the update source offers that is not installed, after a check"),
        chip("reboot", "Reboot", None, "Why a restart is pending, if one is"),
    ]
}

pub fn switch(ctx: &Shared, id: &str) {
    {
        let mut st = ctx.st.borrow_mut();
        st.lists.segment.insert("updates".into(), id.to_string());
        st.lists.chip.insert("updates".into(), String::new());
        st.lists.sel = None;
    }
    ui(ctx).set_list_segment(ss(id));
    lists::set_cols(ctx, "updates");
    lists::render(ctx);
}

fn segment_picked(ctx: &Shared, id: &str) {
    switch(ctx, id);
}

fn refresh(_app: &App, st: &ListState) -> ListData {
    let mut data = api::updates();
    data.pending = st.updates_pending.clone();
    ListData::Updates(data)
}

fn result_tone(r: &UpdateRow) -> i32 {
    if r.result == "Succeeded" {
        2
    } else if r.result == "Succeeded with errors" || r.result == "In progress" || r.result == "Not started" {
        3
    } else if r.ok {
        1
    } else {
        4
    }
}

fn render(_ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Updates(d) = data else { return Rendered::default() };
    let terms = filter_terms(&input.filter);
    let seg = if input.table.ends_with("pending") { "pending" } else if input.table.ends_with("reboot") { "reboot" } else { "installed" };
    let mut out = Rendered::default();
    let now = crate::gui::rows::now_ms();
    let mut head = format!(
        "{} installed{}  ·  {}  ·  {}",
        d.history.iter().filter(|r| r.ok && r.operation == "Installation").count(),
        if d.last_install_ms > 0 { format!(", last {} ago", fmt_age((now - d.last_install_ms).max(0))) } else { String::new() },
        d.source,
        if d.reboot.is_empty() { "no reboot pending".to_string() } else { format!("reboot pending ({})", plural(d.reboot.len(), "reason", "reasons")) }
    );
    if let Some(e) = &d.error {
        head.push_str(&format!("  ·  {}", e));
    }
    if let Some(n) = &d.policy_note {
        head.push_str(&format!("  ·  {}", n));
    }
    match seg {
        "pending" => {
            let rows: &[PendingRow] = match &d.pending {
                Some(Ok(rows)) => rows,
                _ => &[],
            };
            let chip_ok = |p: &PendingRow| match input.chip.as_str() {
                "important" => p.severity == "Critical" || p.severity == "Important",
                "downloaded" => p.downloaded,
                _ => true,
            };
            out.chips = vec![
                chip("", "All", Some(rows.len()), "Every pending update"),
                chip("important", "Critical or Important", Some(rows.iter().filter(|p| p.severity == "Critical" || p.severity == "Important").count()), "Security updates Microsoft rates Critical or Important"),
                chip("downloaded", "Downloaded", Some(rows.iter().filter(|p| p.downloaded).count()), "Payload already on disk, ready to install"),
            ];
            out.shown = (0..rows.len()).filter(|&i| { let p = &rows[i]; chip_ok(p) && (terms.is_empty() || term_matches(&terms, |k| match k { "kb" => Some(p.kb.clone()), _ => None }, &format!("{} {} {} {}", p.title, p.kb, p.severity, p.description))) }).collect();
            sort_indices(rows, &mut out.shown, &input.sort.0, input.sort.1, |p, k| match k {
                "title" => sv_s(&p.title),
                "kb" => sv_s(&p.kb),
                "severity" => sv_s(&p.severity),
                "downloaded" => sv_b(p.downloaded),
                "reboot" => sv_s(&p.reboot),
                "size" => sv_n(p.size as f64),
                _ => sv_s(""),
            });
            out.rows = out.shown.iter().map(|&i| { let p = &rows[i]; simple_row(i as i32, vec![cell(&p.title, 0), cell(&p.kb, 0), cell(&p.severity, if p.severity == "Critical" { 4 } else if p.severity == "Important" { 3 } else { 0 }), cell(if p.downloaded { "yes" } else { "" }, 0), cell(&p.reboot, 0), num(&if p.size > 0 { bytes(p.size) } else { String::new() })], 0, &format!("{}\n{}", p.title, p.description)) }).collect();
            out.empty = match &d.pending {
                None => ("\u{E777}".into(), "Not checked yet.".into(), format!("Click \"Check for pending updates\" to ask {}. It can take a minute or more and needs that source to be reachable.{}{}", d.source, if d.wsus { " Only updates the WSUS administrator approved for this machine appear, exactly what Windows would install." } else { "" }, if d.last_search_ms > 0 { format!(" Windows itself last checked {} ago.", fmt_age((now - d.last_search_ms).max(0))) } else { String::new() })),
                Some(Err(e)) => ("\u{E777}".into(), "The check did not complete.".into(), e.clone()),
                Some(Ok(_)) if input.filter.is_empty() && input.chip.is_empty() => ("\u{E777}".into(), "Nothing pending: this server is up to date as far as the source knows.".into(), String::new()),
                Some(Ok(_)) => ("\u{E777}".into(), lists::nothing_matches(&input.filter), String::new()),
            };
        }
        "reboot" => {
            out.shown = (0..d.reboot.len()).filter(|&i| { let r = &d.reboot[i]; terms.is_empty() || term_matches(&terms, |_| None, &format!("{} {}", r.source, r.detail)) }).collect();
            sort_indices(&d.reboot, &mut out.shown, &input.sort.0, input.sort.1, |r, k| match k {
                "source" => sv_s(&r.source),
                "detail" => sv_s(&r.detail),
                _ => sv_s(""),
            });
            out.rows = out.shown.iter().map(|&i| { let r = &d.reboot[i]; simple_row(i as i32, vec![cell(&r.source, 3), cell(&r.detail, 0)], 0, &r.detail) }).collect();
            out.empty = ("\u{E777}".into(), "No reboot pending.".into(), "Nothing is queued in any of the places Windows records a pending restart: servicing, Windows Update, file renames, computer rename, domain join.".into());
        }
        _ => {
            let week = 7 * 86_400_000;
            let month = 30 * 86_400_000;
            let chip_ok = |r: &UpdateRow| match input.chip.as_str() {
                "failed" => !r.ok,
                "week" => now - r.time_ms <= week,
                "month" => now - r.time_ms <= month,
                "uninstall" => r.operation == "Uninstallation",
                _ => true,
            };
            out.chips = vec![
                chip("", "All", Some(d.history.len()), "Every history entry Windows Update keeps"),
                chip("failed", "Failed", Some(d.history.iter().filter(|r| !r.ok).count()), "Installations that failed or were aborted"),
                chip("week", "Last 7 days", Some(d.history.iter().filter(|r| now - r.time_ms <= week).count()), "What happened this week"),
                chip("month", "Last 30 days", Some(d.history.iter().filter(|r| now - r.time_ms <= month).count()), "What happened this month"),
                chip("uninstall", "Uninstalls", Some(d.history.iter().filter(|r| r.operation == "Uninstallation").count()), "Updates that were removed"),
            ];
            out.shown = (0..d.history.len()).filter(|&i| { let r = &d.history[i]; chip_ok(r) && (terms.is_empty() || term_matches(&terms, |k| match k { "kb" => Some(r.kb.clone()), "result" => Some(r.result.clone()), _ => None }, &format!("{} {} {} {}", r.title, r.kb, r.result, r.operation))) }).collect();
            sort_indices(&d.history, &mut out.shown, &input.sort.0, input.sort.1, |r, k| match k {
                "time" => sv_n(r.time_ms as f64),
                "result" => sv_s(&r.result),
                "title" => sv_s(&r.title),
                "kb" => sv_s(&r.kb),
                "operation" => sv_s(&r.operation),
                _ => sv_s(""),
            });
            out.rows = out.shown.iter().map(|&i| {
                let r = &d.history[i];
                simple_row(i as i32, vec![num(&fmt_age((now - r.time_ms).max(0))), dot_cell(&r.result, result_tone(r)), cell(&r.title, 0), cell(&r.kb, 0), cell(&r.operation, 7)], 0, &format!("{}  ·  {}{}\n{}{}", time_of(r.time_ms), r.result, if r.hresult != 0 && !r.ok { format!(" (0x{:08X})", r.hresult as u32) } else { String::new() }, r.title, if r.description.is_empty() { String::new() } else { format!("\n\n{}", r.description) }))
            }).collect();
            out.empty = ("\u{E777}".into(), if input.filter.is_empty() && input.chip.is_empty() { "Windows Update has no history on this machine.".into() } else { lists::nothing_matches(&input.filter) }, String::new());
        }
    }
    out.count = head;
    out
}

fn kb_first(kb: &str) -> Option<String> {
    kb.split(',').next().map(|s| s.trim().trim_start_matches("KB").to_string()).filter(|s| !s.is_empty())
}

fn double(ctx: &Shared, src: usize) {
    let seg = ctx.st.borrow().lists.segment.get("updates").cloned().unwrap_or_default();
    let st = ctx.st.borrow();
    let ListData::Updates(d) = &st.lists.data else { return };
    let text = match seg.as_str() {
        "pending" => match &d.pending { Some(Ok(rows)) => rows.get(src).map(|p| format!("{} {}", p.title, p.kb)), _ => None },
        "reboot" => d.reboot.get(src).map(|r| format!("{}: {}", r.source, r.detail)),
        _ => d.history.get(src).map(|r| format!("{} {} {} {}", time_of(r.time_ms), r.result, r.title, r.kb)),
    };
    drop(st);
    if let Some(t) = text {
        copy_text(ctx, &t);
    }
}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let seg = ctx.st.borrow().lists.segment.get("updates").cloned().unwrap_or_default();
    let st = ctx.st.borrow();
    let ListData::Updates(d) = &st.lists.data else { return };
    let mut pending: Option<(String, i32)> = None;
    let (title, kb, summary) = match seg.as_str() {
        "pending" => match &d.pending { Some(Ok(rows)) => match rows.get(src) { Some(p) => { pending = Some((p.update_id.clone(), p.revision)); (p.title.clone(), p.kb.clone(), format!("{} {} {}", p.title, p.kb, p.severity)) }, None => return }, _ => return },
        "reboot" => match d.reboot.get(src) { Some(r) => (r.source.clone(), String::new(), format!("{}: {}", r.source, r.detail)), None => return },
        _ => match d.history.get(src) { Some(r) => (r.title.clone(), r.kb.clone(), format!("{} {} {} {}", time_of(r.time_ms), r.result, r.title, r.kb)), None => return },
    };
    drop(st);
    let first = kb_first(&kb);
    let mut items = Vec::new();
    if let Some(id) = pending {
        let t = title.clone();
        items.push(MenuItem::new("install", "Install this update…", move |ctx| install(ctx, vec![id.clone()], t.clone())).tip("Download and install it now through the Windows Update Agent, without restarting"));
        items.push(MenuItem::sep());
    }
    items.extend([
        MenuItem::new("copy", "Copy title", { let v = title.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("copyKb", "Copy KB", { let v = kb.clone(); move |ctx| copy_text(ctx, &v) }).disabled(kb.is_empty()),
        MenuItem::new("copySummary", "Copy summary", { let v = summary.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::sep(),
        MenuItem::new("kb", "Open KB article in the browser", { let k = first.clone().unwrap_or_default(); move |ctx| simple_action(ctx, Action::OpenTool(format!("kb:{}", k)), "Opened the KB article", None) }).disabled(first.is_none()).tip("Opens support.microsoft.com. On an air gapped server the browser cannot reach it"),
        MenuItem::new("history", "Open update history in Settings", |ctx| simple_action(ctx, Action::OpenTool("wuhistory".into()), "Opened update history", None)),
    ]);
    menus::show(ctx, x, y, &title, items);
}

fn button(ctx: &Shared, id: &str) {
    match id {
        "settings" => simple_action(ctx, Action::OpenTool("wu".into()), "Opened Windows Update", None),
        "check" => run_check(ctx, false, false),
        "installall" => {
            let rows: Vec<(String, i32)> = match &ctx.st.borrow().lists.updates_pending { Some(Ok(rows)) => rows.iter().map(|p| (p.update_id.clone(), p.revision)).collect(), _ => Vec::new() };
            if rows.is_empty() {
                bad(ctx, "Nothing is pending. Check for pending updates first");
                return;
            }
            let what = plural(rows.len(), "pending update", "pending updates");
            install(ctx, rows, what);
        }
        _ => {}
    }
}

fn export_csv(data: &ListData, shown: &[usize], st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Updates(d) = data else { return None };
    Some(match current(st) {
        "pending" => {
            let rows: &[PendingRow] = match &d.pending { Some(Ok(r)) => r, _ => &[] };
            ("keyhole-pending-updates", csv(&shown.iter().filter_map(|&i| rows.get(i)).map(|p| vec![p.title.clone(), p.kb.clone(), p.severity.clone(), p.mandatory.to_string(), p.downloaded.to_string(), p.reboot.clone(), p.size.to_string(), p.description.clone()]).collect::<Vec<_>>(), &["Update", "KB", "Severity", "Mandatory", "Downloaded", "Reboot", "Size", "Description"]))
        }
        "reboot" => ("keyhole-reboot-pending", csv(&shown.iter().filter_map(|&i| d.reboot.get(i)).map(|r| vec![r.source.clone(), r.detail.clone()]).collect::<Vec<_>>(), &["Reason", "Detail"])),
        _ => ("keyhole-update-history", csv(&shown.iter().filter_map(|&i| d.history.get(i)).map(|r| vec![time_of(r.time_ms), r.result.clone(), r.title.clone(), r.kb.clone(), r.operation.clone(), if r.hresult != 0 { format!("0x{:08X}", r.hresult as u32) } else { String::new() }, r.update_id.clone(), r.description.clone()]).collect::<Vec<_>>(), &["Time", "Result", "Update", "KB", "Operation", "HRESULT", "Update ID", "Description"])),
    })
}
