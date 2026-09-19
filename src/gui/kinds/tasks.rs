use super::{Kind, RenderInput, Rendered, plural, refresh_after};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{ListData, ListState, nothing_matches};
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, dot_cell, simple_row, sort_indices, sv_s};
use crate::gui::{batch_action, simple_action};
use crate::gui::{Shared, chip, copy_text, dialogs, model, ss};
use crate::{Badge, Chip};
use keyhole::api::{self, Action};
use keyhole::state::App;
use keyhole::sys::tasks::TaskRow;
use std::collections::HashMap;

pub const COLUMNS: &[ColDef] = &[
    c("name", "Task", 240.0, false, "Task name. Click to sort."),
    c("path", "Folder", 200.0, false, "Task Scheduler folder. Click to sort."),
    c("state", "State", 100.0, false, "Ready, Running, Disabled. Click to sort."),
    c("triggers", "Runs", 130.0, false, "What starts the task: a schedule, logon, boot, an event, and so on."),
    c("action", "Action", 300.0, false, "What the task runs."),
    c("user", "Run as", 130.0, false, "Account the task runs under, and whether it asked for highest privileges. Click to sort."),
    c("last", "Last run", 130.0, false, "When the task last ran. Click to sort."),
    c("result", "Last result", 120.0, false, "How the last run ended. Anything other than Success is highlighted."),
    c("next", "Next run", 130.0, false, "When it is next scheduled to run. Click to sort."),
];

fn columns(_st: &ListState) -> &'static [ColDef] {
    COLUMNS
}

fn default_sort(_st: &ListState) -> (&'static str, bool) {
    ("name", false)
}

pub static KIND: Kind = Kind {
    name: "tasks",
    title: "Scheduled tasks",
    placeholder: ("Filter tasks", "Show only tasks whose name, folder, action, author, trigger or result contains this text"),
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
    vec![chip("add", "New task…", None, "Create a scheduled task that runs a program on a schedule, at logon or at startup")]
}

fn refresh(app: &App, st: &ListState) -> ListData {
    let _ = (app, st);
    match api::tasks() { Ok(rows) => ListData::Tasks(rows, String::new()), Err(e) => ListData::Tasks(Vec::new(), e) }
}

fn render(ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Tasks(list, note) = data else { return Rendered::default() };
    let _ = ctx;
    let filter = input.filter.clone();
    let chip_id = input.chip.clone();
    let sort = input.sort.clone();
    
    let matches = |id: &str, r: &TaskRow| match id {
        "ready" => r.state != "Disabled",
        "running" => r.state == "Running",
        "failed" => !r.result.is_empty() && !r.result_ok,
        "nonms" => !r.path.to_lowercase().starts_with("\\microsoft"),
        "disabled" => r.state == "Disabled",
        "hidden" => r.hidden,
        _ => true,
    };
    let chips = vec![
        chip("", "All", Some(list.len()), "Every scheduled task"),
        chip("ready", "Enabled", Some(list.iter().filter(|r| r.state != "Disabled").count()), "Tasks that can run"),
        chip("running", "Running", Some(list.iter().filter(|r| r.state == "Running").count()), "Tasks running right now"),
        chip("failed", "Last run failed", Some(list.iter().filter(|r| !r.result.is_empty() && !r.result_ok).count()), "Tasks whose most recent run did not end in success"),
        chip("nonms", "Outside Microsoft folder", Some(list.iter().filter(|r| !r.path.to_lowercase().starts_with("\\microsoft")).count()), "Tasks not in the Microsoft folder: usually third-party or handmade"),
        chip("disabled", "Disabled", Some(list.iter().filter(|r| r.state == "Disabled").count()), "Tasks that will not run"),
        chip("hidden", "Hidden", Some(list.iter().filter(|r| r.hidden).count()), "Tasks flagged hidden, which Task Scheduler only shows with View > Show Hidden Tasks"),
    ];
    let mut shown = (0..list.len()).filter(|&i| matches(&chip_id, &list[i]) && (filter.is_empty() || format!("{} {} {} {} {} {} {} {}", list[i].name, list[i].path, list[i].action, list[i].state, list[i].author, list[i].result, list[i].triggers, list[i].user).to_lowercase().contains(&filter))).collect();
    sort_indices(list, &mut shown, &sort.0, sort.1, |r, k| match k {
        "name" => sv_s(&r.name),
        "path" => sv_s(&r.path),
        "state" => sv_s(&r.state),
        "triggers" => sv_s(&r.triggers),
        "action" => sv_s(&r.action),
        "user" => sv_s(&r.user),
        "last" => sv_s(&r.last),
        "result" => sv_s(&r.result),
        "next" => sv_s(&r.next),
        _ => sv_s(""),
    });
    let count: String = format!("{}{}", shown_of(shown.len(), list.len(), "tasks"), if note.is_empty() { String::new() } else { format!("  ·  {}", note) });
    let rows = shown
        .iter()
        .map(|&i| {
            let r = &list[i];
            let dot = if r.state == "Running" { 2 } else if r.state == "Disabled" { 1 } else { 5 };
            let mut row = simple_row(
                i as i32,
                vec![
                    cell(&r.name, 0),
                    cell(&r.path, 0),
                    dot_cell(&r.state, dot),
                    cell(&r.triggers, 7),
                    cell(&r.action, 0),
                    cell(&short_user(&r.user), 0),
                    cell(&r.last, 0),
                    cell(&r.result, if r.result.is_empty() || r.result_ok { 0 } else { 4 }),
                    cell(&r.next, 0),
                ],
                if r.state == "Disabled" { 1 } else { 0 },
                &format!("{}{}{}\n{}\nRuns as: {}", r.name, if r.author.is_empty() { String::new() } else { format!("\nAuthor: {}", r.author) }, if r.hidden { "\nHidden task" } else { "" }, r.action, r.user),
            );
            if r.hidden {
                row.badges = model(vec![Badge { text: ss("hidden"), kind: 0, tip: ss("Hidden task") }]);
            }
            row
        })
        .collect();
    let empty = ("\u{E823}".into(), nothing_matches(&filter), note.clone());
    Rendered { chips, rows, shown, count, empty }
}

fn double(_ctx: &Shared, _src: usize) {}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let d = {
        let st = ctx.st.borrow();
        let ListData::Tasks(list, ..) = &st.lists.data else { return };
        let Some(row) = list.get(src) else { return };
        row.clone()
    };
    task_menu(ctx, x, y, &d);
}

fn task_menu(ctx: &Shared, x: f32, y: f32, d: &TaskRow) {
    let full = format!("{}\\{}", if d.path == "\\" { "" } else { &d.path }, d.name);
    let running = d.state == "Running";
    let disabled = d.state == "Disabled";
    let name = d.name.clone();
    let act = |op: &'static str, verb: &'static str, body: Option<String>| {
        let full = full.clone();
        let name = name.clone();
        move |ctx: &Shared| {
            let full = full.clone();
            let name = name.clone();
            let title = format!("{} {}?", verb, name);
            let run = move |ctx: &Shared| simple_action(ctx, Action::Task { path: full.clone(), op: op.into() }, &format!("{} {}", verb, name), refresh_after("tasks"));
            match &body {
                Some(b) => dialogs::confirm(ctx, &title, b, verb, true, Box::new(run)),
                None => run(ctx),
            }
        }
    };
    let target = d.target.clone();
    let mut items = vec![
        MenuItem::new("run", "Run now", act("run", "Ran", None)),
        MenuItem::new("end", "End", act("end", "Ended", None)).disabled(!running),
        MenuItem::sep(),
        MenuItem::new("enable", "Enable", act("enable", "Enabled", None)).disabled(!disabled),
        MenuItem::new("disable", "Disable", act("disable", "Disabled", Some(format!("This disables the scheduled task {} so it will not run.", d.name)))).danger().disabled(disabled),
        MenuItem::sep(),
        MenuItem::new("copyName", "Copy task name", { let v = d.name.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("copyPath", "Copy task path", { let v = full.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("copy", "Copy action", { let v = d.action.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.action.is_empty()),
        MenuItem::new("reveal", "Show action target in Explorer", { let t = target.clone(); move |ctx| simple_action(ctx, Action::Reveal(t), "Revealed", None) }).disabled(target.is_empty()),
        MenuItem::new("running", "Find running process", { let t = target.clone(); move |ctx| crate::gui::tree::find_running(ctx, &t) }).disabled(target.is_empty()),
    ];
    items.extend(menus::file_items(&target));
    items.push(MenuItem::new("console", "Open Task Scheduler", |ctx| simple_action(ctx, Action::OpenTool("tasks".into()), "Opened Task Scheduler", None)));
    items.push(MenuItem::sep());
    items.push(MenuItem::new("del", "Delete task", act("delete", "Deleted", Some(format!("This permanently deletes the scheduled task {}. This cannot be undone.{}", d.name, if d.path.contains("Microsoft") { " This is a task Windows itself installed." } else { "" })))).danger());
    menus::show(ctx, x, y, &d.name, items);
}

fn button(ctx: &Shared, id: &str) {
    if id == "add" {
        add_task(ctx, HashMap::new());
    }
}

pub fn add_task(ctx: &Shared, preset: HashMap<String, String>) {
    use keyhole::sys::tasks::{REPEATS, RUN_AS, TRIGGERS, default_date, default_time};
    let g = |k: &str, d: &str| preset.get(k).cloned().unwrap_or_else(|| d.to_string());
    let fields = vec![
        dialogs::FieldSpec::text("name", "Name", &g("name", ""), "Task name, or Folder\\Task name", true),
        dialogs::FieldSpec::text("program", "Program", &g("program", ""), "Full path to an .exe, .bat, .ps1 runner or script host", true),
        dialogs::FieldSpec::text("arguments", "Arguments", &g("arguments", ""), "Optional command line arguments", false),
        dialogs::FieldSpec::text("startIn", "Start in", &g("startIn", ""), "Optional working folder", false),
        dialogs::FieldSpec::select("trigger", "Runs", &g("trigger", "daily"), TRIGGERS),
        dialogs::FieldSpec::text("time", "At time", &g("time", &default_time()), "HH:MM, 24-hour clock", false).only_when("trigger", &["daily", "weekly", "once"], "Logon and startup triggers have no time"),
        dialogs::FieldSpec::text("date", "On date", &g("date", &default_date()), "YYYY-MM-DD", false).only_when("trigger", &["once"], "Only a one time trigger needs a date"),
        dialogs::FieldSpec::text("days", "Days", &g("days", "Mon, Tue, Wed, Thu, Fri"), "Mon, Tue, Wed, Thu, Fri, Sat, Sun", false).only_when("trigger", &["weekly"], "Only a weekly trigger picks days"),
        dialogs::FieldSpec::select("repeat", "Repeat", &g("repeat", ""), REPEATS),
        dialogs::FieldSpec::select("runAs", "Run as", &g("runAs", "system"), RUN_AS),
        dialogs::FieldSpec::text("account", "Account", &g("account", ""), "DOMAIN\\user or .\\user", false).only_when("runAs", &["account"], "Choose Another account above to fill this in"),
        dialogs::FieldSpec::password("password", "Password", "Leave empty to run without a stored password (no network access)").optional().only_when("runAs", &["account"], "Choose Another account above to fill this in"),
        dialogs::FieldSpec::check("highest", "Run with highest privileges", g("highest", "true") != "false"),
        dialogs::FieldSpec::check("enabled", "Enable the task immediately", g("enabled", "true") != "false"),
        dialogs::FieldSpec::text("description", "Description", &g("description", ""), "Optional note shown in Task Scheduler", false),
    ];
    dialogs::form(
        ctx,
        "New scheduled task",
        "Creates a task in Task Scheduler. Time and date use the 24-hour clock in this computer's time zone.",
        fields,
        "Create task",
        Box::new(|ctx, v| {
            let get = |k: &str| v.get(k).cloned().unwrap_or_default();
            let task = keyhole::sys::tasks::NewTask {
                name: get("name"),
                description: get("description"),
                program: get("program"),
                arguments: get("arguments"),
                start_in: get("startIn"),
                trigger: get("trigger"),
                time: get("time"),
                date: get("date"),
                days: get("days"),
                repeat: get("repeat"),
                run_as: get("runAs"),
                account: get("account"),
                password: get("password").into(),
                highest: get("highest") != "false",
                enabled: get("enabled") != "false",
            };
            if let Err(e) = keyhole::sys::tasks::validate(&task) {
                crate::gui::bad(ctx, &format!("Cannot create task: {}", e));
                add_task(ctx, v);
                return;
            }
            let name = task.name.clone();
            simple_action(ctx, Action::TaskCreate(task), &format!("Created task {}", name), refresh_after("tasks"));
        }),
    );
}

fn export_csv(data: &ListData, shown: &[usize], _st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Tasks(l, _) = data else { return None };
    Some(("keyhole-tasks", csv(&shown.iter().map(|&i| { let r = &l[i]; vec![r.name.clone(), r.path.clone(), r.state.clone(), r.triggers.clone(), r.action.clone(), r.user.clone(), r.last.clone(), r.result.clone(), r.next.clone(), r.author.clone(), r.target.clone(), r.hidden.to_string()] }).collect::<Vec<_>>(), &["Task", "Folder", "State", "Runs", "Action", "Run as", "Last run", "Last result", "Next run", "Author", "Target", "Hidden"])))
}

fn multi(ctx: &Shared, srcs: &[usize], x: f32, y: f32) {
    let rows: Vec<TaskRow> = {
        let st = ctx.st.borrow();
        let ListData::Tasks(list, ..) = &st.lists.data else { return };
        srcs.iter().filter_map(|&i| list.get(i).cloned()).collect()
    };
    if rows.is_empty() {
        return;
    }
    let n = rows.len();
    let full = |d: &TaskRow| format!("{}\\{}", if d.path == "\\" { "" } else { &d.path }, d.name);
    let acts = |pick: fn(&TaskRow) -> bool, op: &'static str| -> Vec<(String, Action)> {
        rows.iter().filter(|r| pick(r)).map(|r| (r.name.clone(), Action::Task { path: full(r), op: op.into() })).collect()
    };
    let names = rows.iter().take(6).map(|r| r.name.clone()).collect::<Vec<_>>();
    let listing = if n > 6 { format!("{} and {} more", names.join(", "), n - 6) } else { names.join(", ") };
    let run = acts(|_| true, "run");
    let end = acts(|r| r.state == "Running", "end");
    let enable = acts(|r| r.state == "Disabled", "enable");
    let disable = acts(|r| r.state != "Disabled", "disable");
    let items = vec![
        MenuItem::new("run", &format!("Run {} now", plural(run.len(), "task", "tasks")), { let a = run; move |ctx| batch_action(ctx, a, "Ran", ("task", "tasks"), refresh_after("tasks")) }),
        MenuItem::new("end", &format!("End {}", plural(end.len(), "task", "tasks")), { let a = end.clone(); move |ctx| batch_action(ctx, a, "Ended", ("task", "tasks"), refresh_after("tasks")) }).disabled(end.is_empty()),
        MenuItem::sep(),
        MenuItem::new("enable", &format!("Enable {}", plural(enable.len(), "task", "tasks")), { let a = enable.clone(); move |ctx| batch_action(ctx, a, "Enabled", ("task", "tasks"), refresh_after("tasks")) }).disabled(enable.is_empty()),
        MenuItem::new("disable", &format!("Disable {}", plural(disable.len(), "task", "tasks")), {
            let a = disable.clone();
            move |ctx| {
                let a = a.clone();
                dialogs::confirm(ctx, "Disable scheduled tasks?", &format!("This disables {} so they will not run: {}.", plural(a.len(), "task", "tasks"), listing), "Disable", true, Box::new(move |ctx| batch_action(ctx, a, "Disabled", ("task", "tasks"), refresh_after("tasks"))));
            }
        })
        .danger()
        .disabled(disable.is_empty()),
        MenuItem::sep(),
        MenuItem::new("copy", "Copy task paths", { let v = rows.iter().map(full).collect::<Vec<_>>().join("\n"); move |ctx| copy_text(ctx, &v) }),
    ];
    menus::show(ctx, x, y, &format!("{} selected", plural(n, "task", "tasks")), items);
}
