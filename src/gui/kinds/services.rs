use super::{Kind, RenderInput, Rendered, refresh_after};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{ListData, ListState, nothing_matches};
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, dot_cell, num, simple_row, sort_indices, suffix_cell, sv_n, sv_s};
use crate::gui::simple_action;
use crate::gui::{Shared, chip, copy_text, dialogs};
use crate::Chip;
use keyhole::api::{self, Action};
use keyhole::state::App;
use keyhole::sys::services::ServiceRow;

pub const COLUMNS: &[ColDef] = &[
    c("display", "Display name", 260.0, false, "Display name shown in Services. Click to sort."),
    c("name", "Service", 170.0, false, "Short service key name. Click to sort."),
    c("state", "State", 104.0, false, "Running, Stopped, and so on. Click to sort."),
    c("start_type", "Start type", 140.0, false, "Automatic starts at boot, Manual only when something asks for it, Disabled never. Click to sort."),
    c("pid", "PID", 72.0, true, "Hosting process, or blank when stopped. Double-click a running service to jump to it."),
    c("account", "Log on as", 160.0, false, "Account the service runs under. Click to sort."),
    c("description", "Description", 280.0, false, "What the service does, as described by its publisher."),
    c("binary", "Path", 300.0, false, "Command line the service is started with, and how many services it depends on."),
];

fn columns(_st: &ListState) -> &'static [ColDef] {
    COLUMNS
}

fn default_sort(_st: &ListState) -> (&'static str, bool) {
    ("display", false)
}

pub static KIND: Kind = Kind {
    name: "services",
    title: "Services",
    placeholder: ("Filter services", "Show only services whose name, display name, description, path, account or PID contains this text"),
    columns,
    table: super::same_table,
    segment: super::no_segment,
    default_sort,
    buttons,
    refresh,
    render,
    menu,
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
    Vec::new()
}

fn refresh(app: &App, st: &ListState) -> ListData {
    let _ = (app, st);
    ListData::Services(api::services())
}

fn render(ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Services(list) = data else { return Rendered::default() };
    let _ = ctx;
    let filter = input.filter.clone();
    let chip_id = input.chip.clone();
    let sort = input.sort.clone();
    
    let filtered = |r: &ServiceRow| match filter.strip_prefix("pid:") {
        Some(pid) => r.pid > 0 && r.pid.to_string() == pid.trim(),
        None => format!("{} {} {} {} {} {} {} {}", r.name, r.display, r.state, r.start_type, r.account, r.binary, r.description, if r.pid > 0 { r.pid.to_string() } else { String::new() }).to_lowercase().contains(&filter),
    };
    let matches = |id: &str, r: &ServiceRow| match id {
        "running" => r.state != "Stopped",
        "stopped" => r.state == "Stopped",
        "auto" => r.start_type.starts_with("Automatic"),
        "autostopped" => r.start_type.starts_with("Automatic") && r.state == "Stopped",
        "disabled" => r.start_type == "Disabled",
        "thirdparty" => !r.in_windows,
        _ => true,
    };
    let chips = vec![
        chip("", "All", Some(list.len()), "Every installed service"),
        chip("running", "Running", Some(list.iter().filter(|r| r.state != "Stopped").count()), "Services that are running, paused or changing state"),
        chip("stopped", "Stopped", Some(list.iter().filter(|r| r.state == "Stopped").count()), "Services that are not running"),
        chip("auto", "Automatic", Some(list.iter().filter(|r| r.start_type.starts_with("Automatic")).count()), "Services set to start on their own at boot"),
        chip("autostopped", "Automatic but stopped", Some(list.iter().filter(|r| r.start_type.starts_with("Automatic") && r.state == "Stopped").count()), "Should be running but is not. Worth a look"),
        chip("disabled", "Disabled", Some(list.iter().filter(|r| r.start_type == "Disabled").count()), "Services that cannot start until enabled again"),
        chip("thirdparty", "Outside Windows", Some(list.iter().filter(|r| !r.in_windows).count()), "Services whose program lives outside the Windows folder"),
    ];
    let mut shown = (0..list.len()).filter(|&i| matches(&chip_id, &list[i]) && (filter.is_empty() || filtered(&list[i]))).collect();
    sort_indices(list, &mut shown, &sort.0, sort.1, |r, k| match k {
        "display" => sv_s(&r.display),
        "name" => sv_s(&r.name),
        "state" => sv_s(&r.state),
        "start_type" => sv_s(&r.start_type),
        "pid" => sv_n(r.pid as f64),
        "account" => sv_s(&r.account),
        "description" => sv_s(&r.description),
        "binary" => sv_s(&r.binary),
        _ => sv_s(""),
    });
    let running = list.iter().filter(|r| r.state == "Running").count();
    let count: String = format!("{}, {} running", shown_of(shown.len(), list.len(), "services"), running);
    let rows = shown
        .iter()
        .map(|&i| {
            let r = &list[i];
            let dot = if r.state == "Running" { 2 } else if r.state == "Stopped" { 1 } else { 3 };
            let deps = if r.depends_on.is_empty() { String::new() } else { format!("{} dep{}", r.depends_on.len(), if r.depends_on.len() == 1 { "" } else { "s" }) };
            let mut row = simple_row(
                i as i32,
                vec![
                    cell(&r.display, 0),
                    cell(&r.name, 0),
                    dot_cell(&r.state, dot),
                    cell(&r.start_type, if r.start_type == "Disabled" { 7 } else { 0 }),
                    num(&if r.pid > 0 { r.pid.to_string() } else { String::new() }),
                    cell(&short_user(&r.account), 0),
                    cell(&r.description, 7),
                    suffix_cell(&r.binary, &deps),
                ],
                0,
                &format!("{}\n{}{}{}", r.display, r.name, if r.description.is_empty() { String::new() } else { format!("\n{}", r.description) }, if r.depends_on.is_empty() { String::new() } else { format!("\n\nDepends on: {}", r.depends_on.join(", ")) }),
            );
            row.id = r.pid as i32;
            row
        })
        .collect();
    let empty = ("\u{E713}".into(), nothing_matches(&filter), String::new());
    Rendered { chips, rows, shown, count, empty }
}

fn double(ctx: &Shared, src: usize) {
    let st = ctx.st.borrow();
    let ListData::Services(l) = &st.lists.data else { return };
    let Some(pid) = l.get(src).map(|r| r.pid) else { return };
    drop(st);
    if pid > 0 {
        crate::gui::tree::select_pid(ctx, pid);
    }
}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let d = {
        let st = ctx.st.borrow();
        let ListData::Services(list) = &st.lists.data else { return };
        let Some(row) = list.get(src) else { return };
        row.clone()
    };
    service_menu(ctx, x, y, &d);
}

fn service_menu(ctx: &Shared, x: f32, y: f32, d: &ServiceRow) {
    let running = d.state == "Running";
    let paused = d.state == "Paused";
    let name = d.name.clone();
    let display = d.display.clone();
    let act = |op: &'static str, verb: &'static str| {
        let name = name.clone();
        let display = display.clone();
        move |ctx: &Shared| simple_action(ctx, Action::Service { name: name.clone(), op: op.into() }, &format!("{} {}", verb, display), refresh_after("services"))
    };
    let confirm_act = |title: String, body: String, ok: &'static str, op: &'static str, verb: &'static str| {
        let name = name.clone();
        let display = display.clone();
        move |ctx: &Shared| {
            let name = name.clone();
            let display = display.clone();
            dialogs::confirm(ctx, &title, &body, ok, true, Box::new(move |ctx| simple_action(ctx, Action::Service { name, op: op.into() }, &format!("{} {}", verb, display), refresh_after("services"))));
        }
    };
    let mut items = vec![
        MenuItem::new("start", "Start", act("start", "Started")).disabled(running || paused),
        MenuItem::new("stop", "Stop", confirm_act(format!("Stop {}?", d.display), format!("This stops the {} service now. Anything depending on it may stop working.", d.name), "Stop", "stop", "Stopped")).danger().disabled(!running && !paused),
        MenuItem::new("restart", "Restart", confirm_act(format!("Restart {}?", d.display), format!("This stops and restarts {}.", d.name), "Restart", "restart", "Restarted")).danger().disabled(!running),
        MenuItem::new("pause", "Pause", act("pause", "Paused")).disabled(!running).tip("Only services that support pausing accept this. The others refuse"),
        MenuItem::new("continue", "Continue", act("continue", "Continued")).disabled(!paused),
        MenuItem::sep(),
        MenuItem::new("auto", "Set start type: Automatic", act("enableAuto", "Set to automatic")),
        MenuItem::new("autoDelayed", "Set start type: Automatic (delayed)", act("enableAutoDelayed", "Set to automatic (delayed)")),
        MenuItem::new("manual", "Set start type: Manual", act("enableManual", "Set to manual")),
        MenuItem::new("disable", "Set start type: Disabled", confirm_act(format!("Disable {}?", d.display), format!("This sets {} to Disabled so it will not start at boot.", d.name), "Disable", "disable", "Disabled")).danger(),
        MenuItem::sep(),
        MenuItem::new("sel", "Go to hosting process", { let pid = d.pid; move |ctx| crate::gui::tree::select_pid(ctx, pid) }).disabled(d.pid == 0),
        MenuItem::new("bin", "Show program in Explorer", { let p = d.exe.clone(); move |ctx| simple_action(ctx, Action::Reveal(p), "Revealed", None) }).disabled(d.exe.is_empty()),
        MenuItem::new("cn", "Copy service name", { let v = d.name.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("cd", "Copy display name", { let v = d.display.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("cb", "Copy command line", { let v = d.binary.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.binary.is_empty()),
        MenuItem::new("events", "Show its events (last 7 days)", { let n = d.display.clone(); move |ctx| crate::gui::kinds::events::show_for_service(ctx, &n) }).tip("What the Service Control Manager and the service itself logged: why it stopped, failed to start or crashed"),
    ];
    items.extend(menus::file_items(&d.exe));
    items.push(MenuItem::new("reg", "Open in Registry Editor", { let k = format!("HKLM\\SYSTEM\\CurrentControlSet\\Services\\{}", d.name); move |ctx| simple_action(ctx, Action::OpenRegistryKey(k), "Opened Registry Editor", None) }));
    items.push(MenuItem::new("console", "Open Services console", |ctx| simple_action(ctx, Action::OpenTool("services".into()), "Opened Services", None)));
    items.push(MenuItem::sep());
    items.push(MenuItem::new("del", "Delete service", confirm_act(format!("Delete the {} service?", d.display), format!("This permanently removes the {} service. It cannot be undone and can break software that depends on it.", d.name), "Delete service", "delete", "Deleted")).danger());
    menus::show(ctx, x, y, &format!("{}  ·  {}", d.display, d.state), items);
}

fn button(ctx: &Shared, id: &str) {
    let _ = (ctx, id);
}

fn export_csv(data: &ListData, shown: &[usize], _st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Services(l) = data else { return None };
    Some(("keyhole-services", csv(&shown.iter().map(|&i| { let r = &l[i]; vec![r.display.clone(), r.name.clone(), r.state.clone(), r.start_type.clone(), if r.pid > 0 { r.pid.to_string() } else { String::new() }, r.account.clone(), r.kind.clone(), r.binary.clone(), r.exe.clone(), r.depends_on.join("; "), r.description.clone()] }).collect::<Vec<_>>(), &["Display name", "Service", "State", "Start type", "PID", "Log on as", "Type", "Path", "Executable", "Depends on", "Description"])))
}
