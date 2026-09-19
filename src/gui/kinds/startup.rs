use super::{Kind, RenderInput, Rendered, plural, refresh_after, unsigned};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{ListData, ListState, nothing_matches};
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, dot_cell, sig_text, sig_tone, simple_row, sort_indices, sv_b, sv_s};
use crate::gui::{batch_action, simple_action};
use crate::gui::{Shared, chip, copy_text, dialogs};
use crate::Chip;
use keyhole::api::{self, Action, StartupEntry};
use keyhole::state::App;

pub const COLUMNS: &[ColDef] = &[
    c("name", "Name", 220.0, false, "Registry value name or shortcut file name. Click to sort."),
    c("command", "Command", 380.0, false, "What gets run at startup."),
    c("publisher", "Publisher", 170.0, false, "Company named in the target file's version information. Click to sort."),
    c("enabled", "Enabled", 84.0, false, "Whether Windows will run this entry at logon (the same switch as Task Manager's Startup tab)."),
    c("trust", "Signature", 100.0, false, "Whether the target executable carries a valid digital signature."),
    c("location", "Location", 150.0, false, "Where this entry is registered."),
    c("scope", "Scope", 110.0, false, "Whether it applies to all users or only the current user."),
];

fn columns(_st: &ListState) -> &'static [ColDef] {
    COLUMNS
}

fn default_sort(_st: &ListState) -> (&'static str, bool) {
    ("name", false)
}

pub static KIND: Kind = Kind {
    name: "startup",
    title: "Startup",
    placeholder: ("Filter entries", "Show only entries whose name, command, publisher or location contains this text"),
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
    Vec::new()
}

fn refresh(app: &App, st: &ListState) -> ListData {
    let _ = (app, st);
    ListData::Startup(api::startup(app))
}

fn render(ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Startup(list) = data else { return Rendered::default() };
    let _ = ctx;
    let filter = input.filter.clone();
    let chip_id = input.chip.clone();
    let sort = input.sort.clone();
    
    let matches = |id: &str, r: &StartupEntry| match id {
        "on" => r.enabled,
        "off" => !r.enabled,
        "unsigned" => unsigned(&r.trust),
        "all" => r.scope == "All users",
        _ => true,
    };
    let chips = vec![
        chip("", "All", Some(list.len()), "Everything that runs at logon"),
        chip("on", "Enabled", Some(list.iter().filter(|r| r.enabled).count()), "Entries that will run at the next logon"),
        chip("off", "Disabled", Some(list.iter().filter(|r| !r.enabled).count()), "Entries switched off in Task Manager or Settings"),
        chip("unsigned", "Not signed", Some(list.iter().filter(|r| unsigned(&r.trust)).count()), "Targets without a valid digital signature: worth checking"),
        chip("all", "All users", Some(list.iter().filter(|r| r.scope == "All users").count()), "Entries that run for every account on this computer"),
    ];
    let mut shown = (0..list.len()).filter(|&i| matches(&chip_id, &list[i]) && (filter.is_empty() || format!("{} {} {} {} {}", list[i].name, list[i].command, list[i].publisher, list[i].location, list[i].scope).to_lowercase().contains(&filter))).collect();
    sort_indices(list, &mut shown, &sort.0, sort.1, |r, k| match k {
        "name" => sv_s(&r.name),
        "command" => sv_s(&r.command),
        "publisher" => sv_s(&r.publisher),
        "enabled" => sv_b(r.enabled),
        "trust" => sv_s(&r.trust),
        "location" => sv_s(&r.location),
        "scope" => sv_s(&r.scope),
        _ => sv_s(""),
    });
    let count: String = shown_of(shown.len(), list.len(), "entries");
    let rows = shown
        .iter()
        .map(|&i| {
            let r = &list[i];
            simple_row(
                i as i32,
                vec![
                    cell(&r.name, 0),
                    cell(&r.command, 0),
                    cell(&r.publisher, 0),
                    dot_cell(if r.enabled { "on" } else { "off" }, if r.enabled { 2 } else { 1 }),
                    cell(&sig_text(&r.trust), sig_tone(&r.trust)),
                    cell(&r.location, 0),
                    cell(&r.scope, 0),
                ],
                if r.enabled { 0 } else { 1 },
                &format!("{}{}\n{}", r.name, if r.description.is_empty() { String::new() } else { format!("\n{}", r.description) }, r.command),
            )
        })
        .collect();
    let empty = ("\u{E7E8}".into(), nothing_matches(&filter), String::new());
    Rendered { chips, rows, shown, count, empty }
}

fn double(_ctx: &Shared, _src: usize) {}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let d = {
        let st = ctx.st.borrow();
        let ListData::Startup(list) = &st.lists.data else { return };
        let Some(row) = list.get(src) else { return };
        row.clone()
    };
    startup_menu(ctx, x, y, &d);
}

fn startup_menu(ctx: &Shared, x: f32, y: f32, d: &StartupEntry) {
    let is_file = is_file_path(&d.image_path);
    let reg_loc = d.location.starts_with("HK");
    let can_toggle = matches!(d.source.as_str(), "hklm_run" | "hklm_wow_run" | "hkcu_run" | "folder");
    let can_remove = d.source != "winlogon" && d.source != "hklm_runonceex" && !d.source.starts_with("hku_");
    let reg_key = if reg_loc { startup_reg_key(d) } else { String::new() };
    let toggle = |enabled: bool, verb: &'static str| {
        let d = d.clone();
        move |ctx: &Shared| simple_action(ctx, Action::StartupEnabled { source: d.source.clone(), scope: d.scope.clone(), name: d.name.clone(), enabled }, &format!("{} {}", verb, d.name), refresh_after("startup"))
    };
    let mut items = vec![
        MenuItem::new("copyName", "Copy name", { let v = d.name.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("copy", "Copy command", { let v = d.command.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("copyPath", "Copy target path", { let v = d.image_path.clone(); move |ctx| copy_text(ctx, &v) }).disabled(!is_file),
        MenuItem::sep(),
        MenuItem::new("reveal", "Show target in Explorer", { let p = d.image_path.clone(); move |ctx| simple_action(ctx, Action::Reveal(p), "Revealed", None) }).disabled(!is_file),
        MenuItem::new("loc", if reg_loc { "Open location in Registry Editor" } else { "Open location in Explorer" }, { let item = d.command.clone(); let key = reg_key.clone(); move |ctx| if reg_loc { simple_action(ctx, Action::OpenRegistryKey(key), "Opened Registry Editor", None) } else { simple_action(ctx, Action::OpenFolder(item.clone()), "Opened folder", None) } }).disabled(if reg_loc { d.location.is_empty() } else { d.source != "folder" || d.command.is_empty() }),
        MenuItem::new("running", "Find running process", { let p = d.image_path.clone(); move |ctx| crate::gui::tree::find_running(ctx, &p) }).disabled(!is_file),
    ];
    items.extend(menus::file_items(&d.image_path));
    items.push(MenuItem::sep());
    items.push(MenuItem::new("disable", "Disable (keep the entry)", toggle(false, "Disabled")).disabled(!d.enabled || !can_toggle));
    items.push(MenuItem::new("enable", "Enable", toggle(true, "Enabled")).disabled(d.enabled || !can_toggle));
    items.push(MenuItem::new("settings", "Open Windows Startup settings", |ctx| simple_action(ctx, Action::OpenTool("startup".into()), "Opened Startup settings", None)));
    items.push(MenuItem::sep());
    items.push(
        MenuItem::new("remove", "Remove this startup entry", {
            let d = d.clone();
            move |ctx| {
                let d2 = d.clone();
                dialogs::confirm(
                    ctx,
                    &format!("Remove {} from startup?", d.name),
                    &format!("This deletes the startup entry {} from {}. The program itself is not uninstalled.{}", d.name, d.location, if d.scope == "All users" { " This is an all-users entry." } else { "" }),
                    "Remove",
                    true,
                    Box::new(move |ctx| simple_action(ctx, Action::RemoveStartup { source: d2.source.clone(), name: d2.name.clone(), command: d2.command.clone() }, &format!("Removed {}", d2.name), refresh_after("startup"))),
                );
            }
        })
        .danger()
        .disabled(!can_remove),
    );
    menus::show(ctx, x, y, &d.name, items);
}

fn startup_reg_key(d: &StartupEntry) -> String {
    let loc = &d.location;
    if loc.contains("Winlogon") {
        return "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon".into();
    }
    if loc.contains("Policies") {
        return loc.replace("\\...\\", "\\Software\\Microsoft\\Windows\\CurrentVersion\\");
    }
    if loc.starts_with("HKU") {
        return "HKEY_USERS".into();
    }
    loc.replace("\\...\\", "\\Software\\Microsoft\\Windows\\CurrentVersion\\").replace("\\WOW6432\\", "\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\")
}

fn button(ctx: &Shared, id: &str) {
    let _ = (ctx, id);
}

fn export_csv(data: &ListData, shown: &[usize], _st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Startup(l) = data else { return None };
    Some(("keyhole-startup", csv(&shown.iter().map(|&i| { let r = &l[i]; vec![r.name.clone(), r.command.clone(), r.publisher.clone(), r.enabled.to_string(), r.trust.clone(), r.location.clone(), r.scope.clone()] }).collect::<Vec<_>>(), &["Name", "Command", "Publisher", "Enabled", "Signature", "Location", "Scope"])))
}

fn multi(ctx: &Shared, srcs: &[usize], x: f32, y: f32) {
    let rows: Vec<StartupEntry> = {
        let st = ctx.st.borrow();
        let ListData::Startup(list) = &st.lists.data else { return };
        srcs.iter().filter_map(|&i| list.get(i).cloned()).collect()
    };
    if rows.is_empty() {
        return;
    }
    let n = rows.len();
    let can_toggle = |d: &StartupEntry| matches!(d.source.as_str(), "hklm_run" | "hklm_wow_run" | "hkcu_run" | "folder");
    let can_remove = |d: &StartupEntry| d.source != "winlogon" && d.source != "hklm_runonceex" && !d.source.starts_with("hku_");
    let toggle = |enabled: bool| -> Vec<(String, Action)> {
        rows.iter().filter(|d| can_toggle(d) && d.enabled != enabled).map(|d| (d.name.clone(), Action::StartupEnabled { source: d.source.clone(), scope: d.scope.clone(), name: d.name.clone(), enabled })).collect()
    };
    let disable = toggle(false);
    let enable = toggle(true);
    let remove: Vec<(String, Action)> = rows.iter().filter(|d| can_remove(d)).map(|d| (d.name.clone(), Action::RemoveStartup { source: d.source.clone(), name: d.name.clone(), command: d.command.clone() })).collect();
    let names = rows.iter().take(6).map(|r| r.name.clone()).collect::<Vec<_>>();
    let listing = if n > 6 { format!("{} and {} more", names.join(", "), n - 6) } else { names.join(", ") };
    let items = vec![
        MenuItem::new("disable", &format!("Disable {} (keep the entries)", plural(disable.len(), "entry", "entries")), { let a = disable.clone(); move |ctx| batch_action(ctx, a, "Disabled", ("entry", "entries"), refresh_after("startup")) }).disabled(disable.is_empty()),
        MenuItem::new("enable", &format!("Enable {}", plural(enable.len(), "entry", "entries")), { let a = enable.clone(); move |ctx| batch_action(ctx, a, "Enabled", ("entry", "entries"), refresh_after("startup")) }).disabled(enable.is_empty()),
        MenuItem::sep(),
        MenuItem::new("copy", "Copy names", { let v = rows.iter().map(|r| r.name.clone()).collect::<Vec<_>>().join("\n"); move |ctx| copy_text(ctx, &v) }),
        MenuItem::sep(),
        MenuItem::new("remove", &format!("Remove {} from startup", plural(remove.len(), "entry", "entries")), {
            let a = remove.clone();
            move |ctx| {
                let a = a.clone();
                dialogs::confirm(ctx, "Remove startup entries?", &format!("This deletes {}: {}. The programs themselves are not uninstalled.", plural(a.len(), "startup entry", "startup entries"), listing), "Remove", true, Box::new(move |ctx| batch_action(ctx, a, "Removed", ("entry", "entries"), refresh_after("startup"))));
            }
        })
        .danger()
        .disabled(remove.is_empty()),
    ];
    menus::show(ctx, x, y, &format!("{} selected", plural(n, "entry", "entries")), items);
}
