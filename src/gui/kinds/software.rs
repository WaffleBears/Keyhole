use super::{Kind, RenderInput, Rendered};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{ListData, ListState, nothing_matches};
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, num, simple_row, sort_indices, sv_n, sv_s};
use crate::gui::simple_action;
use crate::gui::{Shared, chip, copy_text, dialogs};
use crate::Chip;
use keyhole::api::{self, Action};
use keyhole::state::App;
use keyhole::sys::software::SoftwareRow;

pub const COLUMNS: &[ColDef] = &[
    c("name", "Name", 340.0, false, "Program name. Click to sort."),
    c("version", "Version", 140.0, false, "Installed version."),
    c("publisher", "Publisher", 240.0, false, "Who published the program according to its uninstall entry. Click to sort."),
    c("installed", "Installed", 110.0, false, "Install date if recorded."),
    c("size", "Size", 90.0, true, "Estimated size on disk as reported by the installer. Click to sort largest first."),
    c("location", "Location", 300.0, false, "Install folder if recorded."),
    c("scope", "Scope", 150.0, false, "All users, the signed in user, or another user's profile."),
];

fn columns(_st: &ListState) -> &'static [ColDef] {
    COLUMNS
}

fn default_sort(_st: &ListState) -> (&'static str, bool) {
    ("name", false)
}

pub static KIND: Kind = Kind {
    name: "software",
    title: "Installed software",
    placeholder: ("Filter programs", "Show only programs whose name, publisher, version or location contains this text"),
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
    ListData::Software(api::software())
}

fn render(ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Software(list) = data else { return Rendered::default() };
    let _ = ctx;
    let filter = input.filter.clone();
    let sort = input.sort.clone();
    let today = crate::gui::rows::now_ms();
    let recent = |r: &keyhole::sys::software::SoftwareRow| -> bool {
        let mut parts = r.installed.split('-').filter_map(|p| p.parse::<i64>().ok());
        match (parts.next(), parts.next(), parts.next()) {
            (Some(y), Some(m), Some(d)) => today - keyhole::sys::updates::days_from_civil(y, m, d) * 86_400_000 <= 30 * 86_400_000,
            _ => false,
        }
    };
    let per_user = |r: &keyhole::sys::software::SoftwareRow| -> bool { !r.scope.starts_with("All users") };
    let large = |r: &keyhole::sys::software::SoftwareRow| -> bool { r.size >= 500 << 20 };
    let third_party = |r: &keyhole::sys::software::SoftwareRow| -> bool { !super::is_ms(&r.publisher) };
    let no_uninstall = |r: &keyhole::sys::software::SoftwareRow| -> bool { r.uninstall.trim().is_empty() };
    let chips: Vec<Chip> = vec![
        chip("", "All", Some(list.len()), "Every program registered in Programs and Features, from every user hive"),
        chip("recent", "Installed in 30 days", Some(list.iter().filter(|r| recent(r)).count()), "What changed recently, the first question after a new problem"),
        chip("thirdparty", "Not Microsoft", Some(list.iter().filter(|r| third_party(r)).count()), "Programs from any publisher other than Microsoft"),
        chip("user", "Per user installs", Some(list.iter().filter(|r| per_user(r)).count()), "Installed into a user profile rather than for the whole machine. These do not show in Programs and Features for other users"),
        chip("large", "Over 500 MB", Some(list.iter().filter(|r| large(r)).count()), "The biggest programs by their own size estimate"),
        chip("nouninstall", "No uninstaller", Some(list.iter().filter(|r| no_uninstall(r)).count()), "Entries without an uninstall command, usually leftovers or manually registered software"),
    ];
    let chip_ok = |r: &keyhole::sys::software::SoftwareRow| match input.chip.as_str() {
        "recent" => recent(r),
        "thirdparty" => third_party(r),
        "user" => per_user(r),
        "large" => large(r),
        "nouninstall" => no_uninstall(r),
        _ => true,
    };
    let mut shown = (0..list.len()).filter(|&i| chip_ok(&list[i]) && (filter.is_empty() || format!("{} {} {} {} {}", list[i].name, list[i].publisher, list[i].version, list[i].location, list[i].scope).to_lowercase().contains(&filter))).collect();
    sort_indices(list, &mut shown, &sort.0, sort.1, |r, k| match k {
        "name" => sv_s(&r.name),
        "version" => sv_s(&r.version),
        "publisher" => sv_s(&r.publisher),
        "installed" => sv_s(&r.installed),
        "size" => sv_n(r.size as f64),
        "location" => sv_s(&r.location),
        "scope" => sv_s(&r.scope),
        _ => sv_s(""),
    });
    let count = shown_of(shown.len(), list.len(), "programs");
    let rows = shown
        .iter()
        .map(|&i| {
            let r = &list[i];
            simple_row(i as i32, vec![cell(&r.name, 0), cell(&r.version, 0), cell(&r.publisher, 0), cell(&r.installed, 0), num(&bytes(r.size)), cell(&r.location, 0), cell(&r.scope, 0)], 0, &r.name)
        })
        .collect();
    let empty = ("\u{E7B8}".into(), nothing_matches(&filter), String::new());
    Rendered { chips, rows, shown, count, empty }
}

fn double(_ctx: &Shared, _src: usize) {}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let d = {
        let st = ctx.st.borrow();
        let ListData::Software(list) = &st.lists.data else { return };
        let Some(row) = list.get(src) else { return };
        row.clone()
    };
    software_menu(ctx, x, y, &d);
}

fn software_menu(ctx: &Shared, x: f32, y: f32, d: &SoftwareRow) {
    let has_loc = is_file_path(&d.location);
    let loc = d.location.trim_end_matches('\\').to_string();
    let items = vec![
        MenuItem::new("copy", "Copy name", { let v = d.name.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("copyVer", "Copy version", { let v = d.version.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.version.is_empty()),
        MenuItem::new("copyPub", "Copy publisher", { let v = d.publisher.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.publisher.is_empty()),
        MenuItem::new("copyLoc", "Copy install location", { let v = d.location.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.location.is_empty()),
        MenuItem::sep(),
        MenuItem::new("loc", "Open install folder", { let l = loc.clone(); move |ctx| simple_action(ctx, Action::OpenFolder(format!("{}\\x", l)), "Opened folder", None) }).disabled(!has_loc),
        MenuItem::new("running", "Show running processes from its folder", { let l = loc.clone(); move |ctx| crate::gui::tree::filter_tree(ctx, &l) }).disabled(!has_loc),
        MenuItem::new("reg", "Open registry entry in Registry Editor", { let k = d.key.clone(); move |ctx| simple_action(ctx, Action::OpenRegistryKey(k), "Opened Registry Editor", None) }).disabled(d.key.is_empty()),
        MenuItem::new("apps", "Open Apps & features", |ctx| simple_action(ctx, Action::OpenTool("apps".into()), "Opened Apps & features", None)),
        MenuItem::sep(),
        MenuItem::new("modify", "Modify / repair…", { let n = d.name.clone(); let cmd = d.modify.clone(); move |ctx| { let n2 = n.clone(); let c2 = cmd.clone(); dialogs::confirm(ctx, &format!("Modify {}?", n), &format!("This launches the installer's modify or repair mode for {}.", n), "Modify", false, Box::new(move |ctx| simple_action(ctx, Action::Uninstall(c2), &format!("Launched installer for {}", n2), None))); } }).disabled(d.modify.is_empty()),
        MenuItem::new("uninstall", "Uninstall…", { let n = d.name.clone(); let cmd = d.uninstall.clone(); move |ctx| { let n2 = n.clone(); let c2 = cmd.clone(); dialogs::confirm(ctx, &format!("Uninstall {}?", n), &format!("This launches the uninstaller for {}. The uninstaller may ask its own questions.", n), "Uninstall", true, Box::new(move |ctx| simple_action(ctx, Action::Uninstall(c2), &format!("Launched uninstaller for {}", n2), None))); } }).danger().disabled(d.uninstall.is_empty()),
    ];
    menus::show(ctx, x, y, &d.name, items);
}

fn button(ctx: &Shared, id: &str) {
    let _ = (ctx, id);
}

fn export_csv(data: &ListData, shown: &[usize], _st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Software(l) = data else { return None };
    Some(("keyhole-software", csv(&shown.iter().map(|&i| { let r = &l[i]; vec![r.name.clone(), r.version.clone(), r.publisher.clone(), r.installed.clone(), if r.size > 0 { r.size.to_string() } else { String::new() }, r.location.clone(), r.scope.clone(), r.uninstall.clone(), r.modify.clone(), r.key.clone()] }).collect::<Vec<_>>(), &["Name", "Version", "Publisher", "Installed", "Size", "Location", "Scope", "Uninstall command", "Modify command", "Registry key"])))
}
