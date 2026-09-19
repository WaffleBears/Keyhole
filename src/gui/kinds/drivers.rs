use super::{Kind, RenderInput, Rendered, is_ms, refresh_after, unsigned};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{ListData, ListState, nothing_matches};
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, dot_cell, sig_text, sig_tone, simple_row, sort_indices, sv_s};
use crate::gui::simple_action;
use crate::gui::{Shared, chip, copy_text, dialogs};
use crate::Chip;
use keyhole::api::{self, Action};
use keyhole::state::App;
use keyhole::sys::drivers::DriverRow;

pub const COLUMNS: &[ColDef] = &[
    c("name", "Driver", 180.0, false, "Driver service name. Hover for the display name and description. Click to sort."),
    c("state", "State", 100.0, false, "Whether the driver is loaded in the kernel right now. Click to sort."),
    c("start_type", "Start", 90.0, false, "When Windows loads it: Boot, System, Automatic, Manual or Disabled. Click to sort."),
    c("trust", "Signature", 100.0, false, "Authenticode status of the driver file."),
    c("version", "Version", 110.0, false, "File version from the driver binary. Compare it with the vendor download when a driver misbehaves."),
    c("company", "Company", 190.0, false, "Publisher from the version resource."),
    c("path", "Path", 300.0, false, "File the driver loads from."),
];

fn columns(_st: &ListState) -> &'static [ColDef] {
    COLUMNS
}

fn default_sort(_st: &ListState) -> (&'static str, bool) {
    ("name", false)
}

pub static KIND: Kind = Kind {
    name: "drivers",
    title: "Drivers",
    placeholder: ("Filter drivers", "Show only drivers whose name, description, company or path contains this text"),
    columns,
    table: super::same_table,
    segment: super::no_segment,
    default_sort,
    buttons,
    refresh,
    render,
    menu,
    multi: None,
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
    ListData::Drivers(api::drivers(app))
}

fn render(ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Drivers(list) = data else { return Rendered::default() };
    let _ = ctx;
    let filter = input.filter.clone();
    let chip_id = input.chip.clone();
    let sort = input.sort.clone();
    
    let matches = |id: &str, r: &DriverRow| match id {
        "running" => r.running,
        "stopped" => !r.running,
        "unsigned" => unsigned(&r.trust),
        "nonms" => !is_ms(&r.company),
        "disabled" => r.start_type == "Disabled",
        _ => true,
    };
    let chips = vec![
        chip("", "All", Some(list.len()), "Every installed kernel and file system driver"),
        chip("running", "Loaded", Some(list.iter().filter(|r| r.running).count()), "Drivers currently loaded in the kernel"),
        chip("stopped", "Not loaded", Some(list.iter().filter(|r| !r.running).count()), "Installed but not running right now"),
        chip("unsigned", "Not signed", Some(list.iter().filter(|r| unsigned(&r.trust)).count()), "Drivers without a valid signature"),
        chip("nonms", "Not Microsoft", Some(list.iter().filter(|r| !is_ms(&r.company)).count()), "Drivers from other publishers"),
        chip("disabled", "Disabled", Some(list.iter().filter(|r| r.start_type == "Disabled").count()), "Drivers that will not load at boot"),
    ];
    let mut shown = (0..list.len()).filter(|&i| matches(&chip_id, &list[i]) && (filter.is_empty() || format!("{} {} {} {} {} {} {}", list[i].name, list[i].display, list[i].description, list[i].company, list[i].path, list[i].state, list[i].start_type).to_lowercase().contains(&filter))).collect();
    sort_indices(list, &mut shown, &sort.0, sort.1, |r, k| match k {
        "name" => sv_s(&r.name),
        "state" => sv_s(&r.state),
        "start_type" => sv_s(&r.start_type),
        "trust" => sv_s(&r.trust),
        "version" => sv_s(&r.version),
        "company" => sv_s(&r.company),
        "path" => sv_s(&r.path),
        _ => sv_s(""),
    });
    let loaded = list.iter().filter(|r| r.running).count();
    let count: String = format!("{}, {} loaded", shown_of(shown.len(), list.len(), "drivers"), loaded);
    let rows = shown
        .iter()
        .map(|&i| {
            let r = &list[i];
            let dot = if r.running { 2 } else if r.state == "Stopped" || r.state == "Not registered" { 1 } else { 3 };
            simple_row(
                i as i32,
                vec![
                    cell(&r.name, 0),
                    dot_cell(&r.state, dot),
                    cell(&r.start_type, if r.start_type == "Disabled" { 7 } else { 0 }),
                    cell(&sig_text(&r.trust), sig_tone(&r.trust)),
                    cell(&r.version, 0),
                    cell(&r.company, 0),
                    cell(&r.path, 0),
                ],
                if r.running { 0 } else { 1 },
                &format!("{}{}{}\n{} driver", r.name, if !r.display.is_empty() && r.display != r.name { format!("\n{}", r.display) } else { String::new() }, if r.description.is_empty() { String::new() } else { format!("\n{}", r.description) }, r.kind),
            )
        })
        .collect();
    let empty = ("\u{E975}".into(), nothing_matches(&filter), String::new());
    Rendered { chips, rows, shown, count, empty }
}

fn double(_ctx: &Shared, _src: usize) {}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let d = {
        let st = ctx.st.borrow();
        let ListData::Drivers(list) = &st.lists.data else { return };
        let Some(row) = list.get(src) else { return };
        row.clone()
    };
    driver_menu(ctx, x, y, &d);
}

fn driver_menu(ctx: &Shared, x: f32, y: f32, d: &DriverRow) {
    let is_file = is_file_path(&d.path);
    let name = d.name.clone();
    let act = |op: &'static str, verb: &'static str, body: Option<String>| {
        let name = name.clone();
        move |ctx: &Shared| {
            let name = name.clone();
            let n2 = name.clone();
            let run = move |ctx: &Shared| simple_action(ctx, Action::Service { name: n2.clone(), op: op.into() }, &format!("{} {}", verb, n2), refresh_after("drivers"));
            match &body {
                Some(b) => dialogs::confirm(ctx, &format!("{} {}?", verb, name), b, verb, true, Box::new(run)),
                None => run(ctx),
            }
        }
    };
    let early = d.start_type == "Boot" || d.start_type == "System";
    let early_tip = if early { "Boot and System start drivers load before Windows itself, so Keyhole leaves them alone. The wrong change makes the machine unbootable" } else { "" };
    let mut items = vec![
        MenuItem::new("disable", "Disable at boot", act("disable", "Disabled", Some(format!("This sets the {} driver to Disabled so it will not load at boot. Disabling the wrong driver can prevent Windows from starting.", d.name)))).danger().disabled(d.start_type == "Disabled" || early).tip(early_tip),
        MenuItem::new("manual", "Set to load on demand", act("enableManual", "Set to manual", None)).disabled(d.start_type == "Manual" || early).tip(early_tip),
        MenuItem::sep(),
        MenuItem::new("reveal", "Show file in Explorer", { let p = d.path.clone(); move |ctx| simple_action(ctx, Action::Reveal(p), "Revealed", None) }).disabled(!is_file),
        MenuItem::new("copyName", "Copy driver name", { let v = d.name.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("copy", "Copy path", { let v = d.path.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.path.is_empty()),
    ];
    items.extend(menus::file_items(&d.path));
    items.push(MenuItem::new("reg", "Open in Registry Editor", { let k = format!("HKLM\\SYSTEM\\CurrentControlSet\\Services\\{}", d.name); move |ctx| simple_action(ctx, Action::OpenRegistryKey(k), "Opened Registry Editor", None) }));
    items.push(MenuItem::new("console", "Open Device Manager", |ctx| simple_action(ctx, Action::OpenTool("devices".into()), "Opened Device Manager", None)));
    menus::show(ctx, x, y, &format!("{} ({} driver, {})", d.name, if d.kind.is_empty() { "kernel".to_string() } else { d.kind.to_lowercase() }, d.state.to_lowercase()), items);
}

fn button(ctx: &Shared, id: &str) {
    let _ = (ctx, id);
}

fn export_csv(data: &ListData, shown: &[usize], _st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Drivers(l) = data else { return None };
    Some(("keyhole-drivers", csv(&shown.iter().map(|&i| { let r = &l[i]; vec![r.name.clone(), r.display.clone(), r.state.clone(), r.start_type.clone(), r.kind.clone(), r.trust.clone(), r.version.clone(), r.company.clone(), r.path.clone(), r.description.clone()] }).collect::<Vec<_>>(), &["Driver", "Display name", "State", "Start", "Type", "Signature", "Version", "Company", "Path", "Description"])))
}
