use super::{Kind, RenderInput, Rendered, plural, refresh_after};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{self, ListData, ListState, nothing_matches};
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, dot_cell, simple_row, sort_indices, sv_b, sv_s};
use crate::gui::{batch_action, simple_action};
use crate::gui::{Shared, chip, copy_text, dialogs};
use crate::Chip;
use keyhole::api::{self, Action};
use keyhole::state::App;
use keyhole::sys::firewall::{FirewallRow, RuleKey};
use std::collections::HashMap;

pub const COLUMNS: &[ColDef] = &[
    c("display", "Rule", 280.0, false, "Rule name. Hover for the group and description. Click to sort."),
    c("direction", "Direction", 90.0, false, "Inbound (incoming connections) or outbound (connections this computer makes). Click to sort."),
    c("action", "Action", 72.0, false, "Allow or block. Click to sort."),
    c("enabled", "Enabled", 76.0, false, "Whether the rule is currently in effect."),
    c("protocol", "Protocol", 80.0, false, "Protocol the rule matches."),
    c("local_ports", "Local ports", 100.0, false, "Local ports the rule matches. Blank means any."),
    c("remote_ports", "Remote ports", 100.0, false, "Remote ports the rule matches. Blank means any."),
    c("remote_addresses", "Remote addresses", 150.0, false, "Remote addresses or ranges the rule matches. Blank means any."),
    c("profiles", "Profiles", 124.0, false, "Network profiles the rule applies to: Domain, Private, Public or All."),
    c("program", "Program", 260.0, false, "Program or service the rule applies to. Blank means any program."),
];

fn columns(_st: &ListState) -> &'static [ColDef] {
    COLUMNS
}

fn default_sort(_st: &ListState) -> (&'static str, bool) {
    ("display", false)
}

pub static KIND: Kind = Kind {
    name: "firewall",
    title: "Firewall rules",
    placeholder: ("Filter rules", "Show only rules whose name, group, program, ports, addresses or protocol contains this text"),
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
    vec![chip("add", "New rule…", None, "Add a Windows Firewall rule")]
}

fn refresh(app: &App, st: &ListState) -> ListData {
    let _ = (app, st);
    match api::firewall() { Ok(f) => ListData::Firewall(f.rows, f.profiles, String::new()), Err(e) => ListData::Firewall(Vec::new(), Vec::new(), e) }
}

fn render(ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Firewall(list, profiles, note) = data else { return Rendered::default() };
    let _ = ctx;
    let filter = input.filter.clone();
    let chip_id = input.chip.clone();
    let sort = input.sort.clone();
    
    let matches = |id: &str, r: &FirewallRow| match id {
        "enabled" => r.enabled,
        "block" => r.action == "Block",
        "in" => r.direction == "Inbound",
        "out" => r.direction == "Outbound",
        "program" => !r.program.is_empty(),
        "remote" => !r.remote_addresses.is_empty(),
        "keyhole" => r.keyhole,
        _ => true,
    };
    let chips = vec![
        chip("", "All", Some(list.len()), "Every firewall rule"),
        chip("enabled", "Enabled", Some(list.iter().filter(|r| r.enabled).count()), "Rules currently in effect"),
        chip("block", "Block", Some(list.iter().filter(|r| r.action == "Block").count()), "Rules that block traffic"),
        chip("in", "Inbound", Some(list.iter().filter(|r| r.direction == "Inbound").count()), "Rules for connections coming in to this computer"),
        chip("out", "Outbound", Some(list.iter().filter(|r| r.direction == "Outbound").count()), "Rules for connections this computer makes"),
        chip("program", "Per program", Some(list.iter().filter(|r| !r.program.is_empty()).count()), "Rules tied to a specific program"),
        chip("remote", "Remote addresses", Some(list.iter().filter(|r| !r.remote_addresses.is_empty()).count()), "Rules limited to specific remote addresses"),
        chip("keyhole", "Made by Keyhole", Some(list.iter().filter(|r| r.keyhole).count()), "Rules created with Keyhole's New rule form"),
    ];
    let mut shown = (0..list.len()).filter(|&i| matches(&chip_id, &list[i]) && (filter.is_empty() || format!("{} {} {} {} {} {} {} {} {} {} {}", list[i].name, list[i].display, list[i].group, list[i].description, list[i].program, list[i].service, list[i].local_ports, list[i].remote_ports, list[i].remote_addresses, list[i].protocol, list[i].direction).to_lowercase().contains(&filter))).collect();
    sort_indices(list, &mut shown, &sort.0, sort.1, |r, k| match k {
        "display" => sv_s(if r.display.is_empty() { &r.name } else { &r.display }),
        "direction" => sv_s(&r.direction),
        "action" => sv_s(&r.action),
        "enabled" => sv_b(r.enabled),
        "protocol" => sv_s(&r.protocol),
        "local_ports" => sv_s(&r.local_ports),
        "remote_ports" => sv_s(&r.remote_ports),
        "remote_addresses" => sv_s(&r.remote_addresses),
        "profiles" => sv_s(&r.profiles),
        "program" => sv_s(&r.program),
        _ => sv_s(""),
    });
    let enabled = list.iter().filter(|r| r.enabled).count();
    let active: Vec<String> = profiles
        .iter()
        .filter(|p| p.active)
        .map(|p| {
            format!(
                "{} profile: {}",
                p.name,
                if p.block_all_inbound { "firewall on, all inbound blocked".to_string() } else if p.enabled { format!("firewall on, inbound {}, outbound {}", p.inbound.to_lowercase(), p.outbound.to_lowercase()) } else { "firewall OFF".to_string() }
            )
        })
        .collect();
    let count: String = format!("{}, {} enabled{}{}", shown_of(shown.len(), list.len(), "rules"), enabled, if active.is_empty() { String::new() } else { format!("  ·  {}", active.join("  ·  ")) }, if note.is_empty() { String::new() } else { format!("  ·  {}", note) });
    let rows = shown
        .iter()
        .map(|&i| {
            let r = &list[i];
            let prog = if r.program.is_empty() { if r.service.is_empty() { String::new() } else { format!("service {}", r.service) } } else { r.program.clone() };
            let tip = [if r.display.is_empty() { r.name.clone() } else { r.display.clone() }, if !r.display.is_empty() && r.display != r.name { r.name.clone() } else { String::new() }, if r.group.is_empty() { String::new() } else { format!("Group: {}", r.group) }, r.description.clone()].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join("\n");
            simple_row(
                i as i32,
                vec![
                    cell(if r.display.is_empty() { &r.name } else { &r.display }, 0),
                    cell(&r.direction, 0),
                    cell(&r.action, if r.action == "Block" { 4 } else { 0 }),
                    dot_cell(if r.enabled { "on" } else { "off" }, if r.enabled { 2 } else { 1 }),
                    cell(&r.protocol, 0),
                    cell(&r.local_ports, 0),
                    cell(&r.remote_ports, 0),
                    cell(&r.remote_addresses, 0),
                    cell(&r.profiles, 0),
                    cell(&prog, 0),
                ],
                if r.enabled { 0 } else { 1 },
                &tip,
            )
        })
        .collect();
    let empty = ("\u{EA18}".into(), nothing_matches(&filter), note.clone());
    Rendered { chips, rows, shown, count, empty }
}

fn double(_ctx: &Shared, _src: usize) {}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let d = {
        let st = ctx.st.borrow();
        let ListData::Firewall(list, ..) = &st.lists.data else { return };
        let Some(row) = list.get(src) else { return };
        row.clone()
    };
    firewall_menu(ctx, x, y, &d);
}

fn firewall_menu(ctx: &Shared, x: f32, y: f32, d: &FirewallRow) {
    let label = if d.display.is_empty() { d.name.clone() } else { d.display.clone() };
    let key = fw_key(d);
    let items = vec![
        MenuItem::new("enable", "Enable rule", { let k = key.clone(); move |ctx| simple_action(ctx, Action::FirewallEnabled { key: k, enabled: true }, "Enabled rule", refresh_after("firewall")) }).disabled(d.enabled),
        MenuItem::new("disable", "Disable rule", { let k = key.clone(); let l = label.clone(); move |ctx| { let k2 = k.clone(); dialogs::confirm(ctx, "Disable firewall rule?", &format!("This disables {}. Traffic it was controlling will follow other rules or the default policy.", l), "Disable", true, Box::new(move |ctx| simple_action(ctx, Action::FirewallEnabled { key: k2, enabled: false }, "Disabled rule", refresh_after("firewall")))); } }).danger().disabled(!d.enabled),
        MenuItem::sep(),
        MenuItem::new("copy", "Copy rule name", { let v = label.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("prog", "Copy program path", { let v = d.program.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.program.is_empty()),
        MenuItem::new("ports", "Copy local ports", { let v = d.local_ports.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.local_ports.is_empty()),
        MenuItem::new("raddr", "Copy remote addresses", { let v = d.remote_addresses.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.remote_addresses.is_empty()),
        MenuItem::sep(),
        MenuItem::new("only", "Show only rules for this program", { let p = d.program.clone(); move |ctx| lists::set_filter_and_show(ctx, "firewall", &p) }).disabled(d.program.is_empty()),
        MenuItem::new("group", "Show only this group", { let g = d.group.clone(); move |ctx| lists::set_filter_and_show(ctx, "firewall", &g) }).disabled(d.group.is_empty()),
        MenuItem::new("reveal", "Show program in Explorer", { let p = d.program.clone(); move |ctx| simple_action(ctx, Action::Reveal(p), "Revealed", None) }).disabled(!d.program.chars().next().map(|c| c.is_ascii_alphabetic() || c == '%').unwrap_or(false)),
        MenuItem::new("running", "Find running process", { let p = d.program.clone(); move |ctx| crate::gui::tree::find_running(ctx, &p) }).disabled(d.program.is_empty()),
        MenuItem::new("console", "Open Windows Firewall console", |ctx| simple_action(ctx, Action::OpenTool("firewall".into()), "Opened Windows Firewall", None)),
        MenuItem::sep(),
        MenuItem::new("add", "New rule…", |ctx| add_firewall_rule(ctx, HashMap::new())),
        MenuItem::new("addprog", "New rule for this program…", {
            let d = d.clone();
            move |ctx| {
                let mut preset = HashMap::new();
                preset.insert("program".to_string(), d.program.clone());
                preset.insert("direction".to_string(), if d.direction == "Outbound" { "out".into() } else { "in".into() });
                preset.insert("remoteAddresses".to_string(), d.remote_addresses.clone());
                preset.insert("remotePorts".to_string(), d.remote_ports.clone());
                preset.insert("localPorts".to_string(), d.local_ports.clone());
                let protocol = d.protocol.to_lowercase();
                preset.insert("protocol".to_string(), if ["tcp", "udp", "icmpv4", "icmpv6"].contains(&protocol.as_str()) { protocol } else { "any".into() });
                add_firewall_rule(ctx, preset);
            }
        })
        .disabled(d.program.is_empty()),
        MenuItem::new("del", "Delete rule", { let k = key.clone(); let l = label.clone(); let dir = d.direction.clone(); let act = d.action.clone(); move |ctx| { let k2 = k.clone(); dialogs::confirm(ctx, "Delete firewall rule?", &format!("This permanently removes {} ({}, {}). Traffic it was controlling will follow other rules or the default policy.", l, dir, act), "Delete rule", true, Box::new(move |ctx| simple_action(ctx, Action::FirewallDelete(k2), "Deleted rule", refresh_after("firewall")))); } }).danger(),
    ];
    menus::show(ctx, x, y, &label, items);
}

fn fw_key(d: &FirewallRow) -> RuleKey {
    RuleKey { name: d.name.clone(), direction: d.direction.clone(), action: d.action.clone(), protocol: d.protocol.clone(), local_ports: d.local_ports.clone(), remote_ports: d.remote_ports.clone(), remote_addresses: d.remote_addresses.clone(), program: d.program.clone(), profiles: d.profiles.clone() }
}

pub fn add_firewall_rule(ctx: &Shared, preset: HashMap<String, String>) {
    let g = |k: &str, d: &str| preset.get(k).cloned().unwrap_or_else(|| d.to_string());
    let fields = vec![
        dialogs::FieldSpec::text("name", "Name", &g("name", ""), "Rule name", true),
        dialogs::FieldSpec::select("direction", "Direction", &g("direction", "in"), &[("in", "Inbound"), ("out", "Outbound")]),
        dialogs::FieldSpec::select("action", "Action", &g("action", "block"), &[("block", "Block"), ("allow", "Allow")]),
        dialogs::FieldSpec::select("protocol", "Protocol", &g("protocol", "any"), &[("any", "Any"), ("tcp", "TCP"), ("udp", "UDP"), ("icmpv4", "ICMPv4"), ("icmpv6", "ICMPv6")]),
        dialogs::FieldSpec::text("localPorts", "Local ports", &g("localPorts", ""), "Any (e.g. 80, 443, 8000-8100)", false).only_when("protocol", &["tcp", "udp"], "Ports apply to TCP and UDP only"),
        dialogs::FieldSpec::text("remotePorts", "Remote ports", &g("remotePorts", ""), "Any (e.g. 53)", false).only_when("protocol", &["tcp", "udp"], "Ports apply to TCP and UDP only"),
        dialogs::FieldSpec::text("remoteAddresses", "Remote addresses", &g("remoteAddresses", ""), "Any (e.g. 10.0.0.0/8, 203.0.113.5)", false),
        dialogs::FieldSpec::text("program", "Program", &g("program", ""), "Any program (or the path to an .exe)", false),
        dialogs::FieldSpec::select("profiles", "Profiles", &g("profiles", "all"), &[("all", "All"), ("domain", "Domain"), ("private", "Private"), ("public", "Public"), ("domain,private", "Domain and Private"), ("domain,public", "Domain and Public"), ("private,public", "Private and Public")]),
        dialogs::FieldSpec::check("enabled", "Enable the rule immediately", g("enabled", "true") != "false"),
    ];
    dialogs::form(
        ctx,
        "New firewall rule",
        "Adds a rule to Windows Firewall. Leave ports and addresses empty to match any.",
        fields,
        "Add rule",
        Box::new(|ctx, v| {
            let get = |k: &str| v.get(k).cloned().unwrap_or_default();
            let rule = keyhole::sys::firewall::NewRule {
                name: get("name"),
                description: String::new(),
                direction: get("direction"),
                action: get("action"),
                protocol: get("protocol"),
                local_ports: get("localPorts"),
                remote_ports: get("remotePorts"),
                remote_addresses: get("remoteAddresses"),
                program: get("program"),
                profiles: get("profiles"),
                enabled: get("enabled") != "false",
            };
            if let Err(e) = keyhole::sys::firewall::validate(&rule) {
                crate::gui::bad(ctx, &format!("Cannot add the rule: {}", e));
                add_firewall_rule(ctx, v);
                return;
            }
            let name = rule.name.clone();
            simple_action(ctx, Action::FirewallAdd(rule), &format!("Added rule {}", name), refresh_after("firewall"));
        }),
    );
}

fn button(ctx: &Shared, id: &str) {
    if id == "add" {
        add_firewall_rule(ctx, HashMap::new());
    }
}

fn export_csv(data: &ListData, shown: &[usize], _st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Firewall(l, _, _) = data else { return None };
    Some(("keyhole-firewall", csv(&shown.iter().map(|&i| { let r = &l[i]; vec![if r.display.is_empty() { r.name.clone() } else { r.display.clone() }, r.name.clone(), r.group.clone(), r.direction.clone(), r.action.clone(), r.enabled.to_string(), r.protocol.clone(), r.local_ports.clone(), r.remote_ports.clone(), r.remote_addresses.clone(), r.program.clone(), r.service.clone(), r.profiles.clone(), r.description.clone()] }).collect::<Vec<_>>(), &["Rule", "Internal name", "Group", "Direction", "Action", "Enabled", "Protocol", "Local ports", "Remote ports", "Remote addresses", "Program", "Service", "Profiles", "Description"])))
}

fn multi(ctx: &Shared, srcs: &[usize], x: f32, y: f32) {
    let rows: Vec<FirewallRow> = {
        let st = ctx.st.borrow();
        let ListData::Firewall(list, ..) = &st.lists.data else { return };
        srcs.iter().filter_map(|&i| list.get(i).cloned()).collect()
    };
    if rows.is_empty() {
        return;
    }
    let n = rows.len();
    let label = |r: &FirewallRow| if r.display.is_empty() { r.name.clone() } else { r.display.clone() };
    let to_enable: Vec<(String, Action)> = rows.iter().filter(|r| !r.enabled).map(|r| (label(r), Action::FirewallEnabled { key: fw_key(r), enabled: true })).collect();
    let to_disable: Vec<(String, Action)> = rows.iter().filter(|r| r.enabled).map(|r| (label(r), Action::FirewallEnabled { key: fw_key(r), enabled: false })).collect();
    let to_delete: Vec<(String, Action)> = rows.iter().map(|r| (label(r), Action::FirewallDelete(fw_key(r)))).collect();
    let names: Vec<String> = rows.iter().take(6).map(label).collect();
    let listing = if n > 6 { format!("{} and {} more", names.join(", "), n - 6) } else { names.join(", ") };
    let items = vec![
        MenuItem::new("enable", &format!("Enable {}", plural(to_enable.len(), "rule", "rules")), { let acts = to_enable.clone(); move |ctx| batch_action(ctx, acts, "Enabled", ("rule", "rules"), refresh_after("firewall")) }).disabled(to_enable.is_empty()),
        MenuItem::new("disable", &format!("Disable {}", plural(to_disable.len(), "rule", "rules")), {
            let acts = to_disable.clone();
            let listing = listing.clone();
            move |ctx| {
                let acts = acts.clone();
                dialogs::confirm(ctx, "Disable firewall rules?", &format!("This disables {}: {}. Traffic they were controlling will follow other rules or the default policy.", plural(acts.len(), "rule", "rules"), listing), "Disable", true, Box::new(move |ctx| batch_action(ctx, acts, "Disabled", ("rule", "rules"), refresh_after("firewall"))));
            }
        })
        .danger()
        .disabled(to_disable.is_empty()),
        MenuItem::sep(),
        MenuItem::new("copy", "Copy rule names", { let v = rows.iter().map(label).collect::<Vec<_>>().join("\n"); move |ctx| copy_text(ctx, &v) }),
        MenuItem::sep(),
        MenuItem::new("del", &format!("Delete {}", plural(n, "rule", "rules")), {
            let acts = to_delete;
            move |ctx| {
                let acts = acts.clone();
                dialogs::confirm(ctx, "Delete firewall rules?", &format!("This permanently removes {}: {}. Traffic they were controlling will follow other rules or the default policy.", plural(acts.len(), "rule", "rules"), listing), "Delete rules", true, Box::new(move |ctx| batch_action(ctx, acts, "Deleted", ("rule", "rules"), refresh_after("firewall"))));
            }
        })
        .danger(),
    ];
    menus::show(ctx, x, y, &format!("{} selected", plural(n, "rule", "rules")), items);
}
