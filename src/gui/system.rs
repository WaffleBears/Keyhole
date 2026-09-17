use super::format::*;
use super::menus::{self, MenuItem};
use super::rows::{doc_default, kv, section};
use super::{simple_action};
use super::{Shared, copy_text, finder, model, spawn, ss, ui};
use crate::{Badge, DocItem};
use keyhole::api::Action;
use keyhole::sys::sysinfo::SysInfo;
use slint::Model;
use std::cell::RefCell;
use std::rc::Rc;

thread_local! {
    static INFO: RefCell<Option<Rc<SysInfo>>> = const { RefCell::new(None) };
    static ENV_FILTER: RefCell<String> = const { RefCell::new(String::new()) };
}

pub fn wire(ctx: &Shared) {
    let u = ui(ctx);
    {
        let ctx = ctx.clone();
        u.on_doc_right(move |which, i, x, y| {
            if which == "env" {
                env_menu(&ctx, i as usize, x, y);
            } else {
                super::detail::detail_doc_menu(&ctx, i as usize, x, y);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_doc_button(move |_which, id| {
            let tool = match id.as_str() {
                "Event Viewer" => "eventlog",
                "Device Manager" => "devices",
                "Services" => "services",
                "Task Scheduler" => "tasks",
                "Windows Firewall" => "firewall",
                "Apps & features" => "apps",
                _ => return,
            };
            simple_action(&ctx, Action::OpenTool(tool.into()), &format!("Opened {}", id), None);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_env_filter_edited(move |text| {
            ENV_FILTER.with(|f| *f.borrow_mut() = text.to_string());
            render(&ctx);
        });
    }
}

pub fn refresh_environment(ctx: &Shared) {
    spawn(ctx, |_| keyhole::api::environment(), |ctx, info| {
        INFO.with(|i| *i.borrow_mut() = Some(Rc::new(info)));
        if ctx.st.borrow().mode == "environment" {
            render(ctx);
        }
    });
}

fn render(ctx: &Shared) {
    let Some(d) = INFO.with(|i| i.borrow().clone()) else { return };
    let env_filter = ENV_FILTER.with(|f| f.borrow().to_lowercase());
    ui(ctx).set_env_doc(model(build(&d, &env_filter)));
}

fn build(d: &SysInfo, env_filter: &str) -> Vec<DocItem> {
    let mut items: Vec<DocItem> = Vec::new();
    let tools = ["Event Viewer", "Device Manager", "Services", "Task Scheduler", "Windows Firewall", "Apps & features"];
    items.push(DocItem { kind: 5, badges: model(tools.iter().map(|t| Badge { text: ss(t), kind: 0, tip: ss(&format!("Open the Windows {} console", t)) }).collect()), ..doc_default() });
    let push = |items: &mut Vec<DocItem>, k: &str, v: String| {
        if !v.is_empty() {
            items.push(kv(k, &v));
        }
    };
    push(&mut items, "Operating system", d.os.clone());
    push(&mut items, "Computer name", format!("{}  ·  {}", d.host, if d.domain.is_empty() { "not joined to a domain".to_string() } else { d.domain.clone() }));
    push(&mut items, "Model", d.model.clone());
    push(&mut items, "BIOS", d.bios.clone());
    push(&mut items, "Firmware", d.firmware.clone());
    push(&mut items, "Restart pending", if d.reboot_pending.is_empty() { "no".to_string() } else { d.reboot_pending.join(". ") });
    push(&mut items, "Signed-in user", d.user.clone());
    push(&mut items, "Processor", format!("{}  ·  {} logical processors  ({})", d.cpu, d.cores, d.arch));
    push(&mut items, "Physical memory", format!("{}  ({} free)", bytes(d.mem_total), bytes(d.mem_avail)));
    push(&mut items, "Booted", format!("{}  (up {})", time_of(d.boot_unix_ms), fmt_uptime(d.uptime_ms)));
    push(&mut items, "Windows installed", time_of(d.install_unix_ms));

    items.push(section(&format!("Drives ({})", d.drives.len()), "right-click a drive for actions"));
    for v in &d.drives {
        let used = if v.total > 0 { v.total - v.free } else { 0 };
        let pct = if v.total > 0 { used as f64 / v.total as f64 } else { 0.0 };
        let tone = if pct >= 0.9 { 4 } else if pct >= 0.75 { 3 } else { 5 };
        let disk_info = if v.disk >= 0 { d.disks.iter().find(|x| x.number as i64 == v.disk) } else { None };
        let mut where_ = if !v.remote.is_empty() {
            format!("{}{}", v.remote, if v.provider.is_empty() { String::new() } else { format!(" · {}", v.provider) })
        } else if let Some(di) = disk_info {
            format!("Disk {} · {}{}", di.number, di.model, if di.bus.is_empty() { String::new() } else { format!(" · {}", di.bus) })
        } else {
            String::new()
        };
        if !v.note.is_empty() {
            where_ = if where_.is_empty() { v.note.clone() } else { format!("{} · {}", where_, v.note) };
        }
        let head = if v.letter.is_empty() { v.remote.clone() } else { format!("{} {}", v.letter, v.label) };
        let kind = format!("{}{}{}", v.kind, if v.fs.is_empty() { String::new() } else { format!(" · {}", v.fs) }, if v.letter.is_empty() { " · not mapped to a letter" } else { "" });
        let nums = if v.total > 0 { format!("{} free of {}  ·  {}% used", bytes(v.free), bytes(v.total), (pct * 100.0).round() as u64) } else if v.letter.is_empty() { "connected share".into() } else { "not ready".into() };
        items.push(DocItem { kind: 3, key: ss(head.trim()), value: ss(&kind), sub: ss(&where_), sub2: ss(&nums), pct: if v.total > 0 { pct as f32 } else { -1.0 }, tone, id: ss(&v.letter), id2: ss(&v.remote), ..doc_default() });
    }

    items.push(section(&format!("Physical disks ({})", d.disks.len()), "what the volumes above live on. iSCSI and USB disks show their bus"));
    for k in &d.disks {
        let mut bits = Vec::new();
        if !k.letters.is_empty() {
            bits.push(k.letters.join(", "));
        }
        if !k.bus.is_empty() {
            bits.push(k.bus.clone());
        }
        if k.size > 0 {
            bits.push(bytes(k.size));
        }
        if k.removable {
            bits.push("removable".into());
        }
        items.push(DocItem { kind: 1, key: ss(&format!("Disk {}", k.number)), value: ss(&format!("{}{}", k.model, if bits.is_empty() { String::new() } else { format!("  ·  {}", bits.join("  ·  ")) })), id: ss("disk"), ..doc_default() });
    }
    if d.disks.is_empty() {
        items.push(DocItem { kind: 4, value: ss("No physical disks could be opened."), ..doc_default() });
    }

    items.push(section(&format!("Network adapters ({})", d.adapters.len()), ""));
    for a in &d.adapters {
        let mut bits = Vec::new();
        if !a.addresses.is_empty() {
            bits.push(a.addresses.join(", "));
        }
        if !a.gateways.is_empty() {
            bits.push(format!("gateway {}", a.gateways.join(", ")));
        }
        if !a.dns.is_empty() {
            bits.push(format!("DNS {}", a.dns.join(", ")));
        }
        if !a.mac.is_empty() {
            bits.push(a.mac.clone());
        }
        let up = a.status == "Up";
        items.push(DocItem { kind: 8, key: ss(&format!("{} · {}", a.name, a.kind)), value: ss(&if bits.is_empty() { a.status.clone() } else { bits.join("  ·  ") }), tone: if up { 2 } else { 1 }, tip: ss(&a.description), id: ss("adapter"), ..doc_default() });
    }

    items.push(section(&format!("Environment variables ({})", d.env.len()), "as stored in the registry. System applies to everyone, User to the signed in account"));
    for e in &d.env {
        if env_filter.is_empty() || format!("{} {} {}", e.key, e.value, e.scope).to_lowercase().contains(env_filter) {
            let badge_kind = match e.scope.as_str() {
                "System" => 9,
                "User" => 10,
                _ => 3,
            };
            items.push(DocItem { kind: 1, key: ss(&e.key), value: ss(&e.value), badge: ss(&e.scope), badge_kind, id: ss("envvar"), id2: ss("mono"), ..doc_default() });
        }
    }
    items
}

fn env_menu(ctx: &Shared, index: usize, x: f32, y: f32) {
    let items = ui(ctx).get_env_doc();
    let Some(it) = items.row_data(index) else { return };
    match it.kind {
        3 => {
            let letter = it.id.to_string();
            let remote = it.id2.to_string();
            let root = if letter.is_empty() { remote.clone() } else { format!("{}\\", letter) };
            let entries = vec![
                MenuItem::new("open", "Open in Explorer", { let r = root.clone(); let l = if letter.is_empty() { remote.clone() } else { letter.clone() }; move |ctx| simple_action(ctx, Action::OpenFolder(format!("{}\\x", r)), &format!("Opened {}", l), None) }),
                MenuItem::new("who", if letter.is_empty() { "Find everything open on this share" } else { "Find everything open on this drive" }, { let r = root.clone(); move |ctx| finder::find_open(ctx, &r, true) }),
                MenuItem::new("whoShare", "Find everything open on the share itself", { let r = remote.clone(); move |ctx| finder::find_open(ctx, &r, true) }).disabled(remote.is_empty() || letter.is_empty()),
                MenuItem::new("copy", if letter.is_empty() { "Copy share path" } else { "Copy drive letter" }, { let r = root.clone(); move |ctx| copy_text(ctx, &r) }),
                MenuItem::new("copyRemote", "Copy share path", { let r = remote.clone(); move |ctx| copy_text(ctx, &r) }).disabled(remote.is_empty() || letter.is_empty()),
            ];
            menus::show(ctx, x, y, &if letter.is_empty() { remote } else { format!("Drive {}", letter) }, entries);
        }
        1 if it.id == "envvar" => {
            let name = it.key.to_string();
            let value = it.value.to_string();
            let scope = it.badge.to_string();
            let is_path = is_file_path(&value);
            let reg_key = match scope.as_str() {
                "System" => "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                "User" => "HKCU\\Environment",
                "Session" => "HKCU\\Volatile Environment",
                _ => "",
            }
            .to_string();
            let entries = vec![
                MenuItem::new("cn", "Copy name", { let v = name.clone(); move |ctx| copy_text(ctx, &v) }),
                MenuItem::new("cv", "Copy value", { let v = value.clone(); move |ctx| copy_text(ctx, &v) }).disabled(value.is_empty()),
                MenuItem::new("cb", "Copy NAME=value", { let v = format!("{}={}", name, value); move |ctx| copy_text(ctx, &v) }),
                MenuItem::new("cl", "Copy as one entry per line", { let v = value.split(';').filter(|s| !s.is_empty()).collect::<Vec<_>>().join("\n"); move |ctx| copy_text(ctx, &v) }).disabled(!value.contains(';')),
                MenuItem::sep(),
                MenuItem::new("open", "Open in Explorer", { let v = value.trim_end_matches('\\').to_string(); move |ctx| simple_action(ctx, Action::OpenFolder(format!("{}\\x", v)), "Opened folder", None) }).disabled(!is_path),
                MenuItem::new("reg", "Edit in Registry Editor", { let k = reg_key.clone(); move |ctx| simple_action(ctx, Action::OpenRegistryKey(k), "Opened Registry Editor", None) }).disabled(reg_key.is_empty()),
            ];
            menus::show(ctx, x, y, &name, entries);
        }
        1 | 8 => {
            let name = it.key.to_string();
            let value = it.value.to_string();
            let entries = vec![
                MenuItem::new("cv", "Copy value", { let v = value.clone(); move |ctx| copy_text(ctx, &v) }).disabled(value.is_empty()),
                MenuItem::new("cb", "Copy name and value", { let v = format!("{}: {}", name, value); move |ctx| copy_text(ctx, &v) }),
            ];
            menus::show(ctx, x, y, &name, entries);
        }
        _ => {}
    }
}

pub fn system_text(ctx: &Shared) -> String {
    let items: Vec<DocItem> = ui(ctx).get_env_doc().iter().collect();
    doc_text(&items)
}

pub fn text_of(info: &SysInfo) -> String {
    doc_text(&build(info, ""))
}

fn doc_text(items: &[DocItem]) -> String {
    let mut lines = Vec::new();
    for it in items {
        match it.kind {
            1 | 8 => lines.push(format!("{}: {}", it.key, it.value)),
            3 => lines.push(format!("{} {} {} {}", it.key, it.value, it.sub, it.sub2).split_whitespace().collect::<Vec<_>>().join(" ")),
            0 => lines.push(format!("\n{}", it.key)),
            _ => {}
        }
    }
    lines.join("\r\n") + "\r\n"
}
