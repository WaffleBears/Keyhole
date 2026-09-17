use super::format::*;
use super::{do_action, simple_action};
use super::{Shared, copy_text, dialogs, finder, model, ss, ui};
use crate::MenuEntry;
use keyhole::api::Action;
use keyhole::model::{EndpointRow, HandleRow};
use slint::ComponentHandle;

pub struct MenuItem {
    pub id: String,
    pub label: String,
    pub key: String,
    pub tip: String,
    pub danger: bool,
    pub disabled: bool,
    pub separator: bool,
    pub run: Option<Box<dyn FnOnce(&Shared)>>,
}

impl MenuItem {
    pub fn new(id: &str, label: &str, run: impl FnOnce(&Shared) + 'static) -> MenuItem {
        MenuItem { id: id.into(), label: label.into(), key: String::new(), tip: String::new(), danger: false, disabled: false, separator: false, run: Some(Box::new(run)) }
    }
    pub fn sep() -> MenuItem {
        MenuItem { id: String::new(), label: String::new(), key: String::new(), tip: String::new(), danger: false, disabled: false, separator: true, run: None }
    }
    pub fn danger(mut self) -> MenuItem {
        self.danger = true;
        self
    }
    pub fn disabled(mut self, d: bool) -> MenuItem {
        self.disabled = d;
        self
    }
    pub fn key(mut self, k: &str) -> MenuItem {
        self.key = k.into();
        self
    }
    pub fn tip(mut self, t: &str) -> MenuItem {
        self.tip = t.into();
        self
    }
}

pub fn wire(ctx: &Shared) {
    let u = ui(ctx);
    {
        let ctx = ctx.clone();
        u.on_menu_picked(move |id| {
            let action = ctx.st.borrow_mut().menu_actions.remove(id.as_str());
            close(&ctx);
            if let Some(run) = action {
                run(&ctx);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_menu_dismissed(move || close(&ctx));
    }
}

pub fn close(ctx: &Shared) {
    ui(ctx).set_menu_open(false);
    ctx.st.borrow_mut().menu_actions.clear();
    super::focus_keys(ctx);
}

pub fn show(ctx: &Shared, x: f32, y: f32, title: &str, items: Vec<MenuItem>) {
    let mut entries = Vec::with_capacity(items.len());
    let mut actions = std::collections::HashMap::new();
    for (i, it) in items.into_iter().enumerate() {
        let id = if it.separator { format!("sep{}", i) } else { format!("{}#{}", it.id, i) };
        entries.push(MenuEntry { id: ss(&id), label: ss(&it.label), key: ss(&it.key), tip: ss(&it.tip), danger: it.danger, disabled: it.disabled, separator: it.separator });
        if let Some(run) = it.run
            && !it.disabled {
                actions.insert(id, run);
            }
    }
    {
        let mut st = ctx.st.borrow_mut();
        st.menu_actions = actions;
        st.last_menu_rect = (x, y);
    }
    let widest = entries.iter().map(|e| e.label.chars().count() as f32 * 6.6 + if e.key.is_empty() { 0.0 } else { e.key.chars().count() as f32 * 6.0 + 18.0 }).fold(0.0f32, f32::max);
    let u = ui(ctx);
    u.set_menu_title(ss(title));
    u.set_menu_entries(model(entries));
    u.set_menu_x(x);
    u.set_menu_y(y);
    u.set_menu_width((widest + 34.0).clamp(240.0, 520.0));
    u.set_menu_open(true);
    ctx.window.global::<crate::Tips>().set_shown(false);
}

pub fn file_items(path: &str) -> Vec<MenuItem> {
    let is_file = is_file_path(path);
    let p = path.to_string();
    let p2 = path.to_string();
    vec![
        MenuItem::new("props", "Windows file properties", move |ctx| simple_action(ctx, Action::FileProperties(p.clone()), "Opened file properties", None)).disabled(!is_file),
        MenuItem::new("sha", "Copy SHA-256", move |ctx| copy_hash(ctx, &p2)).disabled(!is_file),
    ]
}

pub fn copy_hash(ctx: &Shared, path: &str) {
    let path = path.to_string();
    super::spawn(ctx, move |_| keyhole::api::sha256(&path), |ctx, r| match r {
        Ok(h) => copy_text(ctx, &h),
        Err(e) => super::bad(ctx, &e),
    });
}

pub fn close_connection_item(d: &EndpointRow, after: Box<dyn FnOnce(&Shared)>) -> MenuItem {
    let can_close = d.proto == "TCP" && d.state == "ESTABLISHED";
    let local = d.local.clone();
    let remote = d.remote.clone();
    MenuItem::new("close", "Close this connection", move |ctx| {
        let l = local.clone();
        let r = remote.clone();
        dialogs::confirm(
            ctx,
            "Close this connection?",
            &format!("This forcibly tears down the TCP connection {} → {}. The owning program is not told and may error.", local, remote),
            "Close connection",
            true,
            Box::new(move |ctx| simple_action(ctx, Action::CloseConnection { local: l, remote: r }, "Connection closed", Some(after))),
        );
    })
    .danger()
    .disabled(!can_close)
}

pub fn handle_menu(ctx: &Shared, x: f32, y: f32, row: &HandleRow) {
    let path = if row.display.is_empty() { row.name.clone() } else { row.display.clone() };
    let is_file = is_file_path(&path);
    let is_key = row.type_name == "Key";
    let searchable = row.type_name == "File" || is_key || is_file;
    let pid = row.pid;
    let handle = row.handle;
    let process = if row.process.is_empty() { format!("pid {}", row.pid) } else { row.process.clone() };
    let items = vec![
        MenuItem::new("copyPath", if is_file || is_key { "Copy path" } else { "Copy name" }, { let p = path.clone(); move |ctx| copy_text(ctx, &p) }).disabled(path.is_empty()),
        MenuItem::new("copyRaw", "Copy raw object name", { let n = row.name.clone(); move |ctx| copy_text(ctx, &n) }).disabled(row.name.is_empty() || row.name == path),
        MenuItem::new("copyHandle", "Copy handle value", move |ctx| copy_text(ctx, &hex(handle, 0))),
        MenuItem::new("copyAccess", "Copy access rights", { let a = row.access_text.clone(); move |ctx| copy_text(ctx, &a) }).disabled(row.access_text.is_empty()),
        MenuItem::sep(),
        MenuItem::new("reveal", "Show in Explorer", { let p = path.clone(); move |ctx| simple_action(ctx, Action::Reveal(p.clone()), "Revealed", None) }).disabled(!is_file),
        MenuItem::new("folder", "Open containing folder", { let p = path.clone(); move |ctx| simple_action(ctx, Action::OpenFolder(p.clone()), "Opened folder", None) }).disabled(!is_file),
        MenuItem::new("props", "Windows file properties", { let p = path.clone(); move |ctx| simple_action(ctx, Action::FileProperties(p.clone()), "Opened file properties", None) }).disabled(!is_file),
        MenuItem::new("regedit", "Open in Registry Editor", { let p = path.clone(); move |ctx| simple_action(ctx, Action::OpenRegistryKey(p.clone()), "Opened Registry Editor", None) }).disabled(!is_key),
        MenuItem::sep(),
        MenuItem::new("whoelse", "Find what else has this open", { let p = path.clone(); move |ctx| finder::find_open(ctx, &p, false) }).disabled(!searchable || path.is_empty()),
        MenuItem::new("select", "Select owning process", move |ctx| {
            finder::close(ctx);
            super::tree::select_pid(ctx, pid);
        }),
        MenuItem::sep(),
        MenuItem::new("close", "Force close this handle", {
            let p = path.clone();
            let process = process.clone();
            move |ctx| {
                dialogs::confirm(
                    ctx,
                    "Force close this handle?",
                    &format!("Keyhole will reach into {} and close its handle to {}. That process is not told. A file being written can end up corrupted, or the program can crash. Terminating the process is usually safer.", process, p),
                    "Close the handle",
                    true,
                    Box::new(move |ctx| do_action(ctx, Action::CloseHandle { pid, handle }, "Handle closed")),
                );
            }
        })
        .danger(),
        MenuItem::new("kill", "Terminate owning process", {
            let process = process.clone();
            move |ctx| {
                dialogs::confirm(
                    ctx,
                    &format!("Terminate {}?", process),
                    &format!("This kills {}, releasing every file it holds. Unsaved work is lost.", process),
                    "Terminate",
                    true,
                    Box::new(move |ctx| do_action(ctx, Action::Terminate(pid), "Terminated")),
                );
            }
        })
        .danger(),
    ];
    show(ctx, x, y, &path, items);
}
