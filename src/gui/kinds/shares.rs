use super::{Kind, RenderInput, Rendered};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{self, ListData, ListState};
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, num, simple_row, sort_indices, sv_n, sv_s};
use crate::gui::simple_action;
use crate::gui::{Shared, chip, copy_text, dialogs, finder, model, ss, ui};
use crate::{Badge, Chip};
use keyhole::api::{self, Action};
use keyhole::state::App;
use keyhole::sys::mounts::{self, MountRow};
use keyhole::sys::shares::{ShareRow, SharesData, SmbFile, SmbSession, computer_name};

pub const FILE_COLUMNS: &[ColDef] = &[
    c("path", "File", 420.0, false, "The file or folder a client holds open through a share. Hover for the full path."),
    c("share", "Share", 120.0, false, "The share it was opened through. Click to sort."),
    c("user", "User", 160.0, false, "The account that opened it. Click to sort."),
    c("client", "Client", 160.0, false, "The computer(s) that account is connected from."),
    c("access", "Access", 110.0, false, "read, write or create: write means the client can change the file, which is what blocks other people."),
    c("locks", "Locks", 70.0, true, "Byte range locks the client holds on the file."),
];

pub const SESSION_COLUMNS: &[ColDef] = &[
    c("client", "Client", 200.0, false, "The computer the session comes from. Click to sort."),
    c("user", "User", 200.0, false, "The account that authenticated. Click to sort."),
    c("opens", "Open files", 100.0, true, "Files the session holds open right now."),
    c("connected", "Connected", 110.0, true, "How long the session has been established."),
    c("idle", "Idle", 100.0, true, "Time since the client last did anything."),
    c("transport", "Transport", 200.0, false, "The network transport carrying the session."),
];

pub const SHARE_COLUMNS: &[ColDef] = &[
    c("name", "Share", 180.0, false, "The share name clients see. Names ending in $ are hidden from browsing. Click to sort."),
    c("kind", "Type", 90.0, false, "Disk, Printer, Device or IPC."),
    c("path", "Path", 360.0, false, "The local folder behind the share."),
    c("remark", "Remark", 200.0, false, "The description set when the share was created."),
    c("perms", "Share permissions", 320.0, false, "Who the share lets in and with what rights. NTFS permissions on the folder still apply. Hover a row to see both."),
    c("uses", "In use", 80.0, true, "How many connections are using it right now."),
    c("max", "Max", 70.0, true, "The connection limit, or unlimited."),
];

pub const MOUNT_COLUMNS: &[ColDef] = &[
    c("local", "Local", 110.0, false, "The drive letter, or the local disk for an iSCSI target. Blank for a UNC connection without a letter."),
    c("remote", "Remote", 360.0, false, "The UNC path, NFS export or iSCSI target this machine has mounted. Click to sort."),
    c("kind", "Kind", 90.0, false, "SMB, NFS, WebDAV or iSCSI."),
    c("status", "Status", 150.0, false, "connected, disconnected, remembered (mapped at logon but not connected now), or the iSCSI login state."),
    c("user", "As", 180.0, false, "The credentials the connection was made with, when Windows reports them."),
    c("detail", "Detail", 320.0, false, "Open count, iSCSI addresses, or why a mapping is not live."),
];

pub static KIND: Kind = Kind {
    name: "shares",
    title: "Shares",
    placeholder: ("Filter by file, user, client, share or mount", "Show only rows whose file, share, user, client or remote path contains this text. Prefixes: share:name  user:name  client:name  kind:iscsi"),
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
    match st.segment.get("shares").map(|s| s.as_str()) {
        Some("sessions") => "sessions",
        Some("shares") => "shares",
        Some("mounted") => "mounted",
        _ => "files",
    }
}

fn columns(st: &ListState) -> &'static [ColDef] {
    match current(st) {
        "sessions" => SESSION_COLUMNS,
        "shares" => SHARE_COLUMNS,
        "mounted" => MOUNT_COLUMNS,
        _ => FILE_COLUMNS,
    }
}

fn table(st: &ListState) -> String {
    format!("shares.{}", current(st))
}

fn segment(st: &ListState) -> String {
    current(st).to_string()
}

fn default_sort(st: &ListState) -> (&'static str, bool) {
    match current(st) {
        "sessions" => ("client", false),
        "shares" => ("name", false),
        "mounted" => ("kind", false),
        _ => ("path", false),
    }
}

fn buttons(_st: &ListState) -> Vec<Chip> {
    vec![chip("console", "Shared Folders", None, "Open the Shared Folders console (fsmgmt.msc) to create or change shares")]
}

fn segments(_st: &ListState) -> Vec<Chip> {
    vec![
        chip("files", "Open files", None, "Files clients hold open through the shares"),
        chip("sessions", "Sessions", None, "Clients connected to this server over SMB"),
        chip("shares", "Shares", None, "What this server shares"),
        chip("mounted", "Mounted", None, "What this machine has mounted from elsewhere: SMB and NFS shares, WebDAV, iSCSI targets"),
    ]
}

pub fn switch(ctx: &Shared, id: &str, filter: Option<String>) {
    {
        let mut st = ctx.st.borrow_mut();
        st.lists.segment.insert("shares".into(), id.to_string());
        st.lists.chip.insert("shares".into(), String::new());
        if let Some(f) = &filter {
            st.lists.filter.insert("shares".into(), f.clone());
        }
        st.lists.sel = None;
    }
    let u = ui(ctx);
    u.set_list_segment(ss(id));
    if let Some(f) = filter {
        u.set_list_filter(ss(&f));
    }
    lists::set_cols(ctx, "shares");
    lists::render(ctx);
}

fn segment_picked(ctx: &Shared, id: &str) {
    switch(ctx, id, None);
}

fn refresh(_app: &App, _st: &ListState) -> ListData {
    ListData::Shares(api::shares())
}

fn access_text(f: &SmbFile) -> String {
    let mut parts = Vec::new();
    if f.read {
        parts.push("read");
    }
    if f.write {
        parts.push("write");
    }
    if f.create {
        parts.push("create");
    }
    parts.join(", ")
}

fn unc(share: &str, path: &str, share_path: &str) -> String {
    let rest = if share_path.is_empty() { String::new() } else { path.get(share_path.trim_end_matches('\\').len()..).unwrap_or("").to_string() };
    format!("\\\\{}\\{}{}", computer_name(), share, rest)
}

fn render(_ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Shares(d) = data else { return Rendered::default() };
    let terms = filter_terms(&input.filter);
    let seg = if input.table.ends_with("sessions") { "sessions" } else if input.table.ends_with(".shares") { "shares" } else if input.table.ends_with("mounted") { "mounted" } else { "files" };
    let mut out = Rendered::default();
    let head = format!("{} open over SMB by {} on {}  ·  {} mounted from elsewhere", plural(d.files.len(), "file", "files"), plural(d.sessions.len(), "session", "sessions"), plural(d.shares.len(), "share", "shares"), d.mounts.rows.len());
    let mut note = d.error.as_ref().map(|e| format!("  ·  {}", e)).unwrap_or_default();
    match seg {
        "mounted" => {
            let m = &d.mounts;
            let chip_ok = |r: &MountRow| match input.chip.as_str() {
                "smb" => r.kind == "SMB",
                "nfs" => r.kind == "NFS",
                "iscsi" => r.kind == "iSCSI",
                "down" => !r.connected,
                "persistent" => r.persistent,
                _ => true,
            };
            out.chips = vec![
                chip("", "All", Some(m.rows.len()), "Everything mounted from another machine"),
                chip("smb", "SMB", Some(m.rows.iter().filter(|r| r.kind == "SMB").count()), "Windows file shares and UNC connections"),
                chip("nfs", "NFS", Some(m.rows.iter().filter(|r| r.kind == "NFS").count()), "NFS exports mounted through Client for NFS"),
                chip("iscsi", "iSCSI", Some(m.rows.iter().filter(|r| r.kind == "iSCSI").count()), "Block storage from iSCSI targets, with the local disks they became"),
                chip("down", "Not connected", Some(m.rows.iter().filter(|r| !r.connected).count()), "Remembered or broken mappings: nothing is reachable through these right now"),
                chip("persistent", "Reconnect at logon", Some(m.rows.iter().filter(|r| r.persistent).count()), "Mappings and iSCSI favorites Windows restores automatically"),
            ];
            out.shown = (0..m.rows.len()).filter(|&i| { let r = &m.rows[i]; chip_ok(r) && (terms.is_empty() || term_matches(&terms, |k| match k { "kind" => Some(r.kind.clone()), "user" => Some(r.user.clone()), "status" => Some(r.status.clone()), _ => None }, &format!("{} {} {} {} {} {}", r.local, r.remote, r.kind, r.status, r.user, r.detail))) }).collect();
            sort_indices(&m.rows, &mut out.shown, &input.sort.0, input.sort.1, |r, k| match k {
                "local" => sv_s(&r.local),
                "remote" => sv_s(&r.remote),
                "kind" => sv_s(&r.kind),
                "status" => sv_s(&r.status),
                "user" => sv_s(&r.user),
                "detail" => sv_s(&r.detail),
                _ => sv_s(""),
            });
            out.rows = out.shown.iter().map(|&i| {
                let r = &m.rows[i];
                simple_row(i as i32, vec![cell(&r.local, 0), cell(&r.remote, 0), cell(&r.kind, 7), cell(&r.status, if r.connected { 2 } else { 3 }), cell(&r.user, 7), cell(&r.detail, if r.connected { 7 } else { 3 })], 0, &mounts::summary(r))
            }).collect();
            out.empty = ("\u{E8CE}".into(), if terms.is_empty() && input.chip.is_empty() { "Nothing is mounted from another machine.".into() } else { lists::nothing_matches(&input.filter) }, "Mapped drives belong to the logon session that made them. Keyhole reads its own elevated session and your desktop session. iSCSI targets appear once the Initiator service has logged in.".into());
            for n in &m.notes {
                note.push_str(&format!("  ·  {}", n));
            }
        }
        "sessions" => {
            let chip_ok = |s: &SmbSession| match input.chip.as_str() {
                "idle" => s.idle_secs >= 900,
                "guest" => s.guest,
                _ => true,
            };
            out.chips = vec![
                chip("", "All", Some(d.sessions.len()), "Every SMB session"),
                chip("idle", "Idle over 15 min", Some(d.sessions.iter().filter(|s| s.idle_secs >= 900).count()), "Sessions that have not done anything for a while but still hold their files"),
                chip("guest", "Guest", Some(d.sessions.iter().filter(|s| s.guest).count()), "Sessions authenticated as guest"),
            ];
            out.shown = (0..d.sessions.len()).filter(|&i| { let s = &d.sessions[i]; chip_ok(s) && (terms.is_empty() || term_matches(&terms, |k| match k { "user" => Some(s.user.clone()), "client" => Some(s.client.clone()), _ => None }, &format!("{} {} {}", s.client, s.user, s.transport))) }).collect();
            sort_indices(&d.sessions, &mut out.shown, &input.sort.0, input.sort.1, |s, k| match k {
                "client" => sv_s(&s.client),
                "user" => sv_s(&s.user),
                "opens" => sv_n(s.opens as f64),
                "connected" => sv_n(s.connected_secs as f64),
                "idle" => sv_n(s.idle_secs as f64),
                "transport" => sv_s(&s.transport),
                _ => sv_s(""),
            });
            out.rows = out.shown.iter().map(|&i| {
                let s = &d.sessions[i];
                let mut row = simple_row(i as i32, vec![cell(&s.client, 0), cell(&s.user, 0), num(&s.opens.to_string()), num(&fmt_age(s.connected_secs as i64 * 1000)), num(&if s.idle_secs > 0 { fmt_age(s.idle_secs as i64 * 1000) } else { String::new() }), cell(&s.transport, 7)], 0, &format!("{} from {}\n{} open files, connected {}", s.user, s.client, s.opens, fmt_age(s.connected_secs as i64 * 1000)));
                if s.guest {
                    row.badges = model(vec![Badge { text: ss("guest"), kind: 4, tip: ss("Authenticated as guest") }]);
                }
                row
            }).collect();
            out.empty = ("\u{E8CE}".into(), if terms.is_empty() && input.chip.is_empty() { "Nobody is connected to this server's shares.".into() } else { lists::nothing_matches(&input.filter) }, String::new());
        }
        "shares" => {
            let chip_ok = |s: &ShareRow| match input.chip.as_str() {
                "visible" => !s.hidden,
                "disk" => s.kind == "Disk",
                "used" => s.current_uses > 0,
                _ => true,
            };
            out.chips = vec![
                chip("", "All", Some(d.shares.len()), "Every share, including the hidden administrative ones"),
                chip("visible", "Visible", Some(d.shares.iter().filter(|s| !s.hidden).count()), "Shares clients can browse to (names without a trailing $)"),
                chip("disk", "Disk shares", Some(d.shares.iter().filter(|s| s.kind == "Disk").count()), "Folder shares"),
                chip("used", "In use", Some(d.shares.iter().filter(|s| s.current_uses > 0).count()), "Shares with at least one connection right now"),
            ];
            out.shown = (0..d.shares.len()).filter(|&i| { let s = &d.shares[i]; chip_ok(s) && (terms.is_empty() || term_matches(&terms, |k| match k { "share" => Some(s.name.clone()), _ => None }, &format!("{} {} {} {}", s.name, s.path, s.remark, s.kind))) }).collect();
            sort_indices(&d.shares, &mut out.shown, &input.sort.0, input.sort.1, |s, k| match k {
                "name" => sv_s(&s.name),
                "kind" => sv_s(&s.kind),
                "path" => sv_s(&s.path),
                "remark" => sv_s(&s.remark),
                "perms" => sv_s(&keyhole::sys::acl::share_summary(&s.name, &s.share_acl, &s.share_acl_note)),
                "uses" => sv_n(s.current_uses as f64),
                "max" => sv_n(s.max_uses as f64),
                _ => sv_s(""),
            });
            out.rows = out.shown.iter().map(|&i| {
                let s = &d.shares[i];
                simple_row(i as i32, vec![cell(&s.name, 0), cell(&s.kind, 7), cell(&s.path, 0), cell(&s.remark, 7), cell(&keyhole::sys::acl::share_summary(&s.name, &s.share_acl, &s.share_acl_note), if s.share_acl.is_empty() { 7 } else { 0 }), num(&if s.current_uses > 0 { s.current_uses.to_string() } else { String::new() }), num(&if s.max_uses == u32::MAX { "unlimited".to_string() } else { s.max_uses.to_string() })], if s.hidden { 1 } else { 0 }, &permissions_text(s))
            }).collect();
            out.empty = ("\u{E8CE}".into(), if terms.is_empty() && input.chip.is_empty() { "This server shares nothing.".into() } else { lists::nothing_matches(&input.filter) }, String::new());
        }
        _ => {
            let chip_ok = |f: &SmbFile| match input.chip.as_str() {
                "write" => f.write || f.create,
                "locked" => f.locks > 0,
                other if other.starts_with("share:") => f.share.eq_ignore_ascii_case(&other[6..]),
                _ => true,
            };
            out.chips = vec![
                chip("", "All", Some(d.files.len()), "Every file open through a share"),
                chip("write", "Writable", Some(d.files.iter().filter(|f| f.write || f.create).count()), "Opened with write or create access: these block other users' edits, moves and deletes"),
                chip("locked", "Locked", Some(d.files.iter().filter(|f| f.locks > 0).count()), "Files with byte range locks held by the client"),
            ];
            let mut by_share: Vec<(String, usize)> = Vec::new();
            for f in &d.files {
                if f.share.is_empty() {
                    continue;
                }
                match by_share.iter_mut().find(|(s, _)| s == &f.share) {
                    Some(e) => e.1 += 1,
                    None => by_share.push((f.share.clone(), 1)),
                }
            }
            by_share.sort();
            for (s, n) in by_share {
                out.chips.push(chip(&format!("share:{}", s), &format!("\\{}", s), Some(n), "Only files open through this share"));
            }
            out.shown = (0..d.files.len()).filter(|&i| { let f = &d.files[i]; chip_ok(f) && (terms.is_empty() || term_matches(&terms, |k| match k { "share" => Some(f.share.clone()), "user" => Some(f.user.clone()), "client" => Some(f.clients.join("\n")), _ => None }, &format!("{} {} {} {}", f.path, f.share, f.user, f.clients.join(" ")))) }).collect();
            sort_indices(&d.files, &mut out.shown, &input.sort.0, input.sort.1, |f, k| match k {
                "path" => sv_s(&f.path),
                "share" => sv_s(&f.share),
                "user" => sv_s(&f.user),
                "client" => sv_s(&f.clients.join(" ")),
                "access" => sv_s(&access_text(f)),
                "locks" => sv_n(f.locks as f64),
                _ => sv_s(""),
            });
            out.rows = out.shown.iter().map(|&i| {
                let f = &d.files[i];
                simple_row(i as i32, vec![cell(&f.path, 0), cell(&f.share, 0), cell(&f.user, 0), cell(&f.clients.join(", "), 7), cell(&access_text(f), if f.write || f.create { 3 } else { 1 }), num(&if f.locks > 0 { f.locks.to_string() } else { String::new() })], 0, &format!("{}\n{} via \\{} from {}", f.path, f.user, f.share, if f.clients.is_empty() { "an unknown client".to_string() } else { f.clients.join(", ") }))
            }).collect();
            out.empty = ("\u{E8CE}".into(), if terms.is_empty() && input.chip.is_empty() { "No files are open over SMB right now.".into() } else { lists::nothing_matches(&input.filter) }, "Open files appear here the moment a client opens something through a share.".into());
        }
    }
    out.count = format!("{}{}", head, note);
    out
}

fn permissions_text(s: &ShareRow) -> String {
    let mut out = format!("{}\n{}", unc(&s.name, &s.path, &s.path), s.path);
    out.push_str("\n\nShare permissions:");
    if s.share_acl.is_empty() {
        out.push_str(&format!("\n  {}", keyhole::sys::acl::share_summary(&s.name, &s.share_acl, &s.share_acl_note)));
    }
    for a in &s.share_acl {
        out.push_str(&format!("\n  {}{}: {}", if a.allow { "" } else { "DENY " }, a.who, a.rights));
    }
    if !s.folder_acl.is_empty() {
        out.push_str("\n\nFolder (NTFS) permissions:");
        for a in &s.folder_acl {
            out.push_str(&format!("\n  {}{}: {}{}", if a.allow { "" } else { "DENY " }, a.who, a.rights, if a.inherited { "  (inherited)" } else { "" }));
        }
    }
    out
}

fn share_path(d: &SharesData, share: &str) -> String {
    d.shares.iter().find(|s| s.name.eq_ignore_ascii_case(share)).map(|s| s.path.clone()).unwrap_or_default()
}

fn double(ctx: &Shared, src: usize) {
    let seg = ctx.st.borrow().lists.segment.get("shares").cloned().unwrap_or_default();
    let st = ctx.st.borrow();
    let ListData::Shares(d) = &st.lists.data else { return };
    match seg.as_str() {
        "mounted" => {
            let Some(r) = d.mounts.rows.get(src) else { return };
            let text = r.remote.clone();
            drop(st);
            copy_text(ctx, &text);
        }
        "sessions" => {
            let Some(s) = d.sessions.get(src) else { return };
            let user = s.user.clone();
            drop(st);
            switch(ctx, "files", Some(exact_filter("user", &user)));
        }
        "shares" => {
            let Some(s) = d.shares.get(src) else { return };
            let name = s.name.clone();
            drop(st);
            switch(ctx, "files", Some(exact_filter("share", &name)));
        }
        _ => {
            let Some(f) = d.files.get(src) else { return };
            let path = f.path.clone();
            drop(st);
            finder::find_open(ctx, &path, false);
        }
    }
}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let seg = ctx.st.borrow().lists.segment.get("shares").cloned().unwrap_or_default();
    let st = ctx.st.borrow();
    let ListData::Shares(d) = &st.lists.data else { return };
    match seg.as_str() {
        "mounted" => {
            let Some(r) = d.mounts.rows.get(src).cloned() else { return };
            drop(st);
            let name = if r.local.is_empty() || r.kind == "iSCSI" { r.remote.clone() } else { r.local.clone() };
            let openable = r.kind != "iSCSI" && r.remote.starts_with("\\\\");
            let items = vec![
                MenuItem::new("open", "Open in Explorer", { let p = if r.local.is_empty() { r.remote.clone() } else { format!("{}\\", r.local) }; move |ctx| simple_action(ctx, Action::OpenFolder(format!("{}\\x", p.trim_end_matches('\\'))), "Opened", None) }).disabled(!openable || !r.connected || (r.desktop && !r.local.is_empty())),
                MenuItem::new("copyRemote", "Copy remote path", { let v = r.remote.clone(); move |ctx| copy_text(ctx, &v) }),
                MenuItem::new("copySummary", "Copy summary", { let v = mounts::summary(&r); move |ctx| copy_text(ctx, &v) }),
                MenuItem::sep(),
                MenuItem::new("disconnect", if r.persistent { "Disconnect and forget" } else { "Disconnect" }, { let r2 = r.clone(); let n = name.clone(); move |ctx| { let n2 = n.clone(); let what = if r2.local.is_empty() { r2.remote.clone() } else { format!("{} ({})", r2.local, r2.remote) }; dialogs::confirm(ctx, &format!("Disconnect {}?", what), "Open files on it are closed without warning the programs using them. A persistent mapping stops reconnecting at logon.", "Disconnect", true, Box::new(move |ctx| simple_action(ctx, Action::DisconnectMount(n2.clone()), "Disconnected", super::refresh_after("shares")))); } }).disabled(r.kind == "iSCSI" || r.desktop).danger().tip(if r.kind == "iSCSI" { "iSCSI targets are logged out from the iSCSI Initiator control panel, not here" } else if r.desktop { "This mapping lives in your desktop logon session, which the elevated Keyhole cannot reach. Disconnect it from Explorer or net use" } else { "net use /delete, with force" }),
            ];
            menus::show(ctx, x, y, &r.remote, items);
        }
        "sessions" => {
            let Some(s) = d.sessions.get(src).cloned() else { return };
            drop(st);
            let items = vec![
                MenuItem::new("files", "Show this user's open files", { let u = s.user.clone(); move |ctx| switch(ctx, "files", Some(exact_filter("user", &u))) }),
                MenuItem::new("copyClient", "Copy client", { let v = s.client.clone(); move |ctx| copy_text(ctx, &v) }),
                MenuItem::new("copyUser", "Copy user", { let v = s.user.clone(); move |ctx| copy_text(ctx, &v) }),
                MenuItem::sep(),
                MenuItem::new("disconnect", "Disconnect session", { let s2 = s.clone(); move |ctx| { let s3 = s2.clone(); dialogs::confirm(ctx, &format!("Disconnect {} from {}?", s3.user, s3.client), &format!("This drops the SMB session and its {} open files. The client is not told and loses anything it had not written, though most programs reconnect.", s3.opens), "Disconnect", true, Box::new(move |ctx| simple_action(ctx, Action::DisconnectSmbSession { client: s3.client.clone(), user: s3.user.clone() }, &format!("Disconnected {}", s3.client), super::refresh_after("shares")))); } }).danger(),
            ];
            menus::show(ctx, x, y, &format!("{}  ·  {}", s.client, s.user), items);
        }
        "shares" => {
            let Some(s) = d.shares.get(src).cloned() else { return };
            drop(st);
            let path = s.path.clone();
            let u = unc(&s.name, &s.path, &s.path);
            let items = vec![
                MenuItem::new("open", "Open folder", { let p = path.clone(); move |ctx| simple_action(ctx, Action::OpenFolder(format!("{}\\x", p.trim_end_matches('\\'))), "Opened folder", None) }).disabled(path.is_empty()),
                MenuItem::new("unc", "Copy UNC path", { let v = u.clone(); move |ctx| copy_text(ctx, &v) }),
                MenuItem::new("copyPath", "Copy local path", { let v = path.clone(); move |ctx| copy_text(ctx, &v) }).disabled(path.is_empty()),
                MenuItem::new("copyPerms", "Copy permissions (share and folder)", { let v = permissions_text(&s); move |ctx| copy_text(ctx, &v) }),
                MenuItem::sep(),
                MenuItem::new("files", "Show open files on this share", { let n = s.name.clone(); move |ctx| switch(ctx, "files", Some(exact_filter("share", &n))) }),
                MenuItem::new("who", "Find everything open under its folder", { let p = path.clone(); move |ctx| finder::find_open(ctx, &p, true) }).disabled(path.is_empty()),
                MenuItem::new("console", "Open Shared Folders console", |ctx| simple_action(ctx, Action::OpenTool("shares".into()), "Opened Shared Folders", None)),
                MenuItem::sep(),
                MenuItem::new("unshare", "Stop sharing", { let s2 = s.clone(); move |ctx| { let s3 = s2.clone(); dialogs::confirm(ctx, &format!("Stop sharing {}?", s3.name), &format!("The share goes away at once and its {} drop. The folder {} stays. Administrative shares come back at the next restart.", plural(s3.current_uses as usize, "connection", "connections"), s3.path), "Stop sharing", true, Box::new(move |ctx| simple_action(ctx, Action::StopSharing(s3.name.clone()), &format!("Stopped sharing {}", s3.name), super::refresh_after("shares")))); } }).danger().disabled(s.kind == "IPC"),
            ];
            menus::show(ctx, x, y, &u, items);
        }
        _ => {
            let Some(f) = d.files.get(src).cloned() else { return };
            let sp = share_path(d, &f.share);
            drop(st);
            let u = if f.share.is_empty() { String::new() } else { unc(&f.share, &f.path, &sp) };
            let items = vec![
                MenuItem::new("copyPath", "Copy path", { let v = f.path.clone(); move |ctx| copy_text(ctx, &v) }),
                MenuItem::new("unc", "Copy UNC path", { let v = u.clone(); move |ctx| copy_text(ctx, &v) }).disabled(u.is_empty()),
                MenuItem::new("reveal", "Show in Explorer", { let p = f.path.clone(); move |ctx| simple_action(ctx, Action::Reveal(p), "Revealed", None) }),
                MenuItem::new("who", "Find local handles to this file", { let p = f.path.clone(); move |ctx| finder::find_open(ctx, &p, false) }),
                MenuItem::new("user", "Show only this user", { let n = f.user.clone(); move |ctx| switch(ctx, "files", Some(exact_filter("user", &n))) }),
                MenuItem::sep(),
                MenuItem::new("close", "Close this file", { let f2 = f.clone(); move |ctx| { let f3 = f2.clone(); dialogs::confirm(ctx, "Close this file for the client?", &format!("Keyhole will close {} for {}. The client is not told. Unsaved changes on their side are lost.", f3.path, f3.user), "Close file", true, Box::new(move |ctx| simple_action(ctx, Action::CloseSmbFile(f3.id), "Closed the file", super::refresh_after("shares")))); } }).danger(),
            ];
            menus::show(ctx, x, y, &f.path, items);
        }
    }
}

fn button(ctx: &Shared, id: &str) {
    if id == "console" {
        simple_action(ctx, Action::OpenTool("shares".into()), "Opened Shared Folders", None);
    }
}

fn export_csv(data: &ListData, shown: &[usize], st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Shares(d) = data else { return None };
    Some(match current(st) {
        "sessions" => ("keyhole-smb-sessions", csv(&shown.iter().map(|&i| { let s = &d.sessions[i]; vec![s.client.clone(), s.user.clone(), s.opens.to_string(), s.connected_secs.to_string(), s.idle_secs.to_string(), s.guest.to_string(), s.transport.clone()] }).collect::<Vec<_>>(), &["Client", "User", "Open files", "Connected seconds", "Idle seconds", "Guest", "Transport"])),
        "mounted" => ("keyhole-mounted", csv(&shown.iter().filter_map(|&i| d.mounts.rows.get(i)).map(|r| vec![r.local.clone(), r.remote.clone(), r.kind.clone(), r.status.clone(), r.connected.to_string(), r.user.clone(), r.detail.clone(), r.persistent.to_string(), if r.desktop { "another logon session".to_string() } else { "this session".to_string() }]).collect::<Vec<_>>(), &["Local", "Remote", "Kind", "Status", "Connected", "As", "Detail", "Persistent", "Session"])),
        "shares" => ("keyhole-shares", csv(&shown.iter().map(|&i| { let s = &d.shares[i]; vec![s.name.clone(), s.kind.clone(), s.path.clone(), s.remark.clone(), keyhole::sys::acl::share_summary(&s.name, &s.share_acl, &s.share_acl_note), keyhole::sys::acl::summary(&s.folder_acl), s.current_uses.to_string(), if s.max_uses == u32::MAX { "unlimited".into() } else { s.max_uses.to_string() }, s.hidden.to_string()] }).collect::<Vec<_>>(), &["Share", "Type", "Path", "Remark", "Share permissions", "Folder permissions", "In use", "Max", "Hidden"])),
        _ => ("keyhole-smb-open-files", csv(&shown.iter().map(|&i| { let f = &d.files[i]; vec![f.path.clone(), f.share.clone(), f.user.clone(), f.clients.join("; "), access_text(f), f.locks.to_string()] }).collect::<Vec<_>>(), &["File", "Share", "User", "Client", "Access", "Locks"])),
    })
}
