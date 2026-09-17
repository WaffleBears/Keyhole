use super::{Kind, RenderInput, Rendered};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{self, ListData, ListState};
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, dot_cell, num, simple_row, sort_indices, suffix_cell, sv_b, sv_n, sv_s};
use crate::gui::simple_action;
use crate::gui::{Shared, bad, chip, copy_text, dialogs, good, model, spawn, ss, ui};
use crate::{Badge, Chip};
use keyhole::api::{self, Action};
use keyhole::state::App;
use keyhole::sys::accounts::{GroupRow, MemberRow, UserRow};

pub const USER_COLUMNS: &[ColDef] = &[
    c("name", "User", 180.0, false, "Local account name. Click to sort."),
    c("full_name", "Full name", 180.0, false, "The display name set on the account."),
    c("state", "State", 110.0, false, "Enabled, Disabled or Locked out. Click to sort."),
    c("admin", "Admin", 70.0, false, "Whether the account is in the local Administrators group."),
    c("last_logon", "Last logon", 150.0, false, "When the account last logged on to this machine, as far as the local SAM knows. Click to sort."),
    c("password", "Password age", 140.0, true, "Days since the password was set, and whether it is set to never expire."),
    c("logons", "Logons", 70.0, true, "How many times the account has logged on here."),
    c("groups", "Groups", 260.0, false, "Local groups the account belongs to."),
];

pub const GROUP_COLUMNS: &[ColDef] = &[
    c("name", "Group", 220.0, false, "Local group name. Click to sort."),
    c("members", "Members", 90.0, true, "How many accounts and groups are in it. Click to sort."),
    c("comment", "Description", 520.0, false, "The group's description."),
];

pub const MEMBER_COLUMNS: &[ColDef] = &[
    c("group", "Group", 200.0, false, "The local group. Click to sort."),
    c("member", "Member", 280.0, false, "The account or group that is a member, as DOMAIN\\name. Click to sort."),
    c("kind", "Type", 110.0, false, "User, Group, Local group, Well-known or Deleted."),
    c("source", "Source", 110.0, false, "Local for accounts on this machine, Built-in for Windows principals, Domain for directory accounts."),
    c("via", "Via", 300.0, false, "For members that come in through a domain group, the chain of groups that grants the membership. Blank for direct members."),
];

pub static KIND: Kind = Kind {
    name: "users",
    title: "Users and groups",
    placeholder: ("Filter by name, group or SID", "Show only rows whose name, full name, group or SID contains this text. Prefixes: group:Administrators  member:name"),
    columns,
    table,
    segment,
    default_sort,
    buttons,
    refresh,
    render,
    menu,
    double,
    button,
    csv: export_csv,
    segments,
    segment_picked,
    toggle: super::no_toggle,
    toggled: super::no_toggled,
    after_load,
};

fn current(st: &ListState) -> &str {
    match st.segment.get("users").map(|s| s.as_str()) {
        Some("groups") => "groups",
        Some("members") => "members",
        _ => "users",
    }
}

fn columns(st: &ListState) -> &'static [ColDef] {
    match current(st) {
        "groups" => GROUP_COLUMNS,
        "members" => MEMBER_COLUMNS,
        _ => USER_COLUMNS,
    }
}

fn table(st: &ListState) -> String {
    format!("users.{}", current(st))
}

fn segment(st: &ListState) -> String {
    current(st).to_string()
}

fn default_sort(st: &ListState) -> (&'static str, bool) {
    match current(st) {
        "groups" => ("name", false),
        "members" => ("group", false),
        _ => ("name", false),
    }
}

fn buttons(_st: &ListState) -> Vec<Chip> {
    vec![
        chip("check", "Check an account…", None, "Type any account, local or DOMAIN\\name, to see which local groups it ends up in here, domain groups included"),
        chip("console", "Local Users and Groups", None, "Open lusrmgr.msc to create accounts, reset passwords or change membership"),
    ]
}

fn after_load(ctx: &Shared, data: &ListData) {
    let ListData::Accounts(d) = data else { return };
    if d.domain.is_none() {
        return;
    }
    let members = d.members.clone();
    let machine_sid = d.machine_sid.clone();
    let stamp = ctx.st.borrow().lists.token;
    spawn(ctx, move |_| api::expand_domain_groups(&members, &machine_sid), move |ctx, (rows, notes)| {
        if ctx.st.borrow().lists.token != stamp || ctx.st.borrow().lists.kind != "users" {
            return;
        }
        merge_expansion(ctx, rows, notes);
    });
}

fn merge_expansion(ctx: &Shared, rows: Vec<MemberRow>, notes: Vec<String>) {
    {
        let mut st = ctx.st.borrow_mut();
        if let ListData::Accounts(d) = &mut st.lists.data {
            for r in rows {
                if !d.members.iter().any(|m| m.group == r.group && m.member == r.member && m.via == r.via) {
                    d.members.push(r);
                }
            }
            for n in notes {
                if !d.notes.contains(&n) {
                    d.notes.push(n);
                }
            }
            for u in &mut d.users {
                if u.domain {
                    continue;
                }
                let mine: Vec<String> = d.members.iter().filter(|m| m.local && m.via.is_empty() && m.member.split('\\').next_back().map(|n| n.eq_ignore_ascii_case(&u.name)).unwrap_or(false)).map(|m| m.group.clone()).collect();
                u.admin = mine.iter().any(|g| g.eq_ignore_ascii_case(keyhole::sys::accounts::administrators_group()));
                u.groups = mine;
            }
        }
    }
    lists::render(ctx);
}

fn check_account(ctx: &Shared) {
    dialogs::prompt(ctx, "Check an account", "Which local groups does this account end up in here? Type a local name or DOMAIN\\name. Domain group membership is included.", "e.g. CONTOSO\\jsmith", "Check", Box::new(|ctx, text| {
        let name = text.trim().to_string();
        if name.is_empty() {
            return;
        }
        let stamp = ctx.st.borrow().lists.token;
        let n2 = name.clone();
        spawn(ctx, move |_| api::lookup_account(&n2), move |ctx, res| match res {
            Ok(row) => {
                if ctx.st.borrow().lists.token != stamp {
                    return;
                }
                let shown = row.name.clone();
                let local = !row.domain;
                {
                    let mut st = ctx.st.borrow_mut();
                    if let ListData::Accounts(d) = &mut st.lists.data {
                        d.users.retain(|u| !(u.domain && u.name.eq_ignore_ascii_case(&row.name)));
                        if local {
                            if let Some(existing) = d.users.iter_mut().find(|u| !u.domain && u.name.eq_ignore_ascii_case(&row.name)) {
                                existing.groups = row.groups.clone();
                                existing.admin = row.admin;
                            } else {
                                d.users.push(row);
                            }
                        } else {
                            d.users.push(row);
                        }
                    }
                }
                switch(ctx, "users", Some(shown.clone()));
                good(ctx, &if local { format!("{} is a local account here", shown) } else { format!("{} checked", shown) });
            }
            Err(e) => bad(ctx, &e),
        });
    }));
}

fn segments(_st: &ListState) -> Vec<Chip> {
    vec![
        chip("users", "Users", None, "Local accounts"),
        chip("groups", "Groups", None, "Local groups and how many members each has"),
        chip("members", "Members", None, "Every group membership, one row per member"),
    ]
}

pub fn switch(ctx: &Shared, id: &str, filter: Option<String>) {
    {
        let mut st = ctx.st.borrow_mut();
        st.lists.segment.insert("users".into(), id.to_string());
        st.lists.chip.insert("users".into(), String::new());
        if let Some(f) = &filter {
            st.lists.filter.insert("users".into(), f.clone());
        }
        st.lists.sel = None;
    }
    let u = ui(ctx);
    u.set_list_segment(ss(id));
    if let Some(f) = filter {
        u.set_list_filter(ss(&f));
    }
    lists::set_cols(ctx, "users");
    lists::render(ctx);
}

fn segment_picked(ctx: &Shared, id: &str) {
    switch(ctx, id, None);
}

fn refresh(_app: &App, _st: &ListState) -> ListData {
    ListData::Accounts(api::accounts())
}

fn source_of(m: &MemberRow) -> &'static str {
    if !m.local {
        "Domain"
    } else if m.sid.starts_with("S-1-5-21-") {
        "Local"
    } else {
        "Built-in"
    }
}

fn state_of(u: &UserRow) -> (&'static str, i32) {
    if u.locked {
        ("Locked out", 4)
    } else if u.enabled {
        ("Enabled", 2)
    } else {
        ("Disabled", 1)
    }
}

fn render(_ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Accounts(d) = data else { return Rendered::default() };
    let terms = filter_terms(&input.filter);
    let seg = if input.table.ends_with("groups") { "groups" } else if input.table.ends_with("members") { "members" } else { "users" };
    let mut out = Rendered::default();
    let local_users: Vec<&UserRow> = d.users.iter().filter(|u| !u.domain).collect();
    let enabled = local_users.iter().filter(|u| u.enabled).count();
    let head = format!("{}, {} enabled  ·  {}  ·  {}", plural(local_users.len(), "local user", "local users"), enabled, plural(d.groups.len(), "group", "groups"), match &d.domain { Some(dn) => format!("joined to {}", dn), None => "not domain joined".to_string() });
    let mut note = d.error.as_ref().map(|e| format!("  ·  {}", e)).unwrap_or_default();
    for n in &d.notes {
        note.push_str(&format!("  ·  {}", n));
    }
    match seg {
        "groups" => {
            let chip_ok = |g: &GroupRow| match input.chip.as_str() {
                "members" => g.members > 0,
                _ => true,
            };
            out.chips = vec![chip("", "All", Some(d.groups.len()), "Every local group"), chip("members", "With members", Some(d.groups.iter().filter(|g| g.members > 0).count()), "Groups that have at least one member")];
            out.shown = (0..d.groups.len()).filter(|&i| { let g = &d.groups[i]; chip_ok(g) && (terms.is_empty() || term_matches(&terms, |k| match k { "group" => Some(g.name.clone()), _ => None }, &format!("{} {} {}", g.name, g.comment, g.sid))) }).collect();
            sort_indices(&d.groups, &mut out.shown, &input.sort.0, input.sort.1, |g, k| match k {
                "name" => sv_s(&g.name),
                "members" => sv_n(g.members as f64),
                "comment" => sv_s(&g.comment),
                _ => sv_s(""),
            });
            out.rows = out.shown.iter().map(|&i| { let g = &d.groups[i]; simple_row(i as i32, vec![cell(&g.name, 0), num(&g.members.to_string()), cell(&g.comment, 7)], if g.members == 0 { 1 } else { 0 }, &format!("{}\n{}\n{}", g.name, g.sid, g.comment)) }).collect();
            out.empty = ("\u{E77B}".into(), lists::nothing_matches(&input.filter), String::new());
        }
        "members" => {
            let admins = keyhole::sys::accounts::administrators_group();
            let rdp = keyhole::sys::accounts::remote_desktop_group();
            let chip_ok = |m: &MemberRow| match input.chip.as_str() {
                "admins" => m.group.eq_ignore_ascii_case(admins),
                "rdp" => m.group.eq_ignore_ascii_case(rdp),
                "domain" => !m.local,
                "via" => !m.via.is_empty(),
                "direct" => m.via.is_empty(),
                _ => true,
            };
            out.chips = vec![
                chip("", "All", Some(d.members.len()), "Every membership, direct and through domain groups"),
                chip("admins", admins, Some(d.members.iter().filter(|m| m.group.eq_ignore_ascii_case(admins)).count()), "Who can do anything on this machine, expanded through domain groups"),
                chip("rdp", rdp, Some(d.members.iter().filter(|m| m.group.eq_ignore_ascii_case(rdp)).count()), "Who may log on over Remote Desktop without being an administrator"),
                chip("domain", "Domain accounts", Some(d.members.iter().filter(|m| !m.local).count()), "Members that come from the directory rather than this machine"),
                chip("direct", "Direct", Some(d.members.iter().filter(|m| m.via.is_empty()).count()), "Members listed in the local group itself"),
                chip("via", "Through a domain group", Some(d.members.iter().filter(|m| !m.via.is_empty()).count()), "Members that inherit the group through a domain group, with the chain in the Via column"),
            ];
            out.shown = (0..d.members.len()).filter(|&i| { let m = &d.members[i]; chip_ok(m) && (terms.is_empty() || term_matches(&terms, |k| match k { "group" => Some(m.group.clone()), "member" => Some(m.member.clone()), "via" => Some(m.via.clone()), _ => None }, &format!("{} {} {} {} {}", m.group, m.member, m.kind, m.sid, m.via))) }).collect();
            sort_indices(&d.members, &mut out.shown, &input.sort.0, input.sort.1, |m, k| match k {
                "group" => sv_s(&m.group),
                "member" => sv_s(&m.member),
                "kind" => sv_s(&m.kind),
                "source" => sv_s(source_of(m)),
                "via" => sv_s(&m.via),
                _ => sv_s(""),
            });
            out.rows = out.shown.iter().map(|&i| { let m = &d.members[i]; simple_row(i as i32, vec![cell(&m.group, 0), cell(&m.member, 0), cell(&m.kind, 7), cell(source_of(m), if m.local { 7 } else { 5 }), cell(&m.via, 7)], 0, &format!("{} in {}{}\n{}", m.member, m.group, if m.via.is_empty() { String::new() } else { format!(" via {}", m.via) }, m.sid)) }).collect();
            out.empty = ("\u{E77B}".into(), lists::nothing_matches(&input.filter), String::new());
        }
        _ => {
            let chip_ok = |u: &UserRow| match input.chip.as_str() {
                "enabled" => u.enabled && !u.locked,
                "disabled" => !u.enabled,
                "admins" => u.admin,
                "locked" => u.locked,
                "neverexpires" => u.password_never_expires,
                "neverlogged" => u.logon_count == 0 && u.last_logon_ms == 0,
                _ => true,
            };
            out.chips = vec![
                chip("", "All", Some(d.users.len()), "Every local account"),
                chip("enabled", "Enabled", Some(d.users.iter().filter(|u| u.enabled && !u.locked).count()), "Accounts that can log on"),
                chip("disabled", "Disabled", Some(d.users.iter().filter(|u| !u.enabled).count()), "Accounts that cannot log on until enabled"),
                chip("admins", keyhole::sys::accounts::administrators_group(), Some(d.users.iter().filter(|u| u.admin).count()), "Members of the local administrators group"),
                chip("locked", "Locked out", Some(d.users.iter().filter(|u| u.locked).count()), "Locked after too many bad passwords"),
                chip("neverexpires", "Password never expires", Some(d.users.iter().filter(|u| u.password_never_expires).count()), "Accounts exempt from password expiry: service accounts, usually, and worth a look"),
                chip("neverlogged", "Never logged on", Some(d.users.iter().filter(|u| u.logon_count == 0 && u.last_logon_ms == 0).count()), "Accounts that have never been used here"),
            ];
            out.shown = (0..d.users.len()).filter(|&i| { let u = &d.users[i]; chip_ok(u) && (terms.is_empty() || term_matches(&terms, |k| match k { "group" => Some(u.groups.join("\n")), "member" => Some(u.name.clone()), _ => None }, &format!("{} {} {} {} {}", u.name, u.full_name, u.comment, u.sid, u.groups.join(" ")))) }).collect();
            sort_indices(&d.users, &mut out.shown, &input.sort.0, input.sort.1, |u, k| match k {
                "name" => sv_s(&u.name),
                "full_name" => sv_s(&u.full_name),
                "state" => sv_s(state_of(u).0),
                "admin" => sv_b(u.admin),
                "last_logon" => sv_n(u.last_logon_ms as f64),
                "password" => sv_n(u.password_age_days as f64),
                "logons" => sv_n(u.logon_count as f64),
                "groups" => sv_s(&u.groups.join(" ")),
                _ => sv_s(""),
            });
            out.rows = out.shown.iter().map(|&i| {
                let u = &d.users[i];
                let (state, dot) = state_of(u);
                let mut row = simple_row(
                    i as i32,
                    vec![
                        cell(&u.name, 0),
                        cell(&u.full_name, 7),
                        dot_cell(state, dot),
                        cell(if u.admin { "yes" } else { "" }, if u.admin { 3 } else { 0 }),
                        cell(&if u.last_logon_ms > 0 { time_of(u.last_logon_ms) } else { "never".into() }, if u.last_logon_ms > 0 { 0 } else { 1 }),
                        suffix_cell(&format!("{} d", u.password_age_days), if u.password_never_expires { "never expires" } else if !u.password_required { "not required" } else { "" }),
                        num(&u.logon_count.to_string()),
                        cell(&u.groups.join(", "), 7),
                    ],
                    if u.enabled { 0 } else { 1 },
                    &format!("{}{}\n{}{}{}", u.name, if u.full_name.is_empty() { String::new() } else { format!("  ({})", u.full_name) }, u.sid, if u.comment.is_empty() { String::new() } else { format!("\n{}", u.comment) }, if u.domain { "\n\nLooked up account: these are the local groups it ends up in here, domain groups included." } else { "" }),
                );
                if u.domain {
                    row.badges = model(vec![Badge { text: ss("looked up"), kind: 1, tip: ss("An account you checked. It is not a local account here") }]);
                }
                row
            }).collect();
            out.empty = ("\u{E77B}".into(), lists::nothing_matches(&input.filter), String::new());
        }
    }
    out.count = format!("{}{}", head, note);
    out
}

fn double(ctx: &Shared, src: usize) {
    let seg = ctx.st.borrow().lists.segment.get("users").cloned().unwrap_or_default();
    let st = ctx.st.borrow();
    let ListData::Accounts(d) = &st.lists.data else { return };
    match seg.as_str() {
        "groups" => {
            let Some(g) = d.groups.get(src) else { return };
            let name = g.name.clone();
            drop(st);
            switch(ctx, "members", Some(exact_filter("group", &name)));
        }
        "members" => {
            let Some(m) = d.members.get(src) else { return };
            let name = m.member.split('\\').next_back().unwrap_or("").to_string();
            let local = m.local && m.kind == "User";
            drop(st);
            if local {
                switch(ctx, "users", Some(name));
            }
        }
        _ => {
            let Some(u) = d.users.get(src) else { return };
            let name = u.name.clone();
            drop(st);
            crate::gui::tree::filter_tree(ctx, &format!("user:{}", name));
        }
    }
}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let seg = ctx.st.borrow().lists.segment.get("users").cloned().unwrap_or_default();
    let st = ctx.st.borrow();
    let ListData::Accounts(d) = &st.lists.data else { return };
    match seg.as_str() {
        "groups" => {
            let Some(g) = d.groups.get(src).cloned() else { return };
            drop(st);
            let items = vec![
                MenuItem::new("members", "Show members", { let n = g.name.clone(); move |ctx| switch(ctx, "members", Some(exact_filter("group", &n))) }),
                MenuItem::new("addMember", "Add a member…", { let n = g.name.clone(); move |ctx| add_member_prompt(ctx, &n) }),
                MenuItem::new("copy", "Copy name", { let v = g.name.clone(); move |ctx| copy_text(ctx, &v) }),
                MenuItem::new("copySid", "Copy SID", { let v = g.sid.clone(); move |ctx| copy_text(ctx, &v) }).disabled(g.sid.is_empty()),
                MenuItem::sep(),
                MenuItem::new("console", "Open Local Users and Groups", |ctx| simple_action(ctx, Action::OpenTool("users".into()), "Opened Local Users and Groups", None)),
            ];
            menus::show(ctx, x, y, &g.name, items);
        }
        "members" => {
            let Some(m) = d.members.get(src).cloned() else { return };
            drop(st);
            let local_user = m.local && m.kind == "User";
            let short = m.member.split('\\').next_back().unwrap_or("").to_string();
            let well_known = m.sid.starts_with("S-1-1") || m.sid.starts_with("S-1-5-32") || m.sid == "S-1-5-18" || m.sid == "S-1-5-19" || m.sid == "S-1-5-20";
            let domain_group = !m.local && m.kind == "Group";
            let items = vec![
                MenuItem::new("copy", "Copy member", { let v = m.member.clone(); move |ctx| copy_text(ctx, &v) }),
                MenuItem::new("copySid", "Copy SID", { let v = m.sid.clone(); move |ctx| copy_text(ctx, &v) }).disabled(m.sid.is_empty()),
                MenuItem::new("user", "Show user", { let n = short.clone(); move |ctx| switch(ctx, "users", Some(n)) }).disabled(!local_user),
                MenuItem::new("addMember", &format!("Add a member to {}…", m.group), { let g = m.group.clone(); move |ctx| add_member_prompt(ctx, &g) }),
                MenuItem::new("check", "Check this account's local groups", { let n = m.member.clone(); move |ctx| { let n2 = n.clone(); let stamp = ctx.st.borrow().lists.token; spawn(ctx, move |_| api::lookup_account(&n2), move |ctx, res| match res { Ok(row) => { if ctx.st.borrow().lists.token != stamp { return; } let name = row.name.clone(); { let mut st = ctx.st.borrow_mut(); if let ListData::Accounts(d) = &mut st.lists.data { d.users.retain(|u| !(u.domain && u.name.eq_ignore_ascii_case(&name))); if !row.domain { if let Some(existing) = d.users.iter_mut().find(|u| !u.domain && u.name.eq_ignore_ascii_case(&name)) { existing.groups = row.groups.clone(); existing.admin = row.admin; } else { d.users.push(row); } } else { d.users.push(row); } } } switch(ctx, "users", Some(name)); } Err(e) => bad(ctx, &e) }); } }).disabled(m.kind != "User"),
                MenuItem::new("expand", "Expand domain group", { let g = m.group.clone(); move |ctx| { let stamp = ctx.st.borrow().lists.token; let (members, sid) = { let st = ctx.st.borrow(); match &st.lists.data { ListData::Accounts(d) => (d.members.clone(), d.machine_sid.clone()), _ => return } }; let g2 = g.clone(); spawn(ctx, move |_| api::expand_one_group(&members, &g2, &sid), move |ctx, (rows, notes)| { if ctx.st.borrow().lists.token != stamp { return; } let n = rows.len(); merge_expansion(ctx, rows, notes); good(ctx, &format!("Added {}", plural(n, "member", "members"))); }); } }).disabled(!domain_group),
                MenuItem::sep(),
                MenuItem::new("remove", "Remove from group", { let m2 = m.clone(); move |ctx| { let m3 = m2.clone(); dialogs::confirm(ctx, &format!("Remove {} from {}?", m3.member, m3.group), &format!("{} loses whatever {} grants the moment this runs. Existing logon sessions keep their current token until they log off.", m3.member, m3.group), "Remove", true, Box::new(move |ctx| simple_action(ctx, Action::RemoveGroupMember { group: m3.group.clone(), sid: m3.sid.clone(), member: m3.member.clone() }, &format!("Removed {} from {}", m3.member, m3.group), super::refresh_after("users")))); } }).danger().disabled(m.sid.is_empty() || well_known || !m.via.is_empty()),
            ];
            menus::show(ctx, x, y, &format!("{}  ·  {}", m.member, m.group), items);
        }
        _ => {
            let Some(u) = d.users.get(src).cloned() else { return };
            drop(st);
            let items = vec![
                MenuItem::new("copy", "Copy name", { let v = u.name.clone(); move |ctx| copy_text(ctx, &v) }),
                MenuItem::new("copySid", "Copy SID", { let v = u.sid.clone(); move |ctx| copy_text(ctx, &v) }).disabled(u.sid.is_empty()),
                MenuItem::new("procs", "Show this user's processes", { let n = u.name.clone(); move |ctx| crate::gui::tree::filter_tree(ctx, &format!("user:{}", n)) }),
                MenuItem::new("sessions", "Show this user's sessions", { let n = u.name.clone(); move |ctx| lists::set_filter_and_show(ctx, "sessions", &n) }),
                MenuItem::sep(),
                MenuItem::new("enable", "Enable account", { let n = u.name.clone(); move |ctx| simple_action(ctx, Action::UserEnabled { name: n.clone(), enabled: true }, &format!("Enabled {}", n), super::refresh_after("users")) }).disabled(u.enabled || u.domain),
                MenuItem::new("disable", "Disable account", { let n = u.name.clone(); move |ctx| { let n2 = n.clone(); dialogs::confirm(ctx, &format!("Disable {}?", n), &format!("{} cannot log on until the account is enabled again. Services and tasks running as it fail at their next start.", n), "Disable", true, Box::new(move |ctx| simple_action(ctx, Action::UserEnabled { name: n2.clone(), enabled: false }, &format!("Disabled {}", n2), super::refresh_after("users")))); } }).danger().disabled(!u.enabled || u.domain),
                MenuItem::new("unlock", "Unlock account", { let n = u.name.clone(); move |ctx| simple_action(ctx, Action::UserUnlock(n.clone()), &format!("Unlocked {}", n), super::refresh_after("users")) }).disabled(!u.locked || u.domain),
                MenuItem::new("password", "Set password…", { let n = u.name.clone(); move |ctx| set_password_form(ctx, &n) }).disabled(u.domain).tip("An administrative reset. The old password is not needed, and the account loses EFS encrypted files and saved credentials protected by it"),
                MenuItem::sep(),
                MenuItem::new("console", "Open Local Users and Groups", |ctx| simple_action(ctx, Action::OpenTool("users".into()), "Opened Local Users and Groups", None)),
            ];
            menus::show(ctx, x, y, &format!("{}  ·  {}", u.name, state_of(&u).0), items);
        }
    }
}

fn add_member_prompt(ctx: &Shared, group: &str) {
    let g = group.to_string();
    dialogs::prompt(ctx, &format!("Add a member to {}", group), "Type a local account or DOMAIN\\name (a user or a group). Domain names need the domain controller to be reachable.", "DOMAIN\\name or local name", "Add", Box::new(move |ctx, account| {
        let account = account.trim().to_string();
        if account.is_empty() {
            return;
        }
        simple_action(ctx, Action::AddGroupMember { group: g.clone(), account: account.clone() }, &format!("Added {} to {}", account, g), super::refresh_after("users"));
    }));
}

fn set_password_form(ctx: &Shared, user: &str) {
    let u = user.to_string();
    dialogs::form(ctx, &format!("Set a new password for {}", user), "The old password is not needed. Local password policy (length, complexity, history) still applies.", vec![dialogs::FieldSpec::password("p1", "New password", "at least what the policy asks for"), dialogs::FieldSpec::password("p2", "Repeat it", "")], "Set password", Box::new(move |ctx, values| {
        let p1 = values.get("p1").cloned().unwrap_or_default();
        let p2 = values.get("p2").cloned().unwrap_or_default();
        if p1 != p2 {
            crate::gui::bad(ctx, "The two passwords differ. Type them again");
            set_password_form(ctx, &u);
            return;
        }
        simple_action(ctx, Action::SetPassword { user: u.clone(), password: p1.into() }, &format!("Password set for {}", u), None);
    }));
}

fn button(ctx: &Shared, id: &str) {
    match id {
        "console" => simple_action(ctx, Action::OpenTool("users".into()), "Opened Local Users and Groups", None),
        "check" => check_account(ctx),
        _ => {}
    }
}

fn export_csv(data: &ListData, shown: &[usize], st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Accounts(d) = data else { return None };
    Some(match current(st) {
        "groups" => ("keyhole-groups", csv(&shown.iter().map(|&i| { let g = &d.groups[i]; vec![g.name.clone(), g.members.to_string(), g.comment.clone(), g.sid.clone()] }).collect::<Vec<_>>(), &["Group", "Members", "Description", "SID"])),
        "members" => ("keyhole-group-members", csv(&shown.iter().map(|&i| { let m = &d.members[i]; vec![m.group.clone(), m.member.clone(), m.kind.clone(), source_of(m).to_string(), m.via.clone(), m.sid.clone()] }).collect::<Vec<_>>(), &["Group", "Member", "Type", "Source", "Via", "SID"])),
        _ => ("keyhole-users", csv(&shown.iter().map(|&i| { let u = &d.users[i]; vec![u.name.clone(), u.full_name.clone(), state_of(u).0.to_string(), u.admin.to_string(), if u.last_logon_ms > 0 { time_of(u.last_logon_ms) } else { String::new() }, u.password_age_days.to_string(), u.password_never_expires.to_string(), u.password_required.to_string(), u.cannot_change_password.to_string(), u.logon_count.to_string(), u.groups.join("; "), u.profile_path.clone(), if u.domain { "domain".to_string() } else { "local".to_string() }, u.sid.clone()] }).collect::<Vec<_>>(), &["User", "Full name", "State", "Admin", "Last logon", "Password age days", "Password never expires", "Password required", "Cannot change password", "Logons", "Groups", "Profile path", "Source", "SID"])),
    })
}
