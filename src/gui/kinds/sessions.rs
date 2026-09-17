use super::{Kind, RenderInput, Rendered, refresh_after};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{ListData, ListState, nothing_matches};
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, dot_cell, num, simple_row, sort_indices, sv_n, sv_s};
use crate::gui::simple_action;
use crate::gui::{Shared, chip, copy_text, dialogs};
use crate::Chip;
use keyhole::api::{self, Action};
use keyhole::state::App;

pub const COLUMNS: &[ColDef] = &[
    c("id", "Session", 80.0, true, "Session ID. Session 0 hosts services. Session 1 is usually the console user."),
    c("user", "User", 200.0, false, "Logged on user. Click to sort."),
    c("state", "State", 130.0, false, "Active means someone is using it. Disconnected means they logged in but are not connected right now."),
    c("processes", "Processes", 90.0, true, "Processes running in this session (as far as Keyhole can see them)."),
    c("logon_ms", "Logged on", 160.0, false, "When the user logged on."),
    c("idle_ms", "Idle", 90.0, true, "Time since the last keyboard or mouse input in this session."),
    c("win_station", "Station", 120.0, false, "Console for the local screen, RDP-Tcp#N for Remote Desktop."),
    c("client", "Client", 200.0, false, "Remote computer name and address for Remote Desktop sessions."),
];

fn columns(_st: &ListState) -> &'static [ColDef] {
    COLUMNS
}

fn default_sort(_st: &ListState) -> (&'static str, bool) {
    ("id", false)
}

pub static KIND: Kind = Kind {
    name: "sessions",
    title: "Sessions",
    placeholder: ("Filter sessions", "Show only sessions whose user, state, station or client contains this text"),
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
    ListData::Sessions(api::sessions(app))
}

fn render(ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Sessions(list) = data else { return Rendered::default() };
    let _ = ctx;
    let filter = input.filter.clone();
    let sort = input.sort.clone();
    let remote = |e: &keyhole::api::SessionEntry| -> bool { !e.row.client_address.is_empty() || e.row.win_station.to_lowercase().starts_with("rdp") };
    let chips: Vec<Chip> = vec![
        chip("", "All", Some(list.len()), "Every logon session, including the listener and services session"),
        chip("active", "Active", Some(list.iter().filter(|e| e.row.state == "Active").count()), "Sessions with a user at the keyboard or the RDP client connected"),
        chip("disconnected", "Disconnected", Some(list.iter().filter(|e| e.row.state == "Disconnected" && !e.row.user.is_empty()).count()), "Sessions whose user went away without logging off. Their programs still run and hold licenses and memory"),
        chip("remote", "Remote Desktop", Some(list.iter().filter(|e| remote(e)).count()), "Sessions that came in over RDP"),
        chip("users", "With a user", Some(list.iter().filter(|e| !e.row.user.is_empty()).count()), "Sessions somebody is logged on to, hiding the listener and the services session"),
    ];
    let chip_ok = |e: &keyhole::api::SessionEntry| match input.chip.as_str() {
        "active" => e.row.state == "Active",
        "disconnected" => e.row.state == "Disconnected" && !e.row.user.is_empty(),
        "remote" => remote(e),
        "users" => !e.row.user.is_empty(),
        _ => true,
    };
    let mut shown = (0..list.len()).filter(|&i| { let r = &list[i].row; chip_ok(&list[i]) && (filter.is_empty() || format!("{} {} {} {} {} {}", r.user, r.state, r.win_station, r.client, r.client_address, r.id).to_lowercase().contains(&filter)) }).collect();
    sort_indices(list, &mut shown, &sort.0, sort.1, |e, k| match k {
        "id" => sv_n(e.row.id as f64),
        "user" => sv_s(&e.row.user),
        "state" => sv_s(&e.row.state),
        "processes" => sv_n(e.processes as f64),
        "logon_ms" => sv_n(e.row.logon_ms as f64),
        "idle_ms" => sv_n(e.row.idle_ms as f64),
        "win_station" => sv_s(&e.row.win_station),
        "client" => sv_s(&e.row.client),
        _ => sv_s(""),
    });
    let count = shown_of(shown.len(), list.len(), "sessions");
    let rows = shown
        .iter()
        .map(|&i| {
            let e = &list[i];
            let r = &e.row;
            let dot = if r.state == "Active" { 2 } else if r.state == "Disconnected" { 3 } else { 1 };
            let client = [r.client.as_str(), r.client_address.as_str()].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join("  ·  ");
            simple_row(
                i as i32,
                vec![
                    num(&r.id.to_string()),
                    cell(&if r.user.is_empty() { if r.id == 0 { "(services)".to_string() } else { "-".to_string() } } else { short_user(&r.user) }, 0),
                    dot_cell(&r.state, dot),
                    num(&if e.processes > 0 { e.processes.to_string() } else { String::new() }),
                    cell(&time_of(r.logon_ms), 0),
                    num(&if r.idle_ms > 0 { fmt_age(r.idle_ms) } else { String::new() }),
                    cell(&r.win_station, 0),
                    cell(&client, 0),
                ],
                0,
                &client,
            )
        })
        .collect();
    let empty = ("\u{E716}".into(), nothing_matches(&filter), String::new());
    Rendered { chips, rows, shown, count, empty }
}

fn double(_ctx: &Shared, _src: usize) {}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let d = {
        let st = ctx.st.borrow();
        let ListData::Sessions(list) = &st.lists.data else { return };
        let Some(entry) = list.get(src) else { return };
        entry.row.clone()
    };
    session_menu(ctx, x, y, &d);
}

fn session_menu(ctx: &Shared, x: f32, y: f32, d: &keyhole::sys::sessions::SessionRow) {
    let id = d.id;
    let who = if d.user.is_empty() { format!("session {}", d.id) } else { d.user.clone() };
    let me = ctx.st.borrow().user.clone();
    let items = vec![
        MenuItem::new("procs", "Show this session's processes", move |ctx| crate::gui::tree::filter_tree(ctx, &format!("session:{}", id))),
        MenuItem::new("msg", "Send a message to this session…", { let who = who.clone(); move |ctx| {
            let title = format!("Message from {}", if me.is_empty() { "the administrator".to_string() } else { me.clone() });
            dialogs::prompt(ctx, &format!("Message {}", who), "The text pops up on that session's screen in a Windows message box. Useful before you disconnect or log someone off.", "Type your message", "Send", Box::new(move |ctx, text| simple_action(ctx, Action::SessionMessage { id, title: title.clone(), text }, &format!("Message sent to session {}", id), None)));
        } }).disabled(d.state != "Active" && d.state != "Disconnected"),
        MenuItem::sep(),
        MenuItem::new("cu", "Copy user", { let v = d.user.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.user.is_empty()),
        MenuItem::new("cc", "Copy client name", { let v = d.client.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.client.is_empty()),
        MenuItem::new("ca", "Copy client address", { let v = d.client_address.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.client_address.is_empty()),
        MenuItem::sep(),
        MenuItem::new("disc", "Disconnect session", { let who = who.clone(); move |ctx| dialogs::confirm(ctx, &format!("Disconnect session {}?", id), &format!("This disconnects {}. Their programs keep running. They can reconnect.", who), "Disconnect", true, Box::new(move |ctx| simple_action(ctx, Action::SessionDisconnect(id), &format!("Disconnected session {}", id), refresh_after("sessions")))) }).danger().disabled(d.user.is_empty()),
        MenuItem::new("logoff", "Log off session", { let who = who.clone(); move |ctx| dialogs::confirm(ctx, &format!("Log off session {}?", id), &format!("This logs off {}. Unsaved work in that session is lost.", who), "Log off", true, Box::new(move |ctx| simple_action(ctx, Action::SessionLogoff(id), &format!("Logged off session {}", id), refresh_after("sessions")))) }).danger().disabled(d.user.is_empty()),
    ];
    menus::show(ctx, x, y, &format!("Session {}{}", d.id, if d.user.is_empty() { String::new() } else { format!("  ·  {}", d.user) }), items);
}

fn button(ctx: &Shared, id: &str) {
    let _ = (ctx, id);
}

fn export_csv(data: &ListData, shown: &[usize], _st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Sessions(l) = data else { return None };
    Some(("keyhole-sessions", csv(&shown.iter().map(|&i| { let e = &l[i]; let r = &e.row; vec![r.id.to_string(), r.user.clone(), r.state.clone(), e.processes.to_string(), time_of(r.logon_ms), if r.connect_ms > 0 { time_of(r.connect_ms) } else { String::new() }, if r.idle_ms > 0 { fmt_age(r.idle_ms) } else { String::new() }, r.win_station.clone(), r.client.clone(), r.client_address.clone()] }).collect::<Vec<_>>(), &["Session", "User", "State", "Processes", "Logged on", "Connected", "Idle", "Station", "Client", "Client address"])))
}
