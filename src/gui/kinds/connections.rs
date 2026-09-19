use super::{Kind, RenderInput, Rendered, plural};
use crate::gui::format::*;
use crate::gui::columns::{ColDef, c};
use crate::gui::lists::{self, ListData, ListState};
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, hexc, num, simple_row, sort_indices, suffix_cell, sv_n, sv_s};
use crate::gui::{Shared, batch_action, chip, copy_text, dialogs};
use crate::{Chip, Row};
use keyhole::state::App;

pub const COLUMNS: &[ColDef] = &[
    c("process", "Process", 150.0, false, "Process that owns this endpoint. Click to sort."),
    c("pid", "PID", 60.0, true, "Owning process ID. Click to sort."),
    c("proto", "Protocol", 70.0, false, "TCP, UDP, or an IPv6 variant. Click to sort."),
    c("local", "Local address", 160.0, false, "Local IP and port. Click to sort."),
    c("remote", "Remote address", 160.0, false, "Remote peer address. Tick Resolve names to look up its host name. Click to sort."),
    c("state", "State", 104.0, false, "TCP connection state. Blank for UDP. Click to sort."),
];

fn columns(_st: &ListState) -> &'static [ColDef] {
    COLUMNS
}

fn default_sort(_st: &ListState) -> (&'static str, bool) {
    ("process", false)
}

pub static KIND: Kind = Kind {
    name: "network",
    title: "Connections",
    placeholder: ("Filter by process, address, port", "Show only endpoints whose process, address, port, host name or state contains this text. Prefixes: remote:1.2.3.4  local:0.0.0.0  port:443  pid:1234"),
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
    toggle,
    toggled,
    after_load: super::no_after_load,
};

fn toggle(st: &ListState) -> Option<(&'static str, &'static str, bool)> {
    Some(("Resolve names", "Resolve remote addresses to host names by reverse DNS. Lookups run in the background and fill in over the next few seconds.", st.net_resolve))
}

fn toggled(ctx: &Shared, on: bool) {
    ctx.st.borrow_mut().lists.net_resolve = on;
    crate::gui::activity::refresh_network(ctx);
}

fn buttons(_st: &ListState) -> Vec<Chip> {
    Vec::new()
}

fn refresh(app: &App, st: &ListState) -> ListData {
    let _ = (app, st);
    ListData::None
}

fn render(ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Connections(c) = data else { return Rendered::default() };
    let _ = ctx;
    let filter = input.filter.clone();
    let chip_id = input.chip.clone();
    let sort = input.sort.clone();
    
    let rows: Vec<Row>;
    let matches = |id: &str, r: &keyhole::model::EndpointRow| match id {
        "established" => r.state == "ESTABLISHED",
        "listening" => r.state == "LISTEN",
        "udp" => r.proto.starts_with("UDP"),
        "other" => r.state != "ESTABLISHED" && r.state != "LISTEN" && !r.proto.starts_with("UDP"),
        _ => true,
    };
    let est = c.rows.iter().filter(|r| r.state == "ESTABLISHED").count();
    let lis = c.rows.iter().filter(|r| r.state == "LISTEN").count();
    let udp = c.rows.iter().filter(|r| r.proto.starts_with("UDP")).count();
    let chips = vec![
        chip("", "All", Some(c.rows.len()), "Every TCP and UDP endpoint"),
        chip("established", "Established", Some(est), "Live TCP connections to a remote peer"),
        chip("listening", "Listening", Some(lis), "Ports waiting for incoming TCP connections"),
        chip("udp", "UDP", Some(udp), "UDP sockets (no connection state)"),
        chip("other", "Closing / other", Some(c.rows.len() - est - lis - udp), "TIME_WAIT, CLOSE_WAIT and other transitional states"),
    ];
    let mut shown = (0..c.rows.len()).filter(|&i| matches(&chip_id, &c.rows[i])).collect();
    sort_indices(&c.rows, &mut shown, &sort.0, sort.1, |r, k| match k {
        "process" => sv_s(&r.process),
        "pid" => sv_n(r.pid as f64),
        "proto" => sv_s(&r.proto),
        "local" => sv_s(&r.local),
        "remote" => sv_s(&r.remote),
        "state" => sv_s(&r.state),
        _ => sv_s(""),
    });
    let count: String = if shown.len() == c.rows.len() { format!("{} endpoints", c.rows.len()) } else { format!("{} of {} endpoints", shown.len(), c.rows.len()) };
    rows = shown
        .iter()
        .map(|&i| {
            let r = &c.rows[i];
            let remote = if r.remote_host.is_empty() { hexc(&r.remote) } else { suffix_cell(&r.remote_host, &format!("· {}", r.remote)) };
            let mut row = simple_row(i as i32, vec![cell(&r.process, 0), num(&r.pid.to_string()), cell(&r.proto, 0), hexc(&r.local), remote, cell(&r.state, 0)], 0, &if r.remote_host.is_empty() { r.remote.clone() } else { format!("{} ({})", r.remote_host, r.remote) });
            row.id = r.pid as i32;
            row
        })
        .collect();
    let empty = ("\u{E968}".into(), format!("No connections match{}.", if filter.is_empty() { String::new() } else { format!(" \"{}\"", filter) }), String::new());
    Rendered { chips, rows, shown, count, empty }
}

fn double(ctx: &Shared, src: usize) {
    let st = ctx.st.borrow();
    let ListData::Connections(c) = &st.lists.data else { return };
    let Some(pid) = c.rows.get(src).map(|r| r.pid) else { return };
    drop(st);
    crate::gui::tree::select_pid(ctx, pid);
}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let d = {
        let st = ctx.st.borrow();
        let ListData::Connections(c) = &st.lists.data else { return };
        let Some(row) = c.rows.get(src) else { return };
        row.clone()
    };
    connection_menu(ctx, x, y, &d);
}

fn connection_menu(ctx: &Shared, x: f32, y: f32, d: &keyhole::model::EndpointRow) {
    let proc = crate::gui::tree::row_of(ctx, d.pid);
    let pid = d.pid;
    let items = vec![
        MenuItem::new("sel", "Go to owning process", move |ctx| crate::gui::tree::select_pid(ctx, pid)),
        MenuItem::new("only", &format!("Show only {}", d.process), { let p = d.process.clone(); move |ctx| lists::set_filter_and_show(ctx, "network", &p) }).disabled(d.process.is_empty()),
        MenuItem::new("same", "Show only this remote address", { let q = format!("remote:{}", ip_of(&d.remote)); move |ctx| lists::set_filter_and_show(ctx, "network", &q) }).disabled(d.remote.is_empty()),
        MenuItem::sep(),
        MenuItem::new("cp", "Copy process name", { let v = d.process.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.process.is_empty()),
        MenuItem::new("cl", "Copy local address", { let v = d.local.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("cr", "Copy remote address", { let v = d.remote.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.remote.is_empty()),
        MenuItem::new("ch", "Copy remote host name", { let v = d.remote_host.clone(); move |ctx| copy_text(ctx, &v) }).disabled(d.remote_host.is_empty()),
        MenuItem::sep(),
        MenuItem::new("fw", "Show firewall rules for this program", { let p = proc.as_ref().map(|p| p.image_path.clone()).unwrap_or_default(); move |ctx| lists::set_filter_and_show(ctx, "firewall", &p) }).disabled(proc.as_ref().map(|p| p.image_path.is_empty()).unwrap_or(true)),
        menus::close_connection_item(d, Box::new(crate::gui::activity::refresh_network)),
        MenuItem::new("kill", "Terminate owning process", { let p = proc.clone(); move |ctx| if let Some(p) = &p { crate::gui::tree::confirm_kill(ctx, p) } }).danger().disabled(proc.is_none()),
    ];
    menus::show(ctx, x, y, &if d.remote.is_empty() { d.local.clone() } else { d.remote.clone() }, items);
}

fn ip_of(endpoint: &str) -> String {
    let s = match endpoint.rfind(':') {
        Some(i) => &endpoint[..i],
        None => endpoint,
    };
    s.trim_start_matches('[').trim_end_matches(']').to_string()
}

fn button(ctx: &Shared, id: &str) {
    let _ = (ctx, id);
}

fn export_csv(data: &ListData, shown: &[usize], _st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Connections(c) = data else { return None };
    Some(("keyhole-connections", csv(&shown.iter().map(|&i| { let r = &c.rows[i]; vec![r.process.clone(), r.pid.to_string(), r.proto.clone(), r.local.clone(), r.remote.clone(), r.remote_host.clone(), r.state.clone()] }).collect::<Vec<_>>(), &["Process", "PID", "Protocol", "Local", "Remote", "Remote host", "State"])))
}

fn multi(ctx: &Shared, srcs: &[usize], x: f32, y: f32) {
    let rows: Vec<keyhole::model::EndpointRow> = {
        let st = ctx.st.borrow();
        let ListData::Connections(c) = &st.lists.data else { return };
        srcs.iter().filter_map(|&i| c.rows.get(i).cloned()).collect()
    };
    if rows.is_empty() {
        return;
    }
    let n = rows.len();
    let closable: Vec<(String, keyhole::api::Action)> = rows.iter().filter(|d| d.proto == "TCP" && d.state == "ESTABLISHED").map(|d| (format!("{} → {}", d.local, d.remote), keyhole::api::Action::CloseConnection { local: d.local.clone(), remote: d.remote.clone() })).collect();
    let items = vec![
        MenuItem::new("cr", "Copy remote addresses", { let v = rows.iter().filter(|r| !r.remote.is_empty()).map(|r| r.remote.clone()).collect::<Vec<_>>().join("\n"); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("cl", "Copy local addresses", { let v = rows.iter().map(|r| r.local.clone()).collect::<Vec<_>>().join("\n"); move |ctx| copy_text(ctx, &v) }),
        MenuItem::sep(),
        MenuItem::new("close", &format!("Close {}", plural(closable.len(), "connection", "connections")), {
            let a = closable.clone();
            move |ctx| {
                let a = a.clone();
                dialogs::confirm(ctx, "Close connections?", &format!("This forcibly tears down {}. The owning programs are not told and may error.", plural(a.len(), "established TCP connection", "established TCP connections")), "Close connections", true, Box::new(move |ctx| batch_action(ctx, a, "Closed", ("connection", "connections"), Some(Box::new(crate::gui::activity::refresh_network)))));
            }
        })
        .danger()
        .disabled(closable.is_empty()),
    ];
    menus::show(ctx, x, y, &format!("{} selected", plural(n, "connection", "connections")), items);
}
