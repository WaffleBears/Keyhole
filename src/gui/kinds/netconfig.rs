use super::{Kind, RenderInput, Rendered};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{self, ListData, ListState};
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, dot_cell, num, simple_row, sort_indices, sv_b, sv_n, sv_s};
use crate::gui::simple_action;
use crate::gui::{Shared, bad, chip, copy_text, dialogs, good, spawn, ss, ui};
use crate::Chip;
use keyhole::api::{self, Action};
use keyhole::state::App;
use keyhole::sys::netconfig::{self, AdapterRow, DnsRecord, RouteRow};

pub const ADAPTER_COLUMNS: &[ColDef] = &[
    c("name", "Adapter", 200.0, false, "The connection name Windows shows in Network Connections. Hover a row for everything about it."),
    c("status", "Status", 90.0, false, "Up, Down, or why it is not usable."),
    c("kind", "Kind", 90.0, false, "Ethernet, Wi-Fi, Loopback, Tunnel, PPP or WWAN."),
    c("ipv4", "IPv4", 170.0, false, "IPv4 addresses with prefix length."),
    c("ipv6", "IPv6", 220.0, false, "IPv6 addresses with prefix length."),
    c("gateway", "Gateway", 130.0, false, "Default gateways this adapter uses."),
    c("dns", "DNS servers", 180.0, false, "DNS servers this adapter is configured with."),
    c("dhcp", "DHCP", 130.0, false, "The DHCP server that handed out the address, or static."),
    c("mac", "MAC", 140.0, false, "Hardware address."),
    c("speed", "Speed", 90.0, true, "Negotiated link speed. A gigabit port showing 100 Mbps usually means a bad cable or switch port."),
    c("mtu", "MTU", 70.0, true, "Maximum transmission unit."),
];

pub const ROUTE_COLUMNS: &[ColDef] = &[
    c("destination", "Destination", 220.0, false, "Destination network with prefix length. 0.0.0.0/0 and ::/0 are the default routes."),
    c("nexthop", "Next hop", 170.0, false, "The router packets go to, or on-link when the destination is directly reachable."),
    c("interface", "Interface", 200.0, false, "The adapter the route goes out of."),
    c("metric", "Metric", 80.0, true, "Route metric. Lower wins. The interface metric is added on top."),
    c("protocol", "Protocol", 120.0, false, "How the route got here: Local, Static, DHCP, router advertisement, a routing protocol."),
    c("age", "Age", 90.0, true, "How long the route has existed."),
];

pub const DNS_COLUMNS: &[ColDef] = &[
    c("name", "Name", 300.0, false, "The name that was looked up."),
    c("kind", "Type", 80.0, false, "A, AAAA, CNAME, PTR, SRV."),
    c("data", "Data", 300.0, false, "The answer: an address or the canonical name."),
    c("ttl", "TTL", 90.0, true, "Seconds until the cached answer expires. Blank for hosts file entries."),
    c("source", "Source", 90.0, false, "Where the answer came from: the resolver cache or the hosts file."),
];

pub static KIND: Kind = Kind {
    name: "netconfig",
    title: "Network configuration",
    placeholder: ("Filter by adapter, address or name", "Show only rows containing this text. Prefixes: ip:10.0  mac:00-1A  kind:ethernet  if:Ethernet"),
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
    match st.segment.get("netconfig").map(|s| s.as_str()) {
        Some("routes") => "routes",
        Some("dns") => "dns",
        _ => "adapters",
    }
}

fn columns(st: &ListState) -> &'static [ColDef] {
    match current(st) {
        "routes" => ROUTE_COLUMNS,
        "dns" => DNS_COLUMNS,
        _ => ADAPTER_COLUMNS,
    }
}

fn table(st: &ListState) -> String {
    format!("netconfig.{}", current(st))
}

fn segment(st: &ListState) -> String {
    current(st).to_string()
}

fn default_sort(st: &ListState) -> (&'static str, bool) {
    match current(st) {
        "routes" => ("destination", false),
        "dns" => ("name", false),
        _ => ("name", false),
    }
}

fn buttons(_st: &ListState) -> Vec<Chip> {
    vec![
        chip("flushdns", "Flush DNS", None, "Empty the resolver cache so every name is looked up again (ipconfig /flushdns)"),
        chip("ncpa", "Connections panel", None, "Open the Network Connections control panel to change addresses or adapters"),
    ]
}

fn segments(_st: &ListState) -> Vec<Chip> {
    vec![
        chip("adapters", "Adapters", None, "Every network adapter with its addresses, gateway, DNS and DHCP state"),
        chip("routes", "Routes", None, "The IPv4 and IPv6 routing table"),
        chip("dns", "DNS", None, "The resolver cache and hosts file"),
    ]
}

pub fn switch(ctx: &Shared, id: &str, filter: Option<String>) {
    {
        let mut st = ctx.st.borrow_mut();
        st.lists.segment.insert("netconfig".into(), id.to_string());
        st.lists.chip.insert("netconfig".into(), String::new());
        if let Some(f) = &filter {
            st.lists.filter.insert("netconfig".into(), f.clone());
        }
        st.lists.sel = None;
    }
    let u = ui(ctx);
    u.set_list_segment(ss(id));
    if let Some(f) = filter {
        u.set_list_filter(ss(&f));
    }
    lists::set_cols(ctx, "netconfig");
    lists::render(ctx);
}

fn segment_picked(ctx: &Shared, id: &str) {
    switch(ctx, id, None);
}

fn refresh(_app: &App, _st: &ListState) -> ListData {
    ListData::NetConfig(api::netconfig())
}

fn status_dot(a: &AdapterRow) -> i32 {
    if a.up { 2 } else if a.status == "Down" || a.status == "Not present" { 1 } else { 3 }
}

fn route_text(r: &RouteRow) -> String {
    format!("{}/{} via {} on {}  ·  metric {}  ·  {}{}", r.destination, r.prefix, r.next_hop, r.interface, r.metric, r.protocol, if r.origin.is_empty() { String::new() } else { format!(" ({})", r.origin) })
}

fn render(_ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::NetConfig(d) = data else { return Rendered::default() };
    let terms = filter_terms(&input.filter);
    let seg = if input.table.ends_with("routes") { "routes" } else if input.table.ends_with(".dns") { "dns" } else { "adapters" };
    let mut out = Rendered::default();
    let up: Vec<&AdapterRow> = d.adapters.iter().filter(|a| a.up && a.kind != "Loopback" && !a.ipv4.is_empty()).collect();
    let mut dns_servers: Vec<String> = Vec::new();
    let mut gateways: Vec<String> = Vec::new();
    for a in &up {
        for s in &a.dns {
            if !dns_servers.contains(s) {
                dns_servers.push(s.clone());
            }
        }
        for g in &a.gateways {
            if !gateways.contains(g) {
                gateways.push(g.clone());
            }
        }
    }
    let mut head = format!("{} up  ·  {}{}", plural(up.len(), "adapter", "adapters"), d.host, if d.domain.is_empty() { String::new() } else { format!(".{}", d.domain) });
    if !gateways.is_empty() {
        head.push_str(&format!("  ·  gateway {}", gateways.join(", ")));
    }
    if !dns_servers.is_empty() {
        head.push_str(&format!("  ·  DNS {}", dns_servers.join(", ")));
    }
    if !d.dns_suffixes.is_empty() {
        head.push_str(&format!("  ·  search {}", d.dns_suffixes.join(", ")));
    }
    for n in &d.notes {
        head.push_str(&format!("  ·  {}", n));
    }
    out.count = head;
    match seg {
        "routes" => {
            let chip_ok = |r: &RouteRow| match input.chip.as_str() {
                "v4" => !r.v6,
                "v6" => r.v6,
                "default" => r.prefix == 0,
                "static" => r.protocol == "Static" || r.protocol == "Auto static",
                _ => true,
            };
            out.chips = vec![
                chip("", "All", Some(d.routes.len()), "Every route"),
                chip("v4", "IPv4", Some(d.routes.iter().filter(|r| !r.v6).count()), "IPv4 routes only"),
                chip("v6", "IPv6", Some(d.routes.iter().filter(|r| r.v6).count()), "IPv6 routes only"),
                chip("default", "Default routes", Some(d.routes.iter().filter(|r| r.prefix == 0).count()), "Where traffic goes when nothing more specific matches"),
                chip("static", "Static", Some(d.routes.iter().filter(|r| r.protocol == "Static" || r.protocol == "Auto static").count()), "Routes somebody added by hand"),
            ];
            out.shown = (0..d.routes.len()).filter(|&i| { let r = &d.routes[i]; chip_ok(r) && (terms.is_empty() || term_matches(&terms, |k| match k { "ip" => Some(format!("{} {}", r.destination, r.next_hop)), "if" | "interface" => Some(r.interface.clone()), _ => None }, &format!("{}/{} {} {} {}", r.destination, r.prefix, r.next_hop, r.interface, r.protocol))) }).collect();
            sort_indices(&d.routes, &mut out.shown, &input.sort.0, input.sort.1, |r, k| match k {
                "destination" => sv_s(&format!("{}{:03}{}", if r.v6 { "b" } else { "a" }, r.prefix, netconfig::ip_sort_key(&r.destination))),
                "nexthop" => sv_s(&r.next_hop),
                "interface" => sv_s(&r.interface),
                "metric" => sv_n(r.metric as f64),
                "protocol" => sv_s(&r.protocol),
                "age" => sv_n(r.age_secs as f64),
                _ => sv_s(""),
            });
            out.rows = out.shown.iter().map(|&i| { let r = &d.routes[i]; simple_row(i as i32, vec![cell(&format!("{}/{}", r.destination, r.prefix), 0), cell(&r.next_hop, if r.next_hop == "on-link" { 7 } else { 0 }), cell(&r.interface, 0), num(&r.metric.to_string()), cell(&r.protocol, 7), num(&if r.age_secs > 0 { fmt_age(r.age_secs as i64 * 1000) } else { String::new() })], 0, &route_text(r)) }).collect();
            out.empty = ("\u{E839}".into(), if terms.is_empty() && input.chip.is_empty() { "No routes.".into() } else { lists::nothing_matches(&input.filter) }, String::new());
        }
        "dns" => {
            let chip_ok = |r: &DnsRecord| match input.chip.as_str() {
                "a" => r.kind == "A",
                "aaaa" => r.kind == "AAAA",
                "cname" => r.kind == "CNAME",
                "ptr" => r.kind == "PTR",
                "hosts" => r.source == "hosts",
                _ => true,
            };
            out.chips = vec![
                chip("", "All", Some(d.dns.len()), "Every cached answer and hosts file line"),
                chip("a", "A", Some(d.dns.iter().filter(|r| r.kind == "A").count()), "IPv4 answers"),
                chip("aaaa", "AAAA", Some(d.dns.iter().filter(|r| r.kind == "AAAA").count()), "IPv6 answers"),
                chip("cname", "CNAME", Some(d.dns.iter().filter(|r| r.kind == "CNAME").count()), "Aliases"),
                chip("ptr", "PTR", Some(d.dns.iter().filter(|r| r.kind == "PTR").count()), "Reverse lookups: address to name"),
                chip("hosts", "hosts file", Some(d.dns.iter().filter(|r| r.source == "hosts").count()), "Entries from drivers\\etc\\hosts, which beat DNS"),
            ];
            out.shown = (0..d.dns.len()).filter(|&i| { let r = &d.dns[i]; chip_ok(r) && (terms.is_empty() || term_matches(&terms, |k| match k { "ip" => Some(r.data.clone()), "type" | "kind" => Some(r.kind.clone()), _ => None }, &format!("{} {} {} {}", r.name, r.kind, r.data, r.source))) }).collect();
            sort_indices(&d.dns, &mut out.shown, &input.sort.0, input.sort.1, |r, k| match k {
                "name" => sv_s(&r.name),
                "kind" => sv_s(&r.kind),
                "data" => sv_s(&r.data),
                "ttl" => sv_n(r.ttl as f64),
                "source" => sv_s(&r.source),
                _ => sv_s(""),
            });
            out.rows = out.shown.iter().map(|&i| { let r = &d.dns[i]; simple_row(i as i32, vec![cell(&r.name, 0), cell(&r.kind, 7), cell(&r.data, 0), num(&if r.source == "hosts" { String::new() } else { format!("{} s", r.ttl) }), cell(&r.source, if r.source == "hosts" { 3 } else { 7 })], 0, &format!("{} {} {}\n{}", r.name, r.kind, r.data, if r.source == "hosts" { "From the hosts file: this answer is used before any DNS server is asked.".to_string() } else { format!("Cached answer, {} s left", r.ttl) })) }).collect();
            out.empty = ("\u{E839}".into(), if terms.is_empty() && input.chip.is_empty() { "The resolver cache is empty and the hosts file has no entries.".into() } else { lists::nothing_matches(&input.filter) }, "Answers appear here as programs look names up.".into());
        }
        _ => {
            let chip_ok = |a: &AdapterRow| match input.chip.as_str() {
                "up" => a.up,
                "dhcp" => a.dhcp,
                "static" => !a.dhcp && !a.ipv4.is_empty() && a.kind != "Loopback",
                "wired" => a.kind == "Ethernet",
                "wifi" => a.kind == "Wi-Fi",
                _ => true,
            };
            out.chips = vec![
                chip("", "All", Some(d.adapters.len()), "Every adapter Windows knows about, including virtual and disconnected ones"),
                chip("up", "Up", Some(d.adapters.iter().filter(|a| a.up).count()), "Adapters with link"),
                chip("dhcp", "DHCP", Some(d.adapters.iter().filter(|a| a.dhcp).count()), "Addresses handed out by a DHCP server"),
                chip("static", "Static", Some(d.adapters.iter().filter(|a| !a.dhcp && !a.ipv4.is_empty() && a.kind != "Loopback").count()), "Addresses configured by hand, which is what a server should have"),
                chip("wired", "Ethernet", Some(d.adapters.iter().filter(|a| a.kind == "Ethernet").count()), "Wired adapters"),
                chip("wifi", "Wi-Fi", Some(d.adapters.iter().filter(|a| a.kind == "Wi-Fi").count()), "Wireless adapters"),
            ];
            out.shown = (0..d.adapters.len()).filter(|&i| { let a = &d.adapters[i]; chip_ok(a) && (terms.is_empty() || term_matches(&terms, |k| match k { "ip" => Some(format!("{}\n{}", a.ipv4.join("\n"), a.ipv6.join("\n"))), "mac" => Some(a.mac.clone()), "kind" => Some(a.kind.clone()), "dns" => Some(a.dns.join(" ")), _ => None }, &format!("{} {} {} {} {} {} {} {}", a.name, a.description, a.kind, a.ipv4.join(" "), a.ipv6.join(" "), a.gateways.join(" "), a.dns.join(" "), a.mac))) }).collect();
            sort_indices(&d.adapters, &mut out.shown, &input.sort.0, input.sort.1, |a, k| match k {
                "name" => sv_s(&a.name),
                "status" => sv_b(a.up),
                "kind" => sv_s(&a.kind),
                "ipv4" => sv_s(&a.ipv4.join(" ")),
                "ipv6" => sv_s(&a.ipv6.join(" ")),
                "gateway" => sv_s(&a.gateways.join(" ")),
                "dns" => sv_s(&a.dns.join(" ")),
                "dhcp" => sv_b(a.dhcp),
                "mac" => sv_s(&a.mac),
                "speed" => sv_n(a.speed as f64),
                "mtu" => sv_n(a.mtu as f64),
                _ => sv_s(""),
            });
            out.rows = out.shown.iter().map(|&i| {
                let a = &d.adapters[i];
                simple_row(i as i32, vec![cell(&a.name, 0), dot_cell(&a.status, status_dot(a)), cell(&a.kind, 7), cell(&a.ipv4.join(", "), 0), cell(&a.ipv6.join(", "), 7), cell(&a.gateways.join(", "), 0), cell(&a.dns.join(", "), 0), cell(&if a.dhcp { if a.dhcp_server.is_empty() { "DHCP".to_string() } else { a.dhcp_server.clone() } } else if a.ipv4.is_empty() { String::new() } else { "static".to_string() }, if a.dhcp { 3 } else { 7 }), cell(&a.mac, 7), num(&netconfig::speed_text(a.speed)), num(&if a.mtu > 0 { a.mtu.to_string() } else { String::new() })], if a.up { 0 } else { 1 }, &netconfig::adapter_summary(a))
            }).collect();
            out.empty = ("\u{E839}".into(), if terms.is_empty() && input.chip.is_empty() { "No network adapters.".into() } else { lists::nothing_matches(&input.filter) }, String::new());
        }
    }
    out
}

pub fn ping_toast(ctx: &Shared, target: &str) {
    let t = target.split('/').next().unwrap_or(target).trim().to_string();
    if t.is_empty() {
        return;
    }
    good(ctx, &format!("Pinging {}", t));
    spawn(ctx, move |_| api::ping(&t), |ctx, r| match r {
        Ok(text) => good(ctx, &text),
        Err(text) => bad(ctx, &text),
    });
}

fn first_address(a: &AdapterRow) -> String {
    a.ipv4.first().or(a.ipv6.first()).map(|s| s.split('/').next().unwrap_or("").to_string()).unwrap_or_default()
}

fn double(ctx: &Shared, src: usize) {
    let seg = ctx.st.borrow().lists.segment.get("netconfig").cloned().unwrap_or_default();
    let st = ctx.st.borrow();
    let ListData::NetConfig(d) = &st.lists.data else { return };
    let text = match seg.as_str() {
        "routes" => d.routes.get(src).map(route_text),
        "dns" => d.dns.get(src).map(|r| r.data.clone()),
        _ => d.adapters.get(src).map(first_address),
    };
    drop(st);
    if let Some(t) = text {
        copy_text(ctx, &t);
    }
}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let seg = ctx.st.borrow().lists.segment.get("netconfig").cloned().unwrap_or_default();
    let st = ctx.st.borrow();
    let ListData::NetConfig(d) = &st.lists.data else { return };
    match seg.as_str() {
        "routes" => {
            let Some(r) = d.routes.get(src).cloned() else { return };
            drop(st);
            let items = vec![
                MenuItem::new("copy", "Copy route", { let v = route_text(&r); move |ctx| copy_text(ctx, &v) }),
                MenuItem::new("copyHop", "Copy next hop", { let v = r.next_hop.clone(); move |ctx| copy_text(ctx, &v) }).disabled(r.next_hop == "on-link"),
                MenuItem::new("ping", "Ping the next hop", { let v = r.next_hop.clone(); move |ctx| ping_toast(ctx, &v) }).disabled(r.next_hop == "on-link").tip("Three ICMP echoes with a 1.5 s timeout each. The result appears as a toast"),
                MenuItem::new("adapter", "Show the adapter", { let n = r.interface.clone(); move |ctx| switch(ctx, "adapters", Some(format!("\"{}\"", n))) }),
            ];
            menus::show(ctx, x, y, &format!("{}/{}", r.destination, r.prefix), items);
        }
        "dns" => {
            let Some(r) = d.dns.get(src).cloned() else { return };
            drop(st);
            let items = vec![
                MenuItem::new("copyName", "Copy name", { let v = r.name.clone(); move |ctx| copy_text(ctx, &v) }),
                MenuItem::new("copyData", "Copy answer", { let v = r.data.clone(); move |ctx| copy_text(ctx, &v) }),
                MenuItem::new("ping", "Ping this address", { let v = r.data.clone(); move |ctx| ping_toast(ctx, &v) }).disabled(r.kind != "A" && r.kind != "AAAA"),
                MenuItem::new("conns", "Show connections to this address", { let v = format!("remote:{}", r.data); move |ctx| lists::set_filter_and_show(ctx, "network", &v) }).disabled(r.kind != "A" && r.kind != "AAAA"),
            ];
            menus::show(ctx, x, y, &r.name, items);
        }
        _ => {
            let Some(a) = d.adapters.get(src).cloned() else { return };
            drop(st);
            let addr = first_address(&a);
            let items = vec![
                MenuItem::new("copyIp", "Copy addresses", { let v = a.ipv4.iter().chain(a.ipv6.iter()).cloned().collect::<Vec<_>>().join("\n"); move |ctx| copy_text(ctx, &v) }).disabled(a.ipv4.is_empty() && a.ipv6.is_empty()),
                MenuItem::new("copyMac", "Copy MAC", { let v = a.mac.clone(); move |ctx| copy_text(ctx, &v) }).disabled(a.mac.is_empty()),
                MenuItem::new("copySummary", "Copy summary", { let v = netconfig::adapter_summary(&a); move |ctx| copy_text(ctx, &v) }),
                MenuItem::sep(),
                MenuItem::new("conns", "Show connections on this address", { let v = format!("local:{}", addr); move |ctx| lists::set_filter_and_show(ctx, "network", &v) }).disabled(addr.is_empty()),
                MenuItem::new("pingGw", &format!("Ping the gateway{}", a.gateways.first().map(|g| format!(" ({})", g)).unwrap_or_default()), { let v = a.gateways.first().cloned().unwrap_or_default(); move |ctx| ping_toast(ctx, &v) }).disabled(a.gateways.is_empty()),
                MenuItem::new("pingDns", &format!("Ping the DNS server{}", a.dns.first().map(|d| format!(" ({})", d)).unwrap_or_default()), { let v = a.dns.first().cloned().unwrap_or_default(); move |ctx| ping_toast(ctx, &v) }).disabled(a.dns.is_empty()),
                MenuItem::new("routes", "Show its routes", { let n = a.name.clone(); move |ctx| switch(ctx, "routes", Some(exact_filter("if", &n))) }),
                MenuItem::sep(),
                MenuItem::new("renew", "Renew DHCP lease", { let a2 = a.clone(); move |ctx| { let index = a2.index; let name = a2.name.clone(); dialogs::confirm(ctx, &format!("Renew the DHCP lease on {}?", name), "The address is released and requested again. Connections through this adapter drop for a moment. If the DHCP server does not answer, the adapter is left without an address.", "Renew", true, Box::new(move |ctx| simple_action(ctx, Action::RenewDhcp(index), "Lease renewed", super::refresh_after("netconfig")))); } }).disabled(!a.dhcp || !a.up).danger().tip("ipconfig /release then /renew for this adapter only"),
                MenuItem::new("ncpa", "Open Network Connections", |ctx| simple_action(ctx, Action::OpenTool("ncpa".into()), "Opened Network Connections", None)),
            ];
            menus::show(ctx, x, y, &a.name, items);
        }
    }
}

fn button(ctx: &Shared, id: &str) {
    match id {
        "ncpa" => simple_action(ctx, Action::OpenTool("ncpa".into()), "Opened Network Connections", None),
        "flushdns" => dialogs::confirm(ctx, "Flush the DNS resolver cache?", "Drops every cached answer so names are looked up again. Harmless, and the usual first step when a name resolves to a stale address.", "Flush", false, Box::new(|ctx| simple_action(ctx, Action::FlushDns, "Flushed the DNS cache", super::refresh_after("netconfig")))),
        _ => {}
    }
}

fn export_csv(data: &ListData, shown: &[usize], st: &ListState) -> Option<(&'static str, String)> {
    let ListData::NetConfig(d) = data else { return None };
    Some(match current(st) {
        "routes" => ("keyhole-routes", csv(&shown.iter().filter_map(|&i| d.routes.get(i)).map(|r| vec![format!("{}/{}", r.destination, r.prefix), r.next_hop.clone(), r.interface.clone(), r.metric.to_string(), r.protocol.clone(), r.origin.clone(), r.age_secs.to_string(), r.index.to_string()]).collect::<Vec<_>>(), &["Destination", "Next hop", "Interface", "Metric", "Protocol", "Origin", "Age seconds", "Interface index"])),
        "dns" => ("keyhole-dns-cache", csv(&shown.iter().filter_map(|&i| d.dns.get(i)).map(|r| vec![r.name.clone(), r.kind.clone(), r.data.clone(), r.ttl.to_string(), r.source.clone()]).collect::<Vec<_>>(), &["Name", "Type", "Data", "TTL", "Source"])),
        _ => ("keyhole-adapters", csv(&shown.iter().filter_map(|&i| d.adapters.get(i)).map(|a| vec![a.name.clone(), a.description.clone(), a.status.clone(), a.kind.clone(), a.ipv4.join("; "), a.ipv6.join("; "), a.gateways.join("; "), a.dns.join("; "), a.suffix.clone(), if a.dhcp { a.dhcp_server.clone() } else { "static".into() }, a.mac.clone(), a.speed.to_string(), a.mtu.to_string(), if a.lease_obtained_ms > 0 { time_of(a.lease_obtained_ms) } else { String::new() }, if a.lease_expires_ms > 0 { time_of(a.lease_expires_ms) } else { String::new() }, a.index.to_string()]).collect::<Vec<_>>(), &["Adapter", "Description", "Status", "Kind", "IPv4", "IPv6", "Gateway", "DNS", "Suffix", "DHCP", "MAC", "Speed bps", "MTU", "Lease obtained", "Lease expires", "Interface index"])),
    })
}
